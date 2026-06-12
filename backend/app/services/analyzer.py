from app.services.gmail_client import fetch_email_raw
from app.services.parser import sanitize_email_dom, extract_visible_text, extract_links
from app.services.gemini_service import analyze_with_gemini, summarize_email
from app.services.virustotal_service import inspect_links_with_virustotal
from app.services.rag_service import query_rag_with_meta
from app.services.database import log_email_analysis
from app.services.link_sandbox import inspect_url_static, normalize_url, should_escalate_to_browser_analysis
from app.services.browser_analyzer import inspect_url_with_playwright
from app.schemas.email import EmailAnalyzeResponse
import asyncio

async def analyze_email_pipeline(message_id: str, access_token: str) -> EmailAnalyzeResponse:
    # 1. 원문 획득 및 정제
    raw_email = await fetch_email_raw(message_id, access_token)
    clean_html = sanitize_email_dom(raw_email["body_html"])
    visible_text = extract_visible_text(clean_html)
    
    # 백그라운드에서 요약 작업 시작 (속도 개선을 위해 텍스트 3000자 절삭)
    summary_task = asyncio.create_task(summarize_email(visible_text[:3000]))
    
    # 2. URL 정규화, 중복 제거 및 우선순위 선정 (본문 등장 순 기준 상위 3개)
    raw_urls = extract_links(raw_email["body_html"])
    seen = set()
    unique_urls = []
    for u in raw_urls:
        norm_u = normalize_url(u)
        if norm_u not in seen:
            seen.add(norm_u)
            unique_urls.append(norm_u)
    target_urls = unique_urls[:3]
    
    sender_domain = raw_email["sender"].split("@")[-1].replace(">", "") if "@" in raw_email["sender"] else "Unknown"

    # 3. Tier 1 분석 및 VirusTotal 동시 수행
    vt_results = await inspect_links_with_virustotal(target_urls)
    vt_details_map = {item['url']: item for item in vt_results.get("details", [])}
    
    static_tasks = [inspect_url_static(url) for url in target_urls]
    static_results_raw = await asyncio.gather(*static_tasks, return_exceptions=True)
    
    static_results_map = {}
    for url, result in zip(target_urls, static_results_raw):
        if not isinstance(result, Exception):
            static_results_map[url] = result
            
    static_results = [r for r in static_results_raw if not isinstance(r, Exception)]
    
    # 4. LLM Phase 1 (1차 위험도 산출)
    # 매우 빠르고 가벼운 프롬프트를 통해 1차 위험도 산출 (VT, Static 기반)
    phase1_result = await analyze_with_gemini(
        text=visible_text, sender=raw_email["sender"], subject=raw_email["subject"],
        link_findings={"vt": vt_results, "static_dom": static_results}
    )
    phase1_risk = phase1_result.get("risk_level", "LOW")

    # 5. Tier 2 동적 분석 에스컬레이션 판단 및 실행
    urls_to_escalate = []
    for idx, url in enumerate(target_urls):
        vt_stats = vt_details_map.get(url, {}).get("stats", {})
        # TODO: 실제 VirusTotal 응답 스키마 확인 후 stats 키 경로 수정 필요
        s_result = static_results_map.get(url, {})
        
        if should_escalate_to_browser_analysis(url, vt_stats, s_result, sender_domain, phase1_risk):
            urls_to_escalate.append(url)
            
    dynamic_results_raw = []
    if urls_to_escalate:
        def run_playwright_in_thread(urls):
            import sys
            import asyncio
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                
            async def _run():
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    tasks = [inspect_url_with_playwright(p, url) for url in urls]
                    return await asyncio.gather(*tasks, return_exceptions=True)
                    
            return asyncio.run(_run())
            
        loop = asyncio.get_running_loop()
        dynamic_results_raw = await loop.run_in_executor(None, run_playwright_in_thread, urls_to_escalate)
            
    dynamic_results = [r for r in dynamic_results_raw if not isinstance(r, Exception)]

    # 6. LLM Phase 2 (최종 판정) - 만약 동적 분석이 추가되었다면 다시 판정, 아니면 Phase 1 결과 사용
    # RAG 임베딩 연산 병목 방지를 위해 메일 제목과 본문 상단 1000자만 결합하여 쿼리
    rag_query_text = f"{raw_email.get('subject', '')}\n{visible_text[:1000]}"
    rag_docs = await query_rag_with_meta(rag_query_text)  # 메타데이터 포함 검색
    rag_used = len(rag_docs) > 0
    rag_context = "\n".join(item["document"] for item in rag_docs) if rag_docs else None

    final_gemini_result = phase1_result
    if dynamic_results or rag_context:
        final_gemini_result = await analyze_with_gemini(
            text=visible_text, sender=raw_email["sender"], subject=raw_email["subject"],
            link_findings={"vt": vt_results, "static_dom": static_results, "dynamic_dom": dynamic_results},
            rag_context=rag_context
        )
    
    # 요약 작업 완료 대기
    try:
        mail_summary = await summary_task
    except Exception:
        mail_summary = ""

    # 7. 응답 스키마 조립
    response = EmailAnalyzeResponse(
        is_phishing=final_gemini_result.get("is_phishing", False),
        risk_level=final_gemini_result.get("risk_level", "LOW"),
        summary=final_gemini_result.get("summary", "분석 실패"),
        mail_summary=mail_summary,
        social_engineering_elements=final_gemini_result.get("social_engineering_elements", []),
        actions=final_gemini_result.get("actions", []),
        reason=final_gemini_result.get("reason", "판정 근거 없음"),
        vt_findings=vt_results,
        static_findings=static_results,
        dynamic_findings=dynamic_results,
        # RAG Done Criteria
        rag_used=rag_used,
        rag_doc_count=len(rag_docs),
        rag_retrieved_docs=rag_docs if rag_used else None,
    )

    log_email_analysis(
        message_id=message_id,
        sender=raw_email["sender"],
        subject=raw_email["subject"],
        is_phishing=response.is_phishing,
        risk_level=response.risk_level,
        summary=response.summary,
        rag_used=response.rag_used,
        rag_doc_count=response.rag_doc_count,
        raw_data=response.model_dump_json(exclude={"mail_summary", "rag_retrieved_docs"}), # 방대한 본문 요약 등은 제외하고 검사 결과 위주로
    )

    return response
