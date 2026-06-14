from app.services.gmail_client import fetch_email_raw
from app.services.parser import sanitize_email_dom, extract_visible_text, extract_links
from app.services.gemini_service import analyze_with_gemini, summarize_email
from app.services.virustotal_service import inspect_links_with_virustotal
from app.services.rag_service import query_rag_with_meta
from app.services.database import log_email_analysis, get_cached_email_analysis
from app.services.link_sandbox import inspect_url_static, normalize_url, should_escalate_to_browser_analysis, is_short_url
from app.services.browser_analyzer import inspect_url_with_playwright
from app.schemas.email import EmailAnalyzeResponse
import asyncio
import urllib.parse

async def analyze_email_pipeline(message_id: str, access_token: str) -> EmailAnalyzeResponse:
    # 캐시 확인
    cached = get_cached_email_analysis(message_id)
    if cached and cached.get("raw_data"):
        try:
            print(f"[Info] Cached email analysis found for message_id {message_id}. Returning cache.")
            return EmailAnalyzeResponse.model_validate_json(cached["raw_data"])
        except Exception as e:
            print(f"[Warning] Failed to parse cached email response: {e}")

    # 1. 원문 획득 및 정제
    raw_email = await fetch_email_raw(message_id, access_token)
    clean_html = sanitize_email_dom(raw_email["body_html"])
    visible_text = extract_visible_text(clean_html)
    
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

    # 성능 최적화: RAG 및 요약 작업을 파이프라인 극초반에 백그라운드 태스크로 시작
    rag_query_text = f"{raw_email.get('subject', '')}\n{visible_text[:1000]}"
    rag_task = asyncio.create_task(query_rag_with_meta(rag_query_text))
    summary_task = asyncio.create_task(summarize_email(visible_text[:3000]))

    # 3. Tier 1 분석 및 VirusTotal 동시 수행 (병렬 처리로 응답 속도 단축)
    vt_task = inspect_links_with_virustotal(target_urls)
    static_tasks = [inspect_url_static(url) for url in target_urls]
    
    results = await asyncio.gather(vt_task, *static_tasks, return_exceptions=True)
    
    vt_results = results[0] if not isinstance(results[0], Exception) else {"scanned": 0, "malicious_found": 0, "details": []}
    vt_details_map = {item['url']: item for item in vt_results.get("details", [])}
    
    static_results = []
    static_results_map = {}
    for url, res in zip(target_urls, results[1:]):
        if not isinstance(res, Exception):
            static_results.append(res)
            static_results_map[url] = res

    # 4. 동적 분석 에스컬레이션 조건 선검사 (Pre-LLM 조건 판별)
    # 1차 판단용 AI 호출 전, 이미 동적 분석 조건(단축 URL, 퍼블릭 호스팅 도메인, VT 악성 감지, 정적 폼 감지)을 만족하는지 확인
    urls_to_escalate = []
    pre_llm_escalation = False
    
    for url in target_urls:
        vt_stats = vt_details_map.get(url, {}).get("stats", {})
        s_result = static_results_map.get(url, {})
        
        # 1차 판정 LLM 리스크를 'LOW'로 전달하여, 1차 AI 없이도 무조건 에스컬레이션되는 조건(단축/퍼블릭호스팅/VT악성/정적의심요소)만 선검증
        if should_escalate_to_browser_analysis(url, vt_stats, s_result, sender_domain, "LOW"):
            urls_to_escalate.append(url)
            pre_llm_escalation = True

    dynamic_results = []
    phase1_result = None
    loop = asyncio.get_running_loop()
    
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

    if pre_llm_escalation:
        # 동적 분석 조건이 기확보된 경우, 1차 AI 판정 단계를 과감히 건너뛰어(Skip Phase 1) API 호출 횟수와 레이턴시를 대폭 절약
        print("[Info] Pre-LLM escalation condition matched. Launching Playwright directly...")
        dynamic_results_raw = await loop.run_in_executor(None, run_playwright_in_thread, urls_to_escalate)
        dynamic_results = [r for r in dynamic_results_raw if not isinstance(r, Exception)]
    else:
        # LLM Phase 1 (1차 위험도 산출)
        # 매우 빠르고 가벼운 프롬프트를 통해 1차 위험도 산출 (VT, Static 기반)
        print("[Info] No pre-LLM conditions met. Evaluating Phase 1 AI...")
        phase1_result = await analyze_with_gemini(
            text=visible_text, sender=raw_email["sender"], subject=raw_email["subject"],
            link_findings={"vt": vt_results, "static_dom": static_results}
        )
        phase1_risk = phase1_result.get("risk_level", "LOW")

        # 1차 판정 리스크에 따른 동적 분석 에스컬레이션 판단 및 실행
        for url in target_urls:
            vt_stats = vt_details_map.get(url, {}).get("stats", {})
            s_result = static_results_map.get(url, {})
            if should_escalate_to_browser_analysis(url, vt_stats, s_result, sender_domain, phase1_risk):
                urls_to_escalate.append(url)
                
        urls_to_escalate = list(set(urls_to_escalate))
        if urls_to_escalate:
            print("[Info] Post-LLM escalation triggered. Running Playwright...")
            dynamic_results_raw = await loop.run_in_executor(None, run_playwright_in_thread, urls_to_escalate)
            dynamic_results = [r for r in dynamic_results_raw if not isinstance(r, Exception)]

    # 백그라운드 태스크 결과 Await
    rag_docs = await rag_task
    rag_used = len(rag_docs) > 0
    rag_context = "\n".join(item["document"] for item in rag_docs) if rag_docs else None

    # LLM Phase 2 (최종 판정) - 동적 분석이 실행되었거나 RAG 지식이 있는 경우 수행, 아니면 Phase 1 결과 재사용
    if pre_llm_escalation or dynamic_results or rag_context:
        print("[Info] Running final LLM Phase 2 decision...")
        final_gemini_result = await analyze_with_gemini(
            text=visible_text, sender=raw_email["sender"], subject=raw_email["subject"],
            link_findings={"vt": vt_results, "static_dom": static_results, "dynamic_dom": dynamic_results},
            rag_context=rag_context
        )
    else:
        final_gemini_result = phase1_result if phase1_result else {
            "is_phishing": False,
            "risk_level": "LOW",
            "summary": "AI 분석 진행 단계에서 오류가 발생하여 기본 위험 수준으로 설정합니다.",
            "social_engineering_elements": [],
            "actions": [],
            "reason": "AI 연동 실패 또는 분석 컨텍스트 오류"
        }
    
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
        raw_data=response.model_dump_json(), # 캐시에서 복원할 수 있도록 요약과 RAG 문서를 포함한 전체 JSON 저장
    )

    return response
