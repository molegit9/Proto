import asyncio
from typing import AsyncGenerator, Optional, List

from app.services.gmail_client import fetch_email_raw
from app.services.parser import sanitize_email_dom, extract_visible_text, extract_links
from app.services.gemini_service import analyze_with_gemini
from app.services.virustotal_service import inspect_links_with_virustotal
from app.services.rag_service import query_rag_with_meta
from app.services.database import log_email_analysis, get_cached_email_analysis
from app.services.link_sandbox import (
    inspect_url_static,
    normalize_url,
    should_escalate_to_browser_analysis,
)
from app.services.browser_analyzer import inspect_urls_pooled
from app.core.config import settings
from app.schemas.email import EmailAnalyzeResponse


def _extract_screenshots(results_list):
    cleaned = []
    shots = []
    for item in results_list:
        if not isinstance(item, dict):
            continue
        item_copy = dict(item)
        ss = item_copy.pop("_screenshot_bytes", None)
        if ss:
            shots.append(ss)
        cleaned.append(item_copy)
    return cleaned, shots


def _build_response(
    gemini_result: dict,
    vt_results: dict,
    static_results: list,
    dynamic_results: list,
    rag_used: bool,
    rag_docs: list,
    deep_scan_pending: bool = False,
) -> EmailAnalyzeResponse:
    return EmailAnalyzeResponse(
        is_phishing=gemini_result.get("is_phishing", False),
        risk_level=gemini_result.get("risk_level", "LOW"),
        summary=gemini_result.get("summary", "분석 완료"),
        mail_summary=gemini_result.get("mail_summary", "") or "",
        social_engineering_elements=gemini_result.get("social_engineering_elements", []),
        actions=gemini_result.get("actions", []),
        reason=gemini_result.get("reason", "판정 근거 없음"),
        vt_findings=vt_results,
        static_findings=static_results,
        dynamic_findings=dynamic_results,
        rag_used=rag_used,
        rag_doc_count=len(rag_docs),
        rag_retrieved_docs=rag_docs if rag_used else None,
        deep_scan_pending=deep_scan_pending,
    )


async def analyze_email_stream(
    message_id: str,
    access_token: Optional[str] = None,
    dom_sender: Optional[str] = None,
    dom_subject: Optional[str] = None,
    dom_body_text: Optional[str] = None,
    dom_links: Optional[List[str]] = None,
) -> AsyncGenerator[dict, None]:
    """
    초고속 2단계 NDJSON 스트리밍 이메일 분석 파이프라인:
    - 캐시 히트 시 즉시 final 반환 (~0.05s)
    - DOM Fast Path 제공 시 Gmail REST API 왕복 생략
    - RAG(to_thread) + VT(신뢰도메인 스킵) + 정적 분석(1.8s) 완전 병렬 실행
    - 1-Shot LLM(보안 판정 + 메일 요약 동시 생성)으로 1.5~3초 내 즉시 결과 제공
    - 의심 링크가 있는 경우에만 1차 결과를 먼저 띄우고(partial) Playwright 동적 분석 후 final 업데이트
    """
    # 0. SQLite 캐시 확인 (프리페치/재열람 시 즉시 응답)
    cached = get_cached_email_analysis(message_id)
    if cached and cached.get("raw_data"):
        try:
            cached_resp = EmailAnalyzeResponse.model_validate_json(cached["raw_data"])
            cached_resp.deep_scan_pending = False
            yield {"stage": "final", "data": cached_resp.model_dump()}
            return
        except Exception as e:
            print(f"[Warning] Failed to parse cached email response: {e}")

    # 1. 메일 본문 획득 — DOM Fast Path 우선, 없으면 Gmail API Fallback
    use_dom_fast_path = bool(dom_body_text and len(dom_body_text.strip()) >= 15)
    if use_dom_fast_path:
        sender = (dom_sender or "Unknown").strip()
        subject = (dom_subject or "No Subject").strip()
        visible_text = dom_body_text.strip()
        raw_urls = [u for u in (dom_links or []) if isinstance(u, str) and u.startswith(("http://", "https://"))]
    else:
        if not access_token:
            raise ValueError("이메일 본문 또는 Gmail OAuth access_token이 필요합니다.")
        yield {"stage": "progress", "message": "메일 원문을 불러오는 중..."}
        raw_email = await fetch_email_raw(message_id, access_token)
        sender = raw_email["sender"]
        subject = raw_email["subject"]
        clean_html = sanitize_email_dom(raw_email["body_html"])
        visible_text = extract_visible_text(clean_html)
        raw_urls = extract_links(raw_email["body_html"])

    # 2. URL 정규화 및 중복 제거 (상위 3개)
    seen = set()
    unique_urls = []
    for u in raw_urls:
        norm_u = normalize_url(u)
        if norm_u not in seen:
            seen.add(norm_u)
            unique_urls.append(norm_u)
    target_urls = unique_urls[:3]

    sender_domain = sender.split("@")[-1].replace(">", "").strip() if "@" in sender else "Unknown"

    yield {"stage": "progress", "message": "유사 위협 판례(RAG) 및 링크 평판 병렬 조회 중..."}

    # 3. RAG(비동기 스레드) + VT + 정적 분석 완전 병렬 실행
    rag_query_text = f"{subject}\n{visible_text[:1000]}"
    rag_task = asyncio.create_task(query_rag_with_meta(rag_query_text, n_results=3, max_distance=0.55))
    vt_task = asyncio.create_task(inspect_links_with_virustotal(target_urls))
    static_tasks = [asyncio.create_task(inspect_url_static(url)) for url in target_urls]

    gathered = await asyncio.gather(rag_task, vt_task, *static_tasks, return_exceptions=True)

    rag_docs = gathered[0] if not isinstance(gathered[0], Exception) else []
    rag_used = len(rag_docs) > 0
    rag_context = "\n".join(item["document"] for item in rag_docs) if rag_docs else None

    vt_results = (
        gathered[1]
        if not isinstance(gathered[1], Exception)
        else {"scanned": 0, "malicious_found": 0, "details": []}
    )
    vt_details_map = {item["url"]: item for item in vt_results.get("details", [])}

    static_results = []
    static_results_map = {}
    for url, res in zip(target_urls, gathered[2:]):
        if not isinstance(res, Exception):
            static_results.append(res)
            static_results_map[url] = res

    # 4. 1-Shot LLM 빠른 판정 + 메일 요약 동시 생성 (RAG + VT + 정적 결과 모두 포함)
    yield {"stage": "progress", "message": "AI 보안 판정 및 메일 요약 생성 중..."}
    phase1_result = await analyze_with_gemini(
        text=visible_text,
        sender=sender,
        subject=subject,
        link_findings={"vt": vt_results, "static_dom": static_results},
        rag_context=rag_context,
    )
    phase1_risk = phase1_result.get("risk_level", "LOW")

    # 5. 동적 분석(Playwright) 에스컬레이션 대상 선별
    urls_to_escalate = []
    for url in target_urls:
        vt_stats = vt_details_map.get(url, {}).get("stats", {})
        s_result = static_results_map.get(url, {})
        if should_escalate_to_browser_analysis(url, vt_stats, s_result, sender_domain, phase1_risk):
            urls_to_escalate.append(url)
    urls_to_escalate = list(dict.fromkeys(urls_to_escalate))[:2]  # 최대 2개 의심 링크만 심층 검사

    # 5-A. 동적 분석 불필요(정상 메일 대부분): 1-Shot 결과로 즉시 완료!
    if not urls_to_escalate:
        final_response = _build_response(
            gemini_result=phase1_result,
            vt_results=vt_results,
            static_results=static_results,
            dynamic_results=[],
            rag_used=rag_used,
            rag_docs=rag_docs,
            deep_scan_pending=False,
        )
        log_email_analysis(
            message_id=message_id,
            sender=sender,
            subject=subject,
            is_phishing=final_response.is_phishing,
            risk_level=final_response.risk_level,
            summary=final_response.summary,
            rag_used=final_response.rag_used,
            rag_doc_count=final_response.rag_doc_count,
            raw_data=final_response.model_dump_json(),
        )
        yield {"stage": "final", "data": final_response.model_dump()}
        return

    # 5-B. 의심 링크 감지: 1차 판정 배너를 먼저 즉시 노출하고(partial), 백그라운드 동적 분석 수행
    partial_response = _build_response(
        gemini_result=phase1_result,
        vt_results=vt_results,
        static_results=static_results,
        dynamic_results=[],
        rag_used=rag_used,
        rag_docs=rag_docs,
        deep_scan_pending=True,
    )
    yield {"stage": "partial", "data": partial_response.model_dump()}

    # 6. Tier 2 풀링 Playwright 동적 + Vision 스크린샷 분석
    capture_ss = getattr(settings, "PLAYWRIGHT_CAPTURE_SCREENSHOT", True)
    dynamic_results_raw = await inspect_urls_pooled(urls_to_escalate, capture_screenshot=capture_ss)
    dynamic_results, dynamic_screenshots = _extract_screenshots(dynamic_results_raw)

    # 7. 동적 분석 결과 반영 최종 판정
    final_gemini_result = await analyze_with_gemini(
        text=visible_text,
        sender=sender,
        subject=subject,
        link_findings={"vt": vt_results, "static_dom": static_results, "dynamic_dom": dynamic_results},
        rag_context=rag_context,
        screenshots=dynamic_screenshots if dynamic_screenshots else None,
    )
    # 1차에서 만든 요약이 비어 있으면 보존
    if not final_gemini_result.get("mail_summary") and phase1_result.get("mail_summary"):
        final_gemini_result["mail_summary"] = phase1_result["mail_summary"]

    final_response = _build_response(
        gemini_result=final_gemini_result,
        vt_results=vt_results,
        static_results=static_results,
        dynamic_results=dynamic_results,
        rag_used=rag_used,
        rag_docs=rag_docs,
        deep_scan_pending=False,
    )

    log_email_analysis(
        message_id=message_id,
        sender=sender,
        subject=subject,
        is_phishing=final_response.is_phishing,
        risk_level=final_response.risk_level,
        summary=final_response.summary,
        rag_used=final_response.rag_used,
        rag_doc_count=final_response.rag_doc_count,
        raw_data=final_response.model_dump_json(),
    )
    yield {"stage": "final", "data": final_response.model_dump()}


async def analyze_email_pipeline(
    message_id: str,
    access_token: Optional[str] = None,
    dom_sender: Optional[str] = None,
    dom_subject: Optional[str] = None,
    dom_body_text: Optional[str] = None,
    dom_links: Optional[List[str]] = None,
) -> EmailAnalyzeResponse:
    """하위 호환용 단일 JSON 응답 래퍼 (내부적으로 초고속 스트리밍 파이프라인의 최종 결과 반환)."""
    final_data = None
    async for event in analyze_email_stream(
        message_id=message_id,
        access_token=access_token,
        dom_sender=dom_sender,
        dom_subject=dom_subject,
        dom_body_text=dom_body_text,
        dom_links=dom_links,
    ):
        if event.get("stage") == "final":
            final_data = event["data"]

    if final_data is None:
        raise RuntimeError("이메일 분석 결과를 생성하지 못했습니다.")
    return EmailAnalyzeResponse.model_validate(final_data)
