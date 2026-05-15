from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import json
import httpx
from datetime import datetime
import asyncio
from pydantic import BaseModel
from typing import Optional

from google import genai
from google.genai import types

# MailReader Imports
from app.schemas.email import EmailAnalyzeRequest, EmailAnalyzeResponse
from app.services.analyzer import analyze_email_pipeline

# Service Imports
from app.services.database import get_db, log_analysis, get_cached_analysis, get_recent_logs
from app.services.virustotal_service import check_url_virustotal
from app.services.rag_service import collection as rag_collection
from app.services.link_sandbox import inspect_url_static
from app.services.browser_analyzer import inspect_url_with_playwright
from app.core.config import settings

router = APIRouter()

# --- Pydantic Models for Zp ---
class URLRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None
    action_type: Optional[str] = "hover"
    is_spoofed: Optional[bool] = False
    target_brand: Optional[str] = None
    is_exact_match: Optional[bool] = False
    enable_deep_scan: Optional[bool] = False

class TextAnalyzeRequest(BaseModel):
    selected_text: str

# --- Helper Functions for Zp ---
async def get_domain_age_rdap(domain: str):
    """
    [OSINT] 실제 RDAP API를 호출하여 도메인 생성일을 확인합니다.
    """
    parts = domain.split('.')
    if len(parts) > 2:
        domain = '.'.join(parts[-2:])
        
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            res = await client.get(f"https://rdap.org/domain/{domain}")
            
            if res.status_code == 200:
                data = res.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        reg_date_str = event.get("eventDate")
                        if reg_date_str:
                            reg_date = datetime.fromisoformat(reg_date_str.replace('Z', '+00:00'))
                            now = datetime.now(reg_date.tzinfo)
                            days_old = (now - reg_date).days
                            if days_old < 30:
                                return f"생성된 지 {days_old}일 밖에 안 된 신규(위험) 도메인!!"
                            else:
                                years = days_old // 365
                                return f"생성된 지 {years}년 이상 된 오래된 안전 도메인"
    except Exception as e:
        print(f"[RDAP] 도메인 수집 오류({domain}): {e}")
        pass
        
    return "도메인 생성일 정보 보안 처리됨 (수년 이상 된 일반 도메인일 확률 높음)"

def get_genai_client():
    if settings.GEMINI_API_KEY and settings.GEMINI_API_KEY != "YOUR_GEMINI_API_KEY":
        return genai.Client(api_key=settings.GEMINI_API_KEY)
    return None


# ==============================================================================
# Endpoints
# ==============================================================================

@router.post("/api/analyze-email", response_model=EmailAnalyzeResponse)
async def analyze_email(request: EmailAnalyzeRequest):
    """MailReader 단일 JSON 응답"""
    try:
        result = await analyze_email_pipeline(request.message_id, request.access_token)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/v1/analyze")
async def analyze_url(req: URLRequest):
    """Zp NDJSON 스트리밍 (Hover/URL)"""
    async def event_generator():
        try:
            if not req.url:
                yield json.dumps({"status": "error", "message": "Hover action requires a valid URL."}) + "\n"
                return
                
            domain = req.url.split("//")[-1].split("/")[0]

            parts = domain.split('.')
            base_domain = domain
            if len(parts) > 2:
                base_domain = f"{parts[-2]}.{parts[-1]}"
            top_brands = ["apple.com", "naver.com", "google.com", "amazon.com", "github.com", "facebook.com", "netflix.com"]

            is_backend_exact_match = base_domain in top_brands
            brand_name = base_domain if is_backend_exact_match else req.target_brand
            
            if is_backend_exact_match or (req.is_exact_match and req.target_brand):
                early_data = json.dumps({"safety_score": 100, "reason": f"[{brand_name}] 공식 홈페이지입니다. 안전하게 이용하세요. (로컬 검증 완료)"})
                log_analysis("hover", req.url, "100", f"[{brand_name}] 공식 도메인 즉시 인증", raw_data=json.dumps({"reason": "exact_match"}, ensure_ascii=False))
                yield json.dumps({"status": "success", "data": early_data}) + "\n"
                return
            
            cached = get_cached_analysis(req.url)
            if cached:
                status_val = str(cached["status"])
                if not status_val.isdigit():
                    if "SAFE" in status_val: status_val = "100"
                    elif "WARNING" in status_val: status_val = "40"
                    elif "DANGER" in status_val: status_val = "10"
                    else: status_val = "50"
                
                cache_data = {"safety_score": int(status_val), "reason": cached["reason"]}
                yield json.dumps({"status": "success", "data": json.dumps(cache_data)}) + "\n"
                return
            
            yield json.dumps({"progress": "바이러스토탈 및 도메인 정보 검색 중... 🔍"}) + "\n"
            
            domain_age_task = asyncio.create_task(get_domain_age_rdap(domain))
            vt_task = asyncio.create_task(check_url_virustotal(req.url))
            
            domain_age, vt_result = await asyncio.gather(domain_age_task, vt_task)
            
            vt_info = "미확인 (기록 없거나 대기열 초과)"
            if vt_result:
                if vt_result.get("status") == "VT_DANGER":
                    vt_info = "위험 (기존 보안 엔진 블랙리스트에 이미 감지된 악성 도메인!)"
                    early_data = json.dumps({"safety_score": 10, "reason": "전문 보안 엔진(VirusTotal) 블랙리스트에 이미 감지된 악성 사이트입니다. 절대 접속하지 마세요! (빠른 차단)"})
                    log_analysis("hover", req.url, "10", "전문 보안 엔진(VirusTotal)에서 차단됨", raw_data=json.dumps({"vt_findings": vt_result}, ensure_ascii=False))
                    yield json.dumps({"status": "success", "data": early_data}) + "\n"
                    return
                else:
                    vt_info = "안전 (전문 보안 엔진 블랙리스트에 없음)"
            
            yield json.dumps({"progress": "AI(LLM)가 정보를 받아 처리 중... 🤖"}) + "\n"
            
            # --- 2-Tier Deep Scan (Optional) ---
            deep_scan_info = ""
            raw_data_dict = {}
            if vt_result: raw_data_dict["vt_findings"] = vt_result

            if req.enable_deep_scan:
                # 1단계: 정적 검사
                yield json.dumps({"progress": "🔍 정밀 분석 1단계 — 정적 HTML 검사 중..."}) + "\n"
                try:
                    static_res = await inspect_url_static(req.url)
                    raw_data_dict["static_findings"] = static_res
                    static_str = json.dumps(static_res, ensure_ascii=False)
                    
                    # 1단계 결과 요약 메시지
                    static_flags = []
                    if static_res.get("has_password_field"): static_flags.append("비밀번호 입력란 감지")
                    if static_res.get("has_suspicious_form"): static_flags.append("의심 폼 감지")
                    if static_res.get("final_url") and static_res.get("final_url") != req.url: static_flags.append("리다이렉션 감지")
                    static_summary = f"정적 검사 완료 ({'⚠️ ' + ', '.join(static_flags) if static_flags else '이상 없음'})"
                    yield json.dumps({"progress": f"✅ {static_summary}"}) + "\n"
                    
                    # 2단계: Playwright — Windows asyncio 호환을 위해 별도 스레드+이벤트 루프에서 실행
                    yield json.dumps({"progress": "🕵️ 정밀 분석 2단계 — Playwright 가상 브라우저 실행 중... (수 초 소요)"}) + "\n"
                    
                    def run_playwright_in_thread(url):
                        import sys, asyncio
                        if sys.platform == "win32":
                            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                        async def _run():
                            from playwright.async_api import async_playwright
                            async with async_playwright() as p:
                                return await inspect_url_with_playwright(p, url)
                        return asyncio.run(_run())
                    
                    loop = asyncio.get_running_loop()
                    dynamic_res = await loop.run_in_executor(None, run_playwright_in_thread, req.url)
                    raw_data_dict["dynamic_findings"] = dynamic_res
                    dynamic_str = json.dumps(dynamic_res, ensure_ascii=False)
                    
                    # 2단계 결과 요약 메시지
                    dyn_flags = []
                    if dynamic_res.get("is_redirected"): dyn_flags.append("리다이렉션 감지")
                    if dynamic_res.get("has_password_field"): dyn_flags.append("비밀번호 폼 감지")
                    if dynamic_res.get("has_hidden_form"): dyn_flags.append("히든 폼 감지")
                    dyn_summary = f"동적 검사 완료 ({'⚠️ ' + ', '.join(dyn_flags) if dyn_flags else '이상 없음'})"
                    yield json.dumps({"progress": f"✅ {dyn_summary}"}) + "\n"
                    
                    deep_scan_info = f"""
                    [정밀 분석 (Deep Scan) 결과]
                    - 정적 DOM 검사 결과: {static_str}
                    - 동적 샌드박스(Playwright) 실행 결과: {dynamic_str}
                    """
                except Exception as ex:
                    yield json.dumps({"progress": f"⚠️ 정밀 분석 중 오류 발생: {str(ex)[:50]}"}) + "\n"
                    deep_scan_info = f"정밀 분석 실패: {ex}"
            # -----------------------------------
            
            target_str = req.target_brand if req.target_brand else "없음"
            is_https = "사용 중 (안전함)" if str(req.url).startswith("https://") else "미사용 - HTTP 기반의 암호화되지 않은 취약한 연결 (개인정보 탈취 위험 높음!)"
            
            prompt = f"""
            당신은 보안 취약계층(어르신, 학생 등)을 돕는 친절한 화이트해커 전문가입니다.
            '인증서 만료', 'XSS' 같은 어려운 기술 용어는 절대 쓰지 말고, 중학생도 이해할 수 있는 쉬운 비유와 일상어로 1~2문장으로 대답해야 합니다.
            
            대상 URL: {req.url}
            
            [사전 분석 메타데이터]
            - HTTPS 통신 보안 프로토콜 사용 여부: {is_https}
            - Levenshtein 타이포스쿼팅 탐지: {req.is_spoofed} (사칭 타겟: {target_str})
            - 도메인 나이(RDAP): {domain_age}
            - VirusTotal 보안 DB 감지 여부: {vt_info}
            {deep_scan_info}
            
            위 메타데이터와 시스템 컨텍스트를 파악하여, 이 사이트의 안전도 점수(0~100)를 평가하세요.
            100점은 '공식 사이트이며 완전히 안전함'을 뜻하고, 0점은 '심각한 사기/피싱 환경'을 의미합니다.
            만약 [정밀 분석] 결과에서 리다이렉션 변조, 악성 폼 렌더링, 특히 '히든 폼(has_hidden_form: true)'이 감지되었다면 사용자를 속이려는 악의적인 목적(투명 폼 등)이 매우 강하므로 점수를 0점 가까이 크게 낮추고, 이유에 투명/히든 폼의 위험성을 반드시 명시하세요.
            
            응답은 반드시 아래 JSON 형식으로만 반환하세요:
            {{"safety_score": 90, "reason": "이곳은 아이폰 공식 홈페이지입니다. 안심하고 쓰셔도 좋습니다."}}
            """
            
            client = get_genai_client()
            if client is None:
                yield json.dumps({"status": "error", "message": "Gemini API 키가 설정되지 않았습니다."}) + "\n"
                return
                
            response = await client.aio.models.generate_content(
                model='gemini-3.1-flash-lite-preview',
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                )
            )
            
            try:
                res_data = json.loads(response.text)
                log_score = str(res_data.get("safety_score", 50))
                log_reason = res_data.get("reason", "")
                log_analysis("hover", req.url, log_score, log_reason, raw_data=json.dumps(raw_data_dict, ensure_ascii=False))
            except Exception as db_e:
                print("DB 로그 저장 에러:", db_e)
                
            yield json.dumps({"status": "success", "data": response.text}) + "\n"
        except Exception as e:
            yield json.dumps({"status": "error", "message": str(e)}) + "\n"
            
    return StreamingResponse(event_generator(), media_type="application/x-ndjson")


@router.post("/api/v1/analyze/text")
async def analyze_rag_text(req: TextAnalyzeRequest):
    """Zp NDJSON 스트리밍 (Drag/Text)"""
    async def event_generator():
        try:
            yield json.dumps({"progress": "RAG 지식베이스 검색 중... 🔍"}) + "\n"
            
            retrieved_context = ""
            if rag_collection is not None:
                results = rag_collection.query(query_texts=[req.selected_text], n_results=3)
                
                if results and "documents" in results and len(results["documents"]) > 0 and len(results["documents"][0]) > 0:
                    docs = results["documents"][0]
                    metas = results["metadatas"][0]
                    distances = results.get("distances", [[999]])[0]
                    
                    if len(distances) > 0 and distances[0] < 0.15:
                        best_label = str(metas[0].get("label", "0"))
                        if best_label == "2":
                            yield json.dumps({"risk_level": "위험", "score": 95, "reason": "보안 데이터베이스의 악성 피싱 판례와 100% 일치하여, AI 딥러닝을 거치지 않고 초고속으로 차단했습니다.", "mitigation": "절대로 링크를 클릭하지 마세요."}) + "\n"
                            return
                        elif best_label in ["1", "3"]:
                            yield json.dumps({"risk_level": "안전", "score": 5, "reason": "보안 DB의 안전한 문구 판례와 100% 일치하여 AI 분석을 생략하고 통과시킵니다.", "mitigation": "안심하세요."}) + "\n"
                            return
                        elif best_label in ["4", "5"]:
                            yield json.dumps({"risk_level": "위험", "score": 85, "reason": "알려진 악성 스팸 메일 판례와 파일이 100% 동일합니다. 차단됨.", "mitigation": "즉시 삭제하세요."}) + "\n"
                            return

                    context_pieces = []
                    for i, doc in enumerate(docs):
                        label = metas[i].get("label", "unknown")
                        source = metas[i].get("source", "unknown")
                        context_pieces.append(f"[사례 {i+1} : 과거 라벨 {label} ({source})]\n> 내용: {doc}")
                    retrieved_context = "\n\n".join(context_pieces)
            else:
                retrieved_context = "(로컬 Vector DB가 오프라인입니다.)"

            yield json.dumps({"progress": "AI(LLM)가 정보를 받아 처리 중... 🤖"}) + "\n"

            rag_prompt = f"""
            당신은 개인용 보안 시스템의 코어 엔진 역할을 하는 RAG(검색 증강 생성) 기반 위협 분석 AI입니다.
            사용자가 웹에서 의심스러워 드래그한 텍스트에 스미싱, 피싱, 악성 메일 유도 등 사회공학적 사기 의도가 있는지 분석하세요.

            **[분석 대상 텍스트]**
            "{req.selected_text}"

            **[RAG 지식베이스 검색 결과: 유사 과거 판례 3건]**
            {retrieved_context}
            
            위의 RAG 판례 기록과 텍스트 문맥을 대조하여 실질적 위협도를 종합 분석하세요.
            분석 결과는 **0~100점**의 score로 표기해야 합니다.
            
            반드시 지정된 아래 JSON Schema 형식으로만 응답하세요:
            {{"risk_level": "위험", "score": 95, "reason": "이 텍스트는 RAG 데이터베이스의 Label 2 판례와 문맥이 99% 일치하는 악성 택배 스미싱 수법입니다.", "mitigation": "절대로 링크를 클릭하지 마세요."}}
            """

            client = get_genai_client()
            if client is None:
                yield json.dumps({"risk_level": "에러", "score": 50, "reason": "Gemini API 키가 설정되지 않았습니다.", "mitigation": "-"}) + "\n"
                return

            response = await client.aio.models.generate_content(
                model='gemini-3.1-flash-lite-preview',
                contents=rag_prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    safety_settings=[
                        types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold=types.HarmBlockThreshold.BLOCK_NONE),
                        types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_HARASSMENT, threshold=types.HarmBlockThreshold.BLOCK_NONE),
                        types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold=types.HarmBlockThreshold.BLOCK_NONE),
                        types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold=types.HarmBlockThreshold.BLOCK_NONE),
                    ]
                )
            )
            
            try:
                res_data = json.loads(response.text)
                yield json.dumps(res_data) + "\n"
            except json.JSONDecodeError:
                yield json.dumps({"risk_level": "에러", "score": 0, "reason": "AI 파싱 오류", "mitigation": "-"}) + "\n"
                
        except Exception as e:
            error_msg = str(e)
            if "503" in error_msg or "UNAVAILABLE" in error_msg:
                yield json.dumps({"risk_level": "분석 지연", "score": 50, "reason": "현재 API 서버 지연이 발생했습니다.", "mitigation": "나중에 다시 시도하세요."}) + "\n"
            else:
                yield json.dumps({"risk_level": "시스템 오류", "score": 50, "reason": f"에러 발생: {error_msg}", "mitigation": "-"}) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")


@router.post("/api/clear-db")
async def clear_db():
    """Zp DB 초기화"""
    try:
        with get_db() as conn:
            conn.execute('DELETE FROM security_logs')
            conn.execute('DELETE FROM email_logs')
        return {"status": "success", "message": "Database cleared safely."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/logs")
async def get_logs(limit: int = 20):
    """최근 통합 분석 로그 반환"""
    try:
        logs = get_recent_logs(limit=limit)
        return {"status": "success", "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """서버 상태 반환"""
    return {"status": "ok", "message": "Phishing Security Assistant API is running"}
