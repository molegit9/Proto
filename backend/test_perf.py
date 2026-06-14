import os
import sys
import time
import json
import asyncio
import base64

# app 패키지 인식을 위해 sys.path에 추가
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# .env 로드
from dotenv import load_dotenv
load_dotenv()

# Windows cmd encoding issue 방지
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

from app.services.parser import sanitize_email_dom, extract_visible_text, extract_links
from app.services.analyzer import analyze_email_pipeline

async def test_run():
    # 1. raw_email_sample.json 로드
    if not os.path.exists("raw_email_sample.json"):
        print("raw_email_sample.json 이 존재하지 않습니다.")
        return
        
    print("raw_email_sample.json 로드 완료. 테스트 시작...")
    
    # mock_fetch_email_raw를 만들어 gmail_client.fetch_email_raw를 패치합니다.
    import app.services.analyzer as analyzer_mod
    
    async def mock_fetch_email_raw(message_id, access_token):
        with open("raw_email_sample.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        payload = data.get("payload", {})
        headers_list = payload.get("headers", [])
        sender = next((h["value"] for h in headers_list if h["name"] == "From"), "Unknown")
        subject = next((h["value"] for h in headers_list if h["name"] == "Subject"), "No Subject")
        
        body_html = ""
        parts = payload.get("parts", [payload])
        
        def find_html_part(parts_list):
            for part in parts_list:
                if part.get("mimeType") == "text/html":
                    return part.get("body", {}).get("data", "")
                elif "parts" in part:
                    res = find_html_part(part["parts"])
                    if res: return res
            return ""
            
        body_data = find_html_part(parts)
        if body_data:
            body_html = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore")
                
        return {
            "sender": sender,
            "subject": subject,
            "body_html": body_html
        }
    
    # fetch_email_raw 함수를 mock으로 교체
    analyzer_mod.fetch_email_raw = mock_fetch_email_raw
    
    # RAG 데이터베이스 로딩 시도 (RAG 서비스 강제 초기화 필요)
    from app.services.rag_service import init_vector_db
    print("Vector DB 초기화 중...")
    init_vector_db(csv_path="./data/merged_security_dataset.csv")
    
    # 실행 시간 측정
    start_time = time.perf_counter()
    response = await analyzer_mod.analyze_email_pipeline("test_id", "test_token")
    end_time = time.perf_counter()
    
    print("\n================ 분석 결과 ================")
    print(f"수행 시간: {end_time - start_time:.4f} 초")
    print(f"피싱 여부: {response.is_phishing}")
    print(f"위험 단계: {response.risk_level}")
    print(f"RAG 사용 여부: {response.rag_used}")
    print(f"RAG 검색 건수: {response.rag_doc_count}")
    print(f"요약 내용:\n{response.mail_summary}")
    print(f"최종 리스크 판단 요약:\n{response.summary}")
    print(f"VirusTotal 결과: 스캔 수 {response.vt_findings.get('scanned', 0)}, 탐지 수 {response.vt_findings.get('malicious_found', 0)}")
    print(f"정적 링크 검출 수: {len(response.static_findings)}")
    print(f"동적(Playwright) 링크 검출 수: {len(response.dynamic_findings)}")
    print("===========================================")

if __name__ == "__main__":
    asyncio.run(test_run())
