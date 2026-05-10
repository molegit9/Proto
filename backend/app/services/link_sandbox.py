import httpx
from bs4 import BeautifulSoup
import urllib.parse
from app.services.browser_analyzer import inspect_url_with_playwright

def normalize_url(url: str) -> str:
    """URL의 추적용 쿼리(utm_*) 등을 제거하여 정규화"""
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qsl(parsed.query)
    clean_params = [(k, v) for k, v in query_params if not k.startswith("utm_")]
    clean_query = urllib.parse.urlencode(clean_params)
    return urllib.parse.urlunparse(parsed._replace(query=clean_query))

def is_short_url(url: str) -> bool:
    short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
    parsed = urllib.parse.urlparse(url)
    return any(domain in parsed.netloc for domain in short_domains)

def check_domain_mismatch(url: str, sender_domain: str) -> bool:
    if sender_domain == "Unknown": 
        return False
    parsed = urllib.parse.urlparse(url)
    return sender_domain not in parsed.netloc

def should_escalate_to_browser_analysis(url: str, vt_stats: dict, static_result: dict, sender_domain: str, llm_phase1_risk: str) -> bool:
    """Tier 2 동적 분석 에스컬레이션 조건 총괄"""
    # 1. 단축 URL
    if is_short_url(url): return True
    # 2. VirusTotal 악성 결과 (명확한 스키마 stats 기준)
    if vt_stats.get("malicious", 0) > 0 or vt_stats.get("suspicious", 0) > 0: return True
    # 3. 도메인 불일치
    if check_domain_mismatch(url, sender_domain): return True
    # 4. 정적 분석에서 리다이렉션 또는 로그인 폼 감지
    if static_result.get("is_redirected") or static_result.get("has_password_field") or static_result.get("has_login_form"): return True
    # 5. LLM 1차 판단이 MEDIUM 이상인 경우
    if llm_phase1_risk in ["MEDIUM", "HIGH"]: return True
        
    return False

async def inspect_url_static(url: str) -> dict:
    """Tier 1: 정적 DOM 분석"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        return {"url": url, "error": "Invalid scheme"}
        
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=3.0) as client:
            response = await client.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            return {
                "original_url": url,
                "final_url": str(response.url),
                "is_redirected": url != str(response.url),
                "page_title": soup.title.string.strip() if soup.title and soup.title.string else "No Title",
                "has_password_field": bool(soup.find("input", {"type": "password"})),
                "has_login_form": bool(soup.find("form")),
            }
    except Exception as e:
        return {"original_url": url, "error": f"Failed: {str(e)}"}
