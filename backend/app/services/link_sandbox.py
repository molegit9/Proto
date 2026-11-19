import urllib.parse
from bs4 import BeautifulSoup
import tldextract

from app.services.http_client import get_http_client

# 네트워크 PSL 다운로드 대기를 방지하기 위해 내장 오프라인 스냅샷만 사용
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# 사용자 생성 콘텐츠/퍼블릭 호스팅 도메인 (화이트리스트 제외, 항상 동적 분석 대상)
PUBLIC_HOSTING_DOMAINS = (
    "github.io",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
)

# 공인 신뢰 도메인 (정상 기업 메일 링크에 불필요한 Playwright 기동 방지)
TRUSTED_SAFE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
    "naver.com", "pstatic.net", "kakao.com", "kakaocorp.com", "daum.net",
    "coupang.com", "coupangeats.com",
    "microsoft.com", "live.com", "office.com", "aka.ms",
    "apple.com", "icloud.com",
    "github.com", "amazon.com", "aws.amazon.com", "netflix.com",
    "samsung.com", "lg.com", "sktelecom.com", "kt.com",
    "kbcard.com", "kbstar.com", "shinhancard.com", "shinhan.com",
    "wooribank.com", "hanabank.com", "ibk.co.kr", "toss.im",
    "hancom.com", "everytime.kr", "etoos.com", "supercell.com",
    "instagram.com", "facebook.com", "linkedin.com", "x.com", "twitter.com",
    "notion.so", "slack.com", "discord.com", "zoom.us",
}

SHORT_URL_DOMAINS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "me2.do", "han.gl")


def get_base_domain(url_or_host: str) -> str:
    ext = _tld_extractor(url_or_host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return (ext.domain or "").lower()


def is_public_hosting(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    return any(host == ph or host.endswith("." + ph) for ph in PUBLIC_HOSTING_DOMAINS)


def is_trusted_domain(url: str) -> bool:
    if is_public_hosting(url):
        return False
    base = get_base_domain(url)
    return base in TRUSTED_SAFE_DOMAINS


def normalize_url(url: str) -> str:
    """URL의 추적용 쿼리(utm_*) 등을 제거하여 정규화"""
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qsl(parsed.query)
    clean_params = [(k, v) for k, v in query_params if not k.startswith("utm_")]
    clean_query = urllib.parse.urlencode(clean_params)
    return urllib.parse.urlunparse(parsed._replace(query=clean_query))


def is_short_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in SHORT_URL_DOMAINS)


def check_domain_mismatch(url: str, sender_domain: str) -> bool:
    if not sender_domain or sender_domain == "Unknown":
        return False
    url_base = get_base_domain(url)
    sender_base = get_base_domain(sender_domain)
    if not url_base or not sender_base:
        return False
    return url_base != sender_base


def should_escalate_to_browser_analysis(
    url: str,
    vt_stats: dict,
    static_result: dict,
    sender_domain: str,
    llm_phase1_risk: str,
) -> bool:
    """
    Tier 2 동적 분석(Playwright) 에스컬레이션 조건 정밀화:
    - 정상 기업 메일의 클릭 추적 리다이렉트·검색창 <form> 때문에 Playwright가 남발되는 병목을 차단합니다.
    """
    # 1. 단축 URL / 퍼블릭 호스팅은 항상 동적 분석 수행
    if is_short_url(url) or is_public_hosting(url):
        return True

    # 2. VirusTotal 악성/의심 탐지 시 즉시 동적 분석 수행
    if vt_stats and (vt_stats.get("malicious", 0) > 0 or vt_stats.get("suspicious", 0) > 0):
        return True

    # 3. 공인 신뢰 도메인(또는 최종 리다이렉트도 신뢰 도메인)은 동적 분석 스킵
    final_url = static_result.get("final_url") or url
    if is_trusted_domain(url) and is_trusted_domain(final_url):
        return False

    # 4. VirusTotal에서 안전 검증 완료된 URL은 동적 분석 스킵
    if vt_stats:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        harmless = vt_stats.get("harmless", 0)
        undetected = vt_stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        if total_engines >= 5 and malicious == 0 and suspicious == 0:
            return False

    # 5. 정적 분석 정밀 의심 조건:
    #    - 비밀번호 입력란 존재 (신뢰 도메인이 아닐 때)
    #    - 크로스 도메인 리다이렉션 (발신자 도메인 및 원본 도메인과 다른 외부 도메인으로 튕김)
    if static_result.get("has_password_field"):
        return True
    if static_result.get("is_cross_domain_redirect") and check_domain_mismatch(final_url, sender_domain):
        return True

    # 6. LLM 1차 판단이 HIGH인 경우
    if llm_phase1_risk == "HIGH":
        return True

    # 7. 발신자 도메인 불일치 + 1차 AI 리스크 MEDIUM 이상 (신뢰 도메인 제외)
    if check_domain_mismatch(url, sender_domain) and llm_phase1_risk in ("MEDIUM", "HIGH"):
        return True

    return False


async def inspect_url_static(url: str) -> dict:
    """Tier 1: 초경량 정적 DOM 분석 (신뢰 도메인 즉시 패스, 1.8초 타임아웃, 최대 150KB 읽기)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"original_url": url, "error": "Invalid scheme"}

    # 신뢰 도메인은 외부 HTTP 요청 없이 즉시 정상 반환 (속도 극대화)
    if is_trusted_domain(url):
        return {
            "original_url": url,
            "final_url": url,
            "is_redirected": False,
            "is_cross_domain_redirect": False,
            "page_title": "Trusted Domain (Fast Skip)",
            "has_password_field": False,
            "has_login_form": False,
            "trusted_skip": True,
        }

    orig_base = get_base_domain(url)
    try:
        client = get_http_client()
        chunks = []
        total_bytes = 0
        final_url = url

        async with client.stream("GET", url, timeout=1.8) as response:
            final_url = str(response.url)
            content_type = (response.headers.get("content-type") or "").lower()
            if "text/html" in content_type or not content_type:
                async for chunk in response.aiter_bytes(chunk_size=16384):
                    chunks.append(chunk)
                    total_bytes += len(chunk)
                    if total_bytes >= 150_000:  # 최대 150KB만 파싱
                        break

        html_text = b"".join(chunks).decode("utf-8", errors="ignore")
        soup = BeautifulSoup(html_text, "html.parser")
        final_base = get_base_domain(final_url)

        has_pwd = bool(soup.find("input", {"type": "password"}))
        # 단순 검색창 <form>이 아니라 비밀번호/민감정보 입력 필드가 포함된 폼만 login_form으로 판정
        sensitive_tokens = ("password", "passwd", "pwd", "pin", "otp", "cvv", "card")
        has_sensitive_form = has_pwd or any(
            any(tok in ((inp.get("name") or "") + " " + (inp.get("id") or "")).lower() for tok in sensitive_tokens)
            for inp in soup.find_all("input")
        )

        return {
            "original_url": url,
            "final_url": final_url,
            "is_redirected": url != final_url,
            "is_cross_domain_redirect": bool(orig_base and final_base and orig_base != final_base),
            "page_title": soup.title.string.strip() if soup.title and soup.title.string else "No Title",
            "has_password_field": has_pwd,
            "has_login_form": has_sensitive_form,
        }
    except Exception as e:
        return {"original_url": url, "final_url": url, "error": f"Failed: {str(e)}"}
