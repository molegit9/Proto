"""
공유 httpx.AsyncClient 커넥션 풀 관리 모듈.
요청마다 TLS 핸드셰이크를 반복하지 않고 keep-alive 연결을 재사용하여
Gmail API / VirusTotal / 정적 URL 분석의 레이턴시를 단축합니다.
"""
from typing import Optional
import httpx

_shared_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=30, max_keepalive_connections=15),
            timeout=httpx.Timeout(5.0, connect=2.0),
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
                )
            },
        )
    return _shared_client


async def close_http_client():
    global _shared_client
    if _shared_client is not None and not _shared_client.is_closed:
        try:
            await _shared_client.aclose()
        except Exception:
            pass
    _shared_client = None
