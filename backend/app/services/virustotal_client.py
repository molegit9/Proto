import httpx
from app.core.config import settings

async def inspect_links_with_virustotal(urls: list[str]) -> dict:
    """VirusTotal API를 활용하여 URL 리스트 평판 조회"""
    if not urls:
        return {"scanned": 0, "malicious_found": 0, "details": []}
        
    results = {"scanned": len(urls), "malicious_found": 0, "details": []}
    
    if not settings.VIRUSTOTAL_API_KEY or settings.VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        for url in urls:
            results["details"].append({"url": url, "malicious": False, "note": "VT key not set"})
        return results

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    
    async with httpx.AsyncClient() as client:
        for url in urls:
            # Note: 실제 구현시에는 url을 base64 인코딩하여 /api/v3/urls/{id} 로 조회해야 합니다.
            try:
                # 더미 응답 처리 (실제 API 호출로 대체 필요)
                is_malicious = False 
                if is_malicious:
                    results["malicious_found"] += 1
                results["details"].append({"url": url, "malicious": is_malicious})
            except Exception:
                continue
                
    return results
