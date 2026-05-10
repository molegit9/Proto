import base64
import httpx
import asyncio
from typing import List, Optional
from app.core.config import settings

async def check_url_virustotal(url: str) -> Optional[dict]:
    vt_api_key = settings.VIRUSTOTAL_API_KEY
    if not vt_api_key or vt_api_key == "YOUR_VIRUSTOTAL_API_KEY":
        return None

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": vt_api_key}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=5.0
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                if malicious > 0 or suspicious > 0:
                    return {
                        "status": "VT_DANGER",
                        "reason": f"VirusTotal의 {malicious + suspicious}개 엔진에서 이 링크를 위험요소로 감지했습니다."
                    }
                else:
                    return {
                        "status": "VT_SAFE",
                        "reason": "전문 보안 엔진(VirusTotal) 검사 결과, 이 링크는 안전한 것으로 확인되었습니다."
                    }
            elif response.status_code == 404:
                # Not found in VT database
                return None
            else:
                return None
    except Exception as e:
        print(f"VirusTotal request error: {e}")
        return None

async def inspect_links_with_virustotal(urls: List[str]) -> dict:
    """VirusTotal API를 활용하여 URL 리스트 평판 조회"""
    if not urls:
        return {"scanned": 0, "malicious_found": 0, "details": []}
        
    results = {"scanned": len(urls), "malicious_found": 0, "details": []}
    
    vt_api_key = settings.VIRUSTOTAL_API_KEY
    if not vt_api_key or vt_api_key == "YOUR_VIRUSTOTAL_API_KEY":
        for url in urls:
            results["details"].append({"url": url, "malicious": False, "note": "VT key not set"})
        return results

    # asyncio.gather로 병렬 처리
    tasks = [check_url_virustotal(url) for url in urls]
    vt_responses = await asyncio.gather(*tasks, return_exceptions=True)
    
    for url, vt_resp in zip(urls, vt_responses):
        if isinstance(vt_resp, Exception):
            print(f"Error checking {url}: {vt_resp}")
            results["details"].append({"url": url, "malicious": False, "note": "Error"})
            continue
            
        if vt_resp is None:
            results["details"].append({"url": url, "malicious": False, "note": "No data or not found"})
            continue
            
        is_malicious = vt_resp.get("status") == "VT_DANGER"
        if is_malicious:
            results["malicious_found"] += 1
            
        results["details"].append({
            "url": url, 
            "malicious": is_malicious, 
            "note": vt_resp.get("reason", "")
        })
                
    return results
