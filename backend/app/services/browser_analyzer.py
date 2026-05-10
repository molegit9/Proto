import asyncio
from playwright.async_api import Playwright, TimeoutError
import tldextract

MAX_CONCURRENT_BROWSERS = 2
browser_semaphore = asyncio.Semaphore(MAX_CONCURRENT_BROWSERS)

async def inspect_url_with_playwright(playwright: Playwright, url: str) -> dict:
    """Tier 2: Playwright 기반 동적 DOM 분석"""
    result = {
        "original_url": url,
        "final_url": url,
        "page_title": "",
        "has_password_field": False,
        "has_form": False,
        "is_redirected": False,
        "error": None,
        "error_type": "unknown",
        "requested_urls": [],
        "external_requests": [],
        "redirect_chain": [],
        "external_links": [],
        "suspicious_keywords": [],
        "favicon_url": None,
        "meta_description": None
    }
    
    # 원본 URL의 eTLD+1 도메인 추출
    extracted_original = tldextract.extract(url)
    original_domain = f"{extracted_original.domain}.{extracted_original.suffix}" if extracted_original.suffix else extracted_original.domain
    
    browser = None
    context = None
    page = None
    
    async with browser_semaphore:
        try:
            browser = await playwright.chromium.launch(headless=True)
            
            # 보안 설정: 다운로드 금지, 불필요한 이벤트/권한 차단
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                java_script_enabled=True,
                accept_downloads=False,
                permissions=[] # 위치정보, 알림 등 모든 권한 차단
            )
            
            # 1. 리소스 차단 (보안)
            async def route_handler(route):
                if route.request.resource_type in ["image", "media", "font", "stylesheet"]:
                    await route.abort()
                else:
                    await route.continue_()
                    
            await context.route("**/*", route_handler)
            
            page = await context.new_page()
            
            # 5. 보안 강화: dialog 자동 무시
            page.on("dialog", lambda dialog: asyncio.ensure_future(dialog.dismiss()))
            
            # 2. page.on("request") 요청 추적
            def on_request(request):
                # abort된 리소스는 수집 제외 (resource_type으로 필터링)
                if request.resource_type in ["image", "media", "font", "stylesheet"]:
                    return
                    
                req_url = request.url
                result["requested_urls"].append(req_url)
                
                extracted_req = tldextract.extract(req_url)
                req_domain = f"{extracted_req.domain}.{extracted_req.suffix}" if extracted_req.suffix else extracted_req.domain
                
                if req_domain and original_domain and req_domain != original_domain:
                    result["external_requests"].append(req_url)
                    
            page.on("request", on_request)
            
            # 3. 리다이렉트 체인 추적
            def on_response(response):
                if response.status in [301, 302, 303, 307, 308]:
                    result["redirect_chain"].append({
                        "url": response.url,
                        "status": response.status
                    })
                    
            page.on("response", on_response)
            
            # 최대 5초 타임아웃
            response = await page.goto(url, timeout=5000, wait_until="domcontentloaded")
            
            if response:
                result["final_url"] = page.url
                result["is_redirected"] = (url != page.url)
                result["page_title"] = await page.title()
                
                # 렌더링 후 동적으로 생성된 폼 및 비밀번호 필드 존재 여부 확인
                result["has_password_field"] = await page.locator("input[type='password']").count() > 0
                result["has_form"] = await page.locator("form").count() > 0
                
                # 4. 수집 정보 추가
                # external_links
                try:
                    links = await page.locator("a").evaluate_all("els => els.map(el => el.href)")
                    ext_links = []
                    for link in links:
                        if not link: continue
                        extracted_link = tldextract.extract(link)
                        link_domain = f"{extracted_link.domain}.{extracted_link.suffix}" if extracted_link.suffix else extracted_link.domain
                        if link_domain and link_domain != original_domain:
                            ext_links.append(link)
                    result["external_links"] = list(set(ext_links)) # 중복 제거
                except Exception:
                    result["external_links"] = []
                    
                # suspicious_keywords
                try:
                    content = await page.content()
                    content_lower = content.lower()
                    target_keywords = ['verify your account', 'enter your password', 'suspended', '계정 확인', '비밀번호 입력', '본인인증']
                    result["suspicious_keywords"] = [kw for kw in target_keywords if kw in content_lower]
                except Exception:
                    pass
                    
                # favicon_url
                try:
                    favicon = await page.evaluate("document.querySelector('link[rel~=\"icon\"]')?.href")
                    if favicon:
                        result["favicon_url"] = favicon
                except Exception:
                    pass
                    
                # meta_description
                try:
                    meta_desc = await page.evaluate("document.querySelector('meta[name=\"description\"]')?.content")
                    if meta_desc:
                        result["meta_description"] = meta_desc
                except Exception:
                    pass
    
        except TimeoutError:
            result["error"] = "Timeout exceeded (5s)"
            result["error_type"] = "timeout"
        except Exception as e:
            error_str = str(e).lower()
            result["error"] = str(e)
            if "timeout" in error_str:
                result["error_type"] = "timeout"
            elif "err_name_not_resolved" in error_str:
                result["error_type"] = "dns_failure"
            elif "ssl" in error_str or "certificate" in error_str:
                result["error_type"] = "ssl_error"
            else:
                result["error_type"] = "unknown"
        finally:
            # 6. 리소스 정리 (명시적 종료)
            if page:
                try: await page.close()
                except Exception: pass
            if context:
                try: await context.close()
                except Exception: pass
            if browser:
                try: await browser.close()
                except Exception: pass
                
    return result
