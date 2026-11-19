import asyncio
import sys
import threading
import concurrent.futures
from typing import Optional, List
from playwright.async_api import async_playwright, Playwright, Browser, TimeoutError as PlaywrightTimeoutError
import tldextract

from app.core.config import settings

MAX_CONCURRENT_CONTEXTS = getattr(settings, "PLAYWRIGHT_MAX_CONCURRENT_CONTEXTS", 3)
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _extract_base_domain(url: str) -> str:
    extracted = _tld_extractor(url)
    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain


async def _inspect_url_on_browser(
    browser: Browser,
    url: str,
    semaphore: asyncio.Semaphore,
    capture_screenshot: bool = False,
) -> dict:
    """단일 격리 BrowserContext를 생성하여 URL 동적 DOM/네트워크/시각적 위협을 분석합니다."""
    result = {
        "original_url": url,
        "final_url": url,
        "page_title": "",
        "has_password_field": False,
        "has_form": False,
        "has_hidden_form": False,
        "is_redirected": False,
        "error": None,
        "error_type": "unknown",
        "requested_urls": [],
        "external_requests": [],
        "redirect_chain": [],
        "external_links": [],
        "suspicious_keywords": [],
        "favicon_url": None,
        "meta_description": None,
        "screenshot_captured": False,
        "_screenshot_bytes": None,  # 내부 전달용 (JSON 직렬화 전 pop)
    }

    original_domain = _extract_base_domain(url)
    context = None
    page = None

    async with semaphore:
        try:
            # 브라우저 실제 버전에 기반한 최신 User-Agent 생성 (HeadlessChrome 토큰 제거로 클로킹 우회)
            browser_ver = browser.version or "138.0.0.0"
            modern_ua = (
                f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{browser_ver} Safari/537.36"
            )

            # 보안 격리 설정: 시크릿 컨텍스트, 다운로드 금지, 모든 브라우저 권한 차단
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=modern_ua,
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True,
                accept_downloads=False,
                permissions=[],
            )

            # 리소스 차단 정책:
            # - 일반 DOM 검사: 이미지/미디어/폰트/CSS 차단하여 초고속 분석
            # - 시각적 멀티모달(스크린샷) 검사: 미디어만 차단하고 이미지/CSS 허용하여 실제 렌더링 확보
            blocked_types = ["media"] if capture_screenshot else ["image", "media", "font", "stylesheet"]

            async def route_handler(route):
                if route.request.resource_type in blocked_types:
                    await route.abort()
                else:
                    await route.continue_()

            await context.route("**/*", route_handler)
            page = await context.new_page()

            # 악성 alert/confirm/prompt 자동 무시
            page.on("dialog", lambda dialog: asyncio.ensure_future(dialog.dismiss()))

            # 요청 추적
            def on_request(request):
                if request.resource_type in ["image", "media", "font", "stylesheet"]:
                    return
                req_url = request.url
                result["requested_urls"].append(req_url)
                req_domain = _extract_base_domain(req_url)
                if req_domain and original_domain and req_domain != original_domain:
                    result["external_requests"].append(req_url)

            page.on("request", on_request)

            # 리다이렉트 체인 추적
            def on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    result["redirect_chain"].append({
                        "url": response.url,
                        "status": response.status,
                    })

            page.on("response", on_response)

            # 최대 15초 타임아웃
            response = await page.goto(url, timeout=15000, wait_until="domcontentloaded")

            if response:
                result["final_url"] = page.url
                result["is_redirected"] = (url != page.url)
                result["page_title"] = await page.title()

                # 렌더링 후 동적으로 생성된 폼 및 비밀번호 필드 존재 여부 확인
                result["has_password_field"] = await page.locator("input[type='password']").count() > 0
                result["has_form"] = await page.locator("form").count() > 0
                result["has_hidden_form"] = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('form')).some(f => {
                        const style = window.getComputedStyle(f);
                        return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || f.hasAttribute('hidden');
                    });
                }""")

                # 외부 링크 수집
                try:
                    links = await page.locator("a").evaluate_all("els => els.map(el => el.href)")
                    ext_links = []
                    for link in links:
                        if not link:
                            continue
                        link_domain = _extract_base_domain(link)
                        if link_domain and link_domain != original_domain:
                            ext_links.append(link)
                    result["external_links"] = list(set(ext_links))
                except Exception:
                    result["external_links"] = []

                # 의심 키워드 탐색
                try:
                    content = await page.content()
                    content_lower = content.lower()
                    target_keywords = [
                        "verify your account", "enter your password", "suspended",
                        "계정 확인", "비밀번호 입력", "본인인증",
                    ]
                    result["suspicious_keywords"] = [kw for kw in target_keywords if kw in content_lower]
                except Exception:
                    pass

                # favicon_url
                try:
                    favicon = await page.evaluate('document.querySelector(\'link[rel~="icon"]\')?.href')
                    if favicon:
                        result["favicon_url"] = favicon
                except Exception:
                    pass

                # meta_description
                try:
                    meta_desc = await page.evaluate('document.querySelector(\'meta[name="description"]\')?.content')
                    if meta_desc:
                        result["meta_description"] = meta_desc
                except Exception:
                    pass

                # 시각적 브랜드 사칭 탐지용 뷰포트 스크린샷 캡처 (Gemini Vision 멀티모달용)
                if capture_screenshot:
                    try:
                        # 짧은 안정화 대기 (동적 SPA/이미지 로딩 여유)
                        await page.wait_for_timeout(400)
                        screenshot_bytes = await page.screenshot(type="png", full_page=False, timeout=5000)
                        if screenshot_bytes:
                            result["_screenshot_bytes"] = screenshot_bytes
                            result["screenshot_captured"] = True
                    except Exception as ss_err:
                        print(f"[BrowserPool] 스크린샷 캡처 실패(무시): {ss_err}")

        except PlaywrightTimeoutError:
            result["error"] = "Timeout exceeded (15s)"
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
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            if context:
                try:
                    await context.close()
                except Exception:
                    pass

    return result


class BrowserPoolManager:
    """
    단일 Chromium 인스턴스를 전용 백그라운드 ProactorEventLoop 스레드에서 상시 유지하고,
    요청마다 격리된 BrowserContext만 생성·폐기하는 경량 브라우저 풀 매니저.

    - Windows FastAPI/Uvicorn 이벤트 루프 충돌 원천 차단
    - New Headless (channel='chromium') 우선 사용, 미설치 시 chromium-headless-shell 자동 Fallback
    """

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ready_event = threading.Event()
        self._lock = threading.Lock()
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._browser_lock: Optional[asyncio.Lock] = None
        self._engine_mode: str = "uninitialized"

    def _start_worker_thread(self):
        with self._lock:
            if self._thread and self._thread.is_alive() and self._loop:
                return
            self._ready_event.clear()

            def _thread_main():
                if sys.platform == "win32":
                    loop = asyncio.WindowsProactorEventLoopPolicy().new_event_loop()
                else:
                    loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONTEXTS)
                self._browser_lock = asyncio.Lock()
                self._ready_event.set()
                try:
                    loop.run_forever()
                finally:
                    loop.close()

            self._thread = threading.Thread(target=_thread_main, name="PlaywrightBrowserPool", daemon=True)
            self._thread.start()

        self._ready_event.wait(timeout=10)

    async def _ensure_browser(self) -> Browser:
        if self._browser and self._browser.is_connected():
            return self._browser

        async with self._browser_lock:
            if self._browser and self._browser.is_connected():
                return self._browser

            if self._playwright is None:
                self._playwright = await asyncio.wait_for(async_playwright().start(), timeout=15)

            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ]

            use_new_headless = getattr(settings, "PLAYWRIGHT_USE_NEW_HEADLESS", True)
            if use_new_headless:
                try:
                    self._browser = await self._playwright.chromium.launch(
                        channel="chromium",
                        headless=True,
                        args=launch_args,
                        timeout=15000,
                    )
                    self._engine_mode = "new-headless (channel=chromium)"
                    print(f"[BrowserPool] Chromium 시작 완료: {self._engine_mode} v{self._browser.version}")
                    return self._browser
                except Exception as new_hl_err:
                    print(f"[BrowserPool] New Headless 기동 실패, 기본 headless-shell로 Fallback합니다: {new_hl_err}")

            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=launch_args,
                timeout=15000,
            )
            self._engine_mode = "chromium-headless-shell"
            print(f"[BrowserPool] Chromium 시작 완료: {self._engine_mode} v{self._browser.version}")
            return self._browser

    async def _inspect_single_internal(self, url: str, capture_screenshot: bool = False) -> dict:
        browser = await self._ensure_browser()
        return await _inspect_url_on_browser(
            browser=browser,
            url=url,
            semaphore=self._semaphore,
            capture_screenshot=capture_screenshot,
        )

    async def _inspect_many_internal(self, urls: List[str], capture_screenshot: bool = False) -> List[dict]:
        browser = await self._ensure_browser()
        tasks = [
            _inspect_url_on_browser(
                browser=browser,
                url=u,
                semaphore=self._semaphore,
                capture_screenshot=capture_screenshot,
            )
            for u in urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

    async def _shutdown_internal(self):
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    async def inspect_url(self, url: str, capture_screenshot: bool = False) -> dict:
        self._start_worker_thread()
        future = asyncio.run_coroutine_threadsafe(
            self._inspect_single_internal(url, capture_screenshot=capture_screenshot),
            self._loop,
        )
        return await asyncio.wrap_future(future)

    async def inspect_urls(self, urls: List[str], capture_screenshot: bool = False) -> List[dict]:
        if not urls:
            return []
        self._start_worker_thread()
        future = asyncio.run_coroutine_threadsafe(
            self._inspect_many_internal(urls, capture_screenshot=capture_screenshot),
            self._loop,
        )
        return await asyncio.wrap_future(future)

    async def shutdown(self):
        if not self._loop or not self._thread or not self._thread.is_alive():
            return
        try:
            future = asyncio.run_coroutine_threadsafe(self._shutdown_internal(), self._loop)
            await asyncio.wrap_future(future)
        except Exception as e:
            print(f"[BrowserPool] 종료 중 예외(무시): {e}")
        finally:
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
            self._thread.join(timeout=3)
            self._loop = None
            self._thread = None


browser_pool = BrowserPoolManager()


async def inspect_url_pooled(url: str, capture_screenshot: bool = False) -> dict:
    """풀링된 Chromium 인스턴스를 사용해 단일 URL을 동적 분석합니다."""
    return await browser_pool.inspect_url(url, capture_screenshot=capture_screenshot)


async def inspect_urls_pooled(urls: List[str], capture_screenshot: bool = False) -> List[dict]:
    """풀링된 Chromium 인스턴스를 사용해 여러 URL을 병렬 동적 분석합니다."""
    return await browser_pool.inspect_urls(urls, capture_screenshot=capture_screenshot)


async def shutdown_browser_pool():
    """서버 종료 시 Playwright 브라우저 풀을 안전하게 종료합니다."""
    await browser_pool.shutdown()


async def inspect_url_with_playwright(playwright: Playwright, url: str) -> dict:
    """하위 호환성을 위한 레거시 진입점 (내부적으로 풀링 엔진 사용)."""
    return await inspect_url_pooled(url, capture_screenshot=False)
