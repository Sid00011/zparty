"""
modules/scan/crawler.py — Web crawler with Playwright JS rendering

Two-pass strategy:
  Pass 1 (Playwright)  — renders each page in headless Chromium, intercepts XHR/fetch
                          network requests, extracts dynamically injected forms and links.
                          Catches React/Angular/Vue content that plain HTTP misses entirely.
  Pass 2 (httpx)       — fast BFS fallback when Playwright is unavailable or for pages
                          already collected in pass 1.

The union of both passes feeds ctx["forms"] and ctx["endpoints"].
"""
import asyncio
import logging
import re
from collections import deque
from urllib.parse import urljoin, urlparse

from core.http_client import make_client

logger = logging.getLogger(__name__)

FORM_TAG_RE = re.compile(r'<form([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
ACTION_RE   = re.compile(r'action=["\']?([^"\'>\s]*)["\']?', re.IGNORECASE)
METHOD_RE   = re.compile(r'method=["\']?(\w+)["\']?', re.IGNORECASE)
INPUT_RE    = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
TYPE_RE     = re.compile(r'<input[^>]*type=["\']([^"\']+)["\']', re.IGNORECASE)
SELECT_RE   = re.compile(r'<(?:select|textarea)[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_RE     = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
API_RE      = re.compile(r'["\']/(api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE)
CSRF_RE     = re.compile(
    r'<input[^>]*name=["\']([^"\']*csrf[^"\']*|_token|__RequestVerificationToken)["\'][^>]*'
    r'value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
CSRF_META_RE = re.compile(
    r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _extract_forms(body: str, base_url: str) -> list[dict]:
    """Parse HTML and return a list of form dicts."""
    forms = []
    # Extract CSRF token from meta or hidden input (page-level)
    csrf_meta = CSRF_META_RE.search(body)
    page_csrf = csrf_meta.group(1) if csrf_meta else None

    for fm in FORM_TAG_RE.finditer(body):
        attrs_str = fm.group(1)
        body_str  = fm.group(2)
        action_m  = ACTION_RE.search(attrs_str)
        method_m  = METHOD_RE.search(attrs_str)
        raw_act   = action_m.group(1) if action_m else ""
        action    = urljoin(base_url, raw_act) if raw_act else base_url
        method    = method_m.group(1).upper() if method_m else "GET"

        # Collect all named inputs with their types and values
        fields = []
        for m in re.finditer(
            r'<(input|select|textarea)[^>]*name=["\']([^"\']+)["\']([^>]*)>',
            body_str, re.IGNORECASE
        ):
            tag = m.group(1).lower()
            name = m.group(2)
            rest = m.group(3)
            typ_m = re.search(r'type=["\']([^"\']+)["\']', rest, re.IGNORECASE)
            val_m = re.search(r'value=["\']([^"\']*)["\']', rest, re.IGNORECASE)
            typ = typ_m.group(1).lower() if typ_m else ("select" if tag == "select" else "text")
            val = val_m.group(1) if val_m else ""
            fields.append({"name": name, "type": typ, "value": val})

        # Detect CSRF field inside form
        csrf_m = CSRF_RE.search(body_str)
        csrf_token = csrf_m.group(2) if csrf_m else page_csrf

        forms.append({
            "action":     action,
            "method":     method,
            "fields":     fields,
            "inputs":     [f["name"] for f in fields],  # legacy compat
            "found_at":   base_url,
            "csrf_token": csrf_token,
            "csrf_field": csrf_m.group(1) if csrf_m else None,
        })
    return forms


async def _crawl_httpx(url: str, cfg: dict, limiter) -> dict:
    """BFS httpx crawler — fast, no JS rendering."""
    base = urlparse(url)
    max_depth = cfg.get("scope", {}).get("crawl_depth", 3)
    attempted: set[str] = set()
    fetched: set[str] = set()
    forms: list[dict] = []
    api_endpoints: list[str] = []
    param_endpoints: list[str] = []
    queue = deque([(url, 0)])

    async with make_client() as client:
        while queue:
            current_url, depth = queue.popleft()
            norm = current_url.split("#")[0]
            if norm in attempted or depth > max_depth:
                continue
            attempted.add(norm)
            try:
                async with limiter.acquire():
                    r = await client.get(current_url)
                fetched.add(norm)
                ct = r.headers.get("content-type", "")
                if "text" not in ct and "html" not in ct and "javascript" not in ct:
                    continue
                body = r.text

                # Forms
                for form in _extract_forms(body, current_url):
                    forms.append(form)

                # API patterns in JS/HTML
                for ep in API_RE.findall(body):
                    api_endpoints.append(urljoin(url, "/" + ep))

                # Follow links
                if depth < max_depth:
                    for href in LINK_RE.findall(body):
                        href = href.strip()
                        if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                            continue
                        full = urljoin(current_url, href).split("#")[0]
                        p = urlparse(full)
                        if (p.hostname == base.hostname
                                and p.scheme in ("http", "https")
                                and full not in attempted):
                            queue.append((full, depth + 1))
                            if p.query:
                                param_endpoints.append(full)
            except Exception as e:
                logger.debug(f"Crawl error {current_url}: {type(e).__name__}: {e}")

    return {
        "pages":           list(fetched),
        "forms":           forms,
        "api_endpoints":   list(set(api_endpoints)),
        "param_endpoints": list(set(param_endpoints)),
    }


async def _crawl_playwright(url: str, cfg: dict) -> dict:
    """
    Playwright headless Chromium crawler.
    Renders JS, intercepts XHR/fetch, extracts dynamic content.
    Returns same shape dict as _crawl_httpx.
    """
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout

    base = urlparse(url)
    max_depth = cfg.get("scope", {}).get("crawl_depth", 2)  # shallower — PW is slower
    visited: set[str] = set()
    forms: list[dict] = []
    api_endpoints: list[str] = []
    param_endpoints: list[str] = []
    pages_fetched: list[str] = []
    network_urls: list[str] = []

    # We only allow up to 30 pages with Playwright to stay in budget
    MAX_PW_PAGES = 30

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--ignore-certificate-errors",
            ],
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ),
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        # Inject auth cookies if set
        try:
            from core.http_client import _AUTH_COOKIES, _AUTH_HEADERS
            if _AUTH_COOKIES:
                await context.add_cookies([
                    {"name": k, "value": v, "url": url}
                    for k, v in _AUTH_COOKIES.items()
                ])
        except Exception:
            pass

        queue = deque([(url, 0)])

        while queue and len(pages_fetched) < MAX_PW_PAGES:
            current_url, depth = queue.popleft()
            norm = current_url.split("#")[0]
            if norm in visited or depth > max_depth:
                continue
            visited.add(norm)

            page = await context.new_page()
            intercepted: list[str] = []

            # Intercept all network requests to find API calls
            async def on_request(req):
                rurl = req.url
                if any(k in rurl for k in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/")):
                    intercepted.append(rurl)
                    api_endpoints.append(rurl)
                p = urlparse(rurl)
                if p.hostname == base.hostname and p.query:
                    param_endpoints.append(rurl.split("#")[0])

            page.on("request", on_request)

            try:
                resp = await page.goto(
                    current_url,
                    wait_until="networkidle",
                    timeout=15_000,
                )
                if resp is None:
                    await page.close()
                    continue

                pages_fetched.append(norm)
                network_urls.extend(intercepted)

                # Wait a bit for dynamic content
                await page.wait_for_timeout(1500)

                # ── Extract forms from rendered DOM ───────────────────────────
                raw_forms = await page.evaluate("""() => {
                    const forms = [];
                    for (const form of document.querySelectorAll('form')) {
                        const fields = [];
                        for (const el of form.querySelectorAll('input,select,textarea')) {
                            if (el.name) {
                                fields.push({
                                    name: el.name,
                                    type: el.type || el.tagName.toLowerCase(),
                                    value: el.value || ''
                                });
                            }
                        }
                        forms.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'GET').toUpperCase(),
                            fields: fields
                        });
                    }
                    return forms;
                }""")

                for rf in raw_forms:
                    rf["inputs"] = [f["name"] for f in rf.get("fields", [])]
                    rf["found_at"] = current_url
                    rf["csrf_token"] = None
                    rf["csrf_field"] = None
                    # Extract CSRF from fields
                    for fld in rf.get("fields", []):
                        if any(k in fld["name"].lower() for k in ("csrf", "_token", "verif")):
                            rf["csrf_field"] = fld["name"]
                            rf["csrf_token"] = fld["value"]
                    forms.append(rf)

                # ── Extract links from rendered DOM ───────────────────────────
                if depth < max_depth:
                    links = await page.evaluate("""() =>
                        Array.from(document.querySelectorAll('a[href]'))
                             .map(a => a.href)
                             .filter(h => h.startsWith('http'))
                    """)
                    for link in links:
                        ln = link.split("#")[0]
                        p = urlparse(ln)
                        if p.hostname == base.hostname and ln not in visited:
                            queue.append((ln, depth + 1))

                # ── Look for API routes in JS bundles ─────────────────────────
                scripts = await page.evaluate("""() =>
                    Array.from(document.querySelectorAll('script[src]'))
                         .map(s => s.src)
                """)
                for src in scripts[:10]:
                    if base.hostname in src:
                        api_endpoints.append(src)

            except PWTimeout:
                logger.debug(f"Playwright timeout: {current_url}")
            except Exception as e:
                logger.debug(f"Playwright error {current_url}: {type(e).__name__}: {e}")
            finally:
                await page.close()

        await browser.close()

    return {
        "pages":           pages_fetched,
        "forms":           forms,
        "api_endpoints":   list(set(api_endpoints)),
        "param_endpoints": list(set(param_endpoints)),
        "network_urls":    network_urls,
    }


class Crawler:
    async def run(self, ctx: dict) -> dict:
        url = ctx["target_url"]
        cfg = ctx["config"]
        limiter = ctx["limiter"]

        logger.info(f"Crawler starting: {url}")

        # ── Pass 1: Playwright (JS-rendered) ──────────────────────────────────
        pw_result: dict = {}
        pw_available = False
        try:
            import playwright  # noqa: F401
            pw_available = True
        except ImportError:
            logger.info("Playwright not installed — using httpx-only crawl (run: playwright install chromium)")

        if pw_available:
            try:
                pw_result = await asyncio.wait_for(
                    _crawl_playwright(url, cfg),
                    timeout=90,  # Playwright gets 90 s of the 120 s module budget
                )
                logger.info(
                    f"Playwright crawl: {len(pw_result.get('pages', []))} pages, "
                    f"{len(pw_result.get('forms', []))} forms, "
                    f"{len(pw_result.get('api_endpoints', []))} API endpoints"
                )
            except asyncio.TimeoutError:
                logger.warning("Playwright crawl timed out — falling back to httpx")
            except Exception as e:
                logger.warning(f"Playwright crawl failed ({type(e).__name__}: {e}) — falling back to httpx")

        # ── Pass 2: httpx BFS ─────────────────────────────────────────────────
        hx_result = await asyncio.wait_for(
            _crawl_httpx(url, cfg, limiter),
            timeout=60,
        )
        logger.info(
            f"httpx crawl: {len(hx_result.get('pages', []))} pages, "
            f"{len(hx_result.get('forms', []))} forms"
        )

        # ── Merge results ─────────────────────────────────────────────────────
        seen_actions: set[str] = set()
        all_forms: list[dict] = []
        for f in pw_result.get("forms", []) + hx_result.get("forms", []):
            key = f"{f['action']}|{f['method']}"
            if key not in seen_actions:
                seen_actions.add(key)
                all_forms.append(f)

        all_pages = list(set(
            pw_result.get("pages", []) + hx_result.get("pages", [])
        ))
        all_api = list(set(
            pw_result.get("api_endpoints", []) + hx_result.get("api_endpoints", [])
        ))
        all_params = list(set(
            pw_result.get("param_endpoints", []) + hx_result.get("param_endpoints", [])
        ))
        network_urls = list(set(pw_result.get("network_urls", [])))

        result = {
            "pages":           all_pages,
            "forms":           all_forms,
            "api_endpoints":   all_api,
            "param_endpoints": all_params,
            "network_urls":    network_urls,
            "playwright_used": pw_available and bool(pw_result),
        }

        ctx["forms"].extend(all_forms)
        ctx["endpoints"].extend(all_api)
        ctx["endpoints"].extend(all_params)
        ctx["endpoints"].extend(network_urls)

        logger.info(
            f"Crawler complete — {len(all_pages)} pages, {len(all_forms)} forms, "
            f"{len(all_api + all_params)} endpoints "
            f"({'Playwright+httpx' if result['playwright_used'] else 'httpx only'})"
        )
        return result
