"""
core/http_client.py
Shared async HTTP client factory used by every module.

Fixes applied:
  - http2=False — many targets break with h2 negotiation
  - verify=False — pentest tool, cert errors must not block
  - Separate connect/read timeouts so slow servers don't stall probes
  - follow_redirects pulled out of hardcoded kwargs so callers can override it
    (passing follow_redirects=False in **kwargs previously caused
     "multiple values for keyword argument" TypeError that was silently swallowed)
"""
import logging
import httpx
from core.evasion import random_headers, get_proxy

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(connect=15.0, read=30.0, write=10.0, pool=8.0)

# Shorter timeout for attack probes — fail-fast on dead hosts so more probes
# fit inside the per-module 120 s budget.
PROBE_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)

# ── Global auth state ─────────────────────────────────────────────────────────
# Set once by core/pipeline.py after AuthManager is initialised; merged into
# every client created by make_client() so all modules get auth for free.
_AUTH_COOKIES: dict = {}
_AUTH_HEADERS: dict = {}


def set_global_auth(cookies: dict, headers: dict) -> None:
    """Store auth cookies and headers to be merged into every make_client() call."""
    global _AUTH_COOKIES, _AUTH_HEADERS
    _AUTH_COOKIES = dict(cookies)
    _AUTH_HEADERS = dict(headers)


def make_client(
    timeout: httpx.Timeout | None = None,
    follow_redirects: bool = True,
    **kwargs,
) -> httpx.AsyncClient:
    """
    Return a configured AsyncClient ready to use as an async context manager.

    Parameters
    ----------
    timeout          : Use PROBE_TIMEOUT for vuln probes, TIMEOUT (default) for
                       discovery/crawl requests.
    follow_redirects : Set False for open-redirect or SSRF tests where you need
                       to inspect the raw Location header.
    **kwargs         : Passed through to httpx.AsyncClient (e.g. headers={...}).
                       Per-call headers override global auth headers.
    """
    # Randomised browser headers — no tool fingerprint in User-Agent.
    merged_headers = {**random_headers(), **_AUTH_HEADERS, **kwargs.pop("headers", {})}

    # Merge global auth cookies under any per-call cookies.
    caller_cookies: dict = kwargs.pop("cookies", {}) or {}
    merged_cookies = {**_AUTH_COOKIES, **caller_cookies}

    # Proxy support — routes through configured proxy or rotates through list
    proxy = get_proxy()
    proxy_kwargs = {"proxy": proxy} if proxy else {}

    return httpx.AsyncClient(
        timeout=timeout or TIMEOUT,
        http2=False,
        follow_redirects=follow_redirects,
        verify=False,
        headers=merged_headers,
        cookies=merged_cookies if merged_cookies else None,
        limits=httpx.Limits(
            max_keepalive_connections=10,
            max_connections=50,
            keepalive_expiry=10,
        ),
        **proxy_kwargs,
        **kwargs,
    )


async def get(url: str, **kwargs) -> httpx.Response | None:
    """Single GET with full exception handling. Returns None on any failure."""
    try:
        async with make_client() as c:
            return await c.get(url, **kwargs)
    except Exception as e:
        logger.debug(f"GET {url} failed: {type(e).__name__}: {e}")
        return None


async def post(url: str, **kwargs) -> httpx.Response | None:
    try:
        async with make_client() as c:
            return await c.post(url, **kwargs)
    except Exception as e:
        logger.debug(f"POST {url} failed: {type(e).__name__}: {e}")
        return None
