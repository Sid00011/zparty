import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

REDIRECT_PARAMS = {"next", "redirect", "return", "returnUrl", "returnTo", "url", "dest",
                   "destination", "redir", "redirect_uri", "goto", "target", "continue", "r"}
PAYLOADS = [
    "https://evil.zparty-test.com",
    "//evil.zparty-test.com",
    "/\\evil.zparty-test.com",
]


class OpenRedirect:
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
                    if param.lower() not in REDIRECT_PARAMS:
                        continue
                    for payload in PAYLOADS:
                        p = dict(params)
                        p[param] = [payload]
                        probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                        try:
                            async with limiter.acquire():
                                async with make_client(follow_redirects=False) as c:
                                    r = await c.get(probe_url)
                            loc = r.headers.get("location", "")
                            if r.status_code in (301, 302, 303, 307, 308) and "evil.zparty-test.com" in loc:
                                findings.append(Finding(
                                    title=f"Open Redirect via '{param}'",
                                    severity="Medium",
                                    description=f"Parameter '{param}' causes an unvalidated redirect to an external domain.",
                                    affected_url=probe_url,
                                    proof=f"GET {probe_url}\nHTTP {r.status_code}\nLocation: {loc}",
                                    remediation="Validate redirect targets against a whitelist of allowed internal paths. Never redirect to user-supplied URLs directly.",
                                    impact=3, likelihood=4, module="OpenRedirect",
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                                ))
                                return
                        except Exception as e:
                            logger.debug(f"Redirect probe {probe_url}: {type(e).__name__}: {e}")

        await asyncio.gather(*[probe(u) for u in endpoints[:150]])
        logger.info(f"OpenRedirect completed — {len(findings)} finding(s)")
        return findings
