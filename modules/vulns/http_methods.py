import asyncio
import logging
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

# TRACE is handled separately via the XST probe below — exclude from generic loop
DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT"}


class HttpMethods:
    async def run(self, ctx: dict) -> list[Finding]:
        findings = []
        urls = list(set([ctx["target_url"]] + ctx.get("endpoints", [])))[:40]
        limiter = ctx["limiter"]

        async def probe(url: str):
            allowed = []
            allow_hdr = ""
            try:
                async with limiter.acquire():
                    async with make_client(follow_redirects=False) as c:
                        r = await c.options(url)
                allow_hdr = r.headers.get("allow", "") + r.headers.get("access-control-allow-methods", "")
                if allow_hdr:
                    allowed = [m.strip().upper() for m in allow_hdr.replace(",", " ").split()]
            except Exception:
                pass

            for method in DANGEROUS_METHODS:
                if method not in allowed:
                    continue
                try:
                    async with limiter.acquire():
                        async with make_client(follow_redirects=False) as c:
                            r = await c.request(method, url)
                    # 405/501/403 = explicitly rejected; 5xx = server error (not "enabled")
                    if r.status_code not in (405, 501, 403) and r.status_code < 500:
                        findings.append(Finding(
                            title=f"Dangerous HTTP Method Enabled: {method}",
                            severity="Medium" if method in ("DELETE", "PUT") else "Low",
                            description=f"HTTP {method} is accepted by the server (HTTP {r.status_code}). This may allow unintended data modification or information leakage.",
                            affected_url=url,
                            proof=f"{method} {url}\nHTTP {r.status_code}\nAllow header: {allow_hdr if allow_hdr else 'not set'}",
                            remediation=f"Disable {method} in your web server config unless explicitly required. Restrict via firewall or WAF rules.",
                            impact=3, likelihood=3, module="HttpMethods",
                        ))
                except Exception:
                    pass

            try:
                async with limiter.acquire():
                    async with make_client(follow_redirects=False) as c:
                        r = await c.request("TRACE", url, headers={"X-Custom-Header": "zparty-xst"})
                if "zparty-xst" in r.text and r.status_code == 200:
                    findings.append(Finding(
                        title="HTTP TRACE Enabled (XST Risk)",
                        severity="Low",
                        description="TRACE method is enabled and reflects request headers — Cross-Site Tracing (XST) may be possible.",
                        affected_url=url,
                        proof=f"TRACE {url}\nHTTP {r.status_code}\nResponse echoes: X-Custom-Header: zparty-xst",
                        remediation="Disable TRACE in your web server configuration (TraceEnable Off in Apache, trace_handler off in nginx).",
                        impact=2, likelihood=2, module="HttpMethods",
                    ))
            except Exception:
                pass

        await asyncio.gather(*[probe(u) for u in urls])
        logger.info(f"HttpMethods completed — {len(findings)} finding(s)")
        return findings
