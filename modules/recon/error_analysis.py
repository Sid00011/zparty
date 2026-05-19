import logging
from core.finding import Finding
from core.http_client import make_client

logger = logging.getLogger(__name__)

MALFORMED_PROBES = [
    ("?id='", "single-quote injection"),
    ("?id=1/0", "arithmetic error"),
    ("/../../../etc/passwd", "path traversal"),
]

LEAK_PATTERNS = [
    ("stack trace", "Stack trace in error response"),
    ("at com.", "Java stack trace"),
    ("Fatal error", "PHP fatal error"),
    ("ORA-", "Oracle DB error"),
    ("mysql_", "MySQL legacy error"),
    ("SQLSTATE", "SQLSTATE DB error"),
    ("Microsoft OLE DB", "MSSQL OLE DB error"),
    ("Warning: include", "PHP include warning"),
    ("/var/www/", "Server path disclosure"),
    ("/home/", "Server home path disclosure"),
]


class ErrorAnalysis:
    async def run(self, ctx: dict) -> list[Finding]:
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        findings = []
        logger.info(f"Error analysis: {url}")

        for suffix, label in MALFORMED_PROBES:
            probe_url = url.rstrip("/") + suffix
            try:
                async with limiter.acquire():
                    async with make_client() as client:
                        r = await client.get(probe_url)

                body = r.text.lower()
                for pattern, desc in LEAK_PATTERNS:
                    if pattern.lower() in body:
                        findings.append(Finding(
                            title=f"Verbose Error: {desc}",
                            severity="Medium",
                            description=f"Server leaks {desc} in response to malformed input ({label}).",
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nHTTP {r.status_code}\n{r.text[:500]}",
                            remediation="Disable verbose error messages in production. Configure custom error pages.",
                            impact=2,
                            likelihood=4,
                            module="ErrorAnalysis",
                        ))
                        break
            except Exception as e:
                logger.debug(f"Error probe failed {probe_url}: {e}")

        ctx["recon"]["error_analysis"] = [f.to_dict() for f in findings]
        return findings
