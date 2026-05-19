import asyncio
import base64
import logging
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

MAGIC_BYTES = {
    "rO0":      "Java serialized object",
    "O:":       "PHP serialized object",
    "gASV":     "Python pickle",
    "AAEAAAD":  ".NET BinaryFormatter",
}

PROTO_POLLUTION_PAYLOADS = [
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"admin":true}}}',
]


class Deserialization:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        forms = ctx.get("forms", [])
        limiter = ctx["limiter"]
        sem = asyncio.Semaphore(10)

        async def probe_ep(ep: str):
            f = await self._check_endpoint(ep, limiter, sem)
            if f:
                findings.append(f)

        async def probe_form(form: dict):
            if form.get("method", "").upper() == "POST":
                f = await self._test_proto_pollution(form, limiter, sem)
                if f:
                    findings.append(f)

        await asyncio.gather(
            *[probe_ep(ep) for ep in endpoints[:100]],
            *[probe_form(f) for f in forms[:20]],
        )
        logger.info(f"Deserialization completed — {len(findings)} finding(s)")
        return findings

    async def _check_endpoint(self, url: str, limiter, sem) -> Finding | None:
        async with sem:
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
                        r = await client.get(url)

                set_cookie = r.headers.get("set-cookie", "")
                all_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else [set_cookie]

                for cookie in all_cookies:
                    for part in cookie.split(";"):
                        if "=" in part:
                            _, val = part.split("=", 1)
                            val = val.strip()
                            try:
                                decoded = base64.b64decode(val + "==").decode(errors="ignore")
                                for magic, label in MAGIC_BYTES.items():
                                    if decoded.startswith(magic) or val.startswith(magic):
                                        return Finding(
                                            title=f"Possible Insecure Deserialization ({label}) in Cookie",
                                            severity="High",
                                            description=f"Cookie value appears to be a {label}. Insecure deserialization can lead to RCE.",
                                            affected_url=url,
                                            proof=f"Set-Cookie: {cookie[:200]}\nDecoded prefix: {decoded[:40]}",
                                            remediation="Use signed, non-serialized session tokens. If deserialization is required, use safe deserialization with allowlists.",
                                            impact=5, likelihood=3,
                                            module="Deserialization",
                                            references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                                        )
                            except Exception:
                                pass

            except Exception as e:
                logger.debug(f"Deserialization check error {url}: {type(e).__name__}: {e}")
        return None

    async def _test_proto_pollution(self, form: dict, limiter, sem) -> Finding | None:
        action = form.get("action", "")
        if not action:
            return None
        async with sem:
            for payload in PROTO_POLLUTION_PAYLOADS:
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            r = await client.post(
                                action,
                                content=payload.encode(),
                                headers={"Content-Type": "application/json"},
                            )

                    body_low = r.text.lower()
                    # Require admin-elevation indicator in JSON context, not just nav links
                    proto_hit = (
                        r.status_code == 200
                        and ('"admin":true' in body_low
                             or '"isadmin":true' in body_low
                             or '"role":"admin"' in body_low
                             or '"elevated":true' in body_low)
                    )
                    if proto_hit:
                        return Finding(
                            title="JavaScript Prototype Pollution",
                            severity="High",
                            description="JSON body with __proto__ key was accepted and may have polluted the global prototype.",
                            affected_url=action,
                            proof=f"POST {action}\n{payload}\nHTTP {r.status_code}\n{r.text[:300]}",
                            remediation="Sanitize JSON keys server-side. Use Object.create(null) for maps. Use a schema validation library.",
                            impact=4, likelihood=3,
                            module="Deserialization",
                            references=["https://portswigger.net/web-security/prototype-pollution"],
                        )
                except Exception as e:
                    logger.debug(f"Proto pollution probe {action}: {type(e).__name__}: {e}")
        return None
