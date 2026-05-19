import asyncio
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.exploit_verifier import XSS_PROOF_PAYLOAD
from core.evasion import XSS_PAYLOADS, maybe_jitter

logger = logging.getLogger(__name__)

# Use evasion module payloads — multiple encodings bypass different WAF rules
REFLECTED_PROBES = XSS_PAYLOADS

DOM_SINKS = [
    "innerHTML", "document.write", "eval(", "location.href",
    "location.hash", "location.search", "outerHTML",
]


class Xss:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        forms = ctx.get("forms", [])
        endpoints = ctx.get("endpoints", [])
        limiter = ctx["limiter"]
        oob = ctx.get("oob")
        sem = asyncio.Semaphore(10)

        verifier = ctx.get("verifier")

        async def probe_ep(ep: str):
            parsed = urlparse(ep)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:3]:
                f = await self._test_reflected(ep, param, parsed, params, limiter, sem, verifier)
                if f:
                    findings.append(f)
                    break

        async def probe_form(form: dict):
            f = await self._test_form_xss(form, limiter, sem, oob)
            if f:
                findings.append(f)

        js_data = ctx.get("recon", {}).get("JsAnalysis", {})
        js_files = js_data.get("js_files", [])[:20]

        async def probe_js(js_url: str):
            f = await self._test_dom_xss(js_url, limiter, sem)
            if f:
                findings.append(f)

        await asyncio.gather(
            *[probe_ep(ep) for ep in endpoints[:100]],
            *[probe_form(f) for f in forms[:25]],
            *[probe_js(js) for js in js_files],
        )
        logger.info(f"Xss completed — {len(findings)} finding(s)")
        return findings

    async def _test_reflected(self, url, param, parsed, params, limiter, sem, verifier=None) -> Finding | None:
        async with sem:
            # ── Reflection pre-check ─────────────────────────────────────────
            # If the endpoint doesn't reflect a benign unique sentinel in its
            # response, it ignores the parameter (SPA catch-all, server-side
            # routing, etc.) — no point probing XSS payloads.
            sentinel = "zp4rty_xss_check"
            pre_params = dict(params)
            pre_params[param] = [sentinel]
            pre_url = parsed._replace(query=urlencode(pre_params, doseq=True)).geturl()
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        pre_r = await client.get(pre_url)
                if sentinel not in pre_r.text:
                    return None  # Parameter is not reflected — skip
            except Exception:
                return None

            for payload, label in REFLECTED_PROBES:
                probe_params = dict(params)
                probe_params[param] = [payload]
                probe_url = parsed._replace(query=urlencode(probe_params, doseq=True)).geturl()
                try:
                    await maybe_jitter()
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            r = await client.get(probe_url)

                    if payload in r.text and r.headers.get("content-type", "").startswith("text/html"):
                        finding = Finding(
                            title=f"Reflected XSS in '{param}' ({label})",
                            severity="High",
                            description=f"Parameter '{param}' reflects user input unescaped in the HTML response.",
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nHTTP {r.status_code}\nPayload found in response: {payload[:80]}",
                            remediation="HTML-encode all user-supplied data before rendering in the DOM. Implement a strict Content-Security-Policy.",
                            impact=4, likelihood=4,
                            module="Xss",
                            references=["https://owasp.org/www-community/attacks/xss/"],
                        )
                        # ── Playwright proof-of-exploit verification ──────────
                        if verifier and verifier.available:
                            proof_params = dict(params)
                            proof_params[param] = [XSS_PROOF_PAYLOAD]
                            proof_url_visual = parsed._replace(
                                query=urlencode(proof_params, doseq=True)
                            ).geturl()
                            confirmed, screenshot = await verifier.verify_xss(proof_url_visual)
                            if confirmed:
                                finding.verified    = True
                                finding.screenshot  = screenshot
                                finding.title       = f"Reflected XSS in '{param}' ({label}) [VERIFIED]"
                                finding.severity    = "High"
                                finding.proof      += f"\n\nPlaywright verified: XSS banner rendered in headless Chromium.\nProof URL: {proof_url_visual}"
                        return finding
                except Exception as e:
                    logger.debug(f"XSS probe error {probe_url}: {type(e).__name__}: {e}")
        return None

    async def _test_form_xss(self, form: dict, limiter, sem, oob=None) -> Finding | None:
        action = form.get("action", "")
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        if not action or not inputs:
            return None

        async with sem:
            # ── Reflected XSS probe ───────────────────────────────────────────
            payload = '<script>alert("zparty")</script>'
            data = {i: payload if i == inputs[0] else "test" for i in inputs}
            # Inject CSRF token if present
            csrf_field = form.get("csrf_field")
            csrf_token = form.get("csrf_token")
            if csrf_field and csrf_token:
                data[csrf_field] = csrf_token

            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        if method == "POST":
                            r = await client.post(action, data=data)
                        else:
                            r = await client.get(action, params=data)

                if payload in r.text:
                    return Finding(
                        title=f"XSS in Form Field '{inputs[0]}' at {action}",
                        severity="High",
                        description="Form field reflects input unescaped, enabling XSS.",
                        affected_url=action,
                        proof=f"{method} {action}\ndata={data}\nHTTP {r.status_code}\nPayload in response: {payload}",
                        remediation="Encode output and implement a Content-Security-Policy.",
                        impact=4, likelihood=4,
                        module="Xss",
                    )
            except Exception as e:
                logger.debug(f"XSS form probe {action}: {type(e).__name__}: {e}")

            # ── Blind XSS via OOB (stored XSS in fields like comments, name) ──
            if oob and oob.active:
                oob_token, oob_payload = oob.make_xss_payload()
                blind_data = {i: oob_payload if i == inputs[0] else "zparty_test" for i in inputs}
                if csrf_field and csrf_token:
                    blind_data[csrf_field] = csrf_token
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            if method == "POST":
                                await client.post(action, data=blind_data)
                            else:
                                await client.get(action, params=blind_data)
                    if await oob.wait_for(oob_token, timeout=5.0):
                        return Finding(
                            title=f"Blind/Stored XSS in Form Field '{inputs[0]}' (OOB Confirmed)",
                            severity="High",
                            description=(
                                f"Blind XSS confirmed via OOB callback. Payload submitted to "
                                f"'{inputs[0]}' at {action} triggered a script load from our "
                                f"OOB server, indicating stored/blind XSS."
                            ),
                            affected_url=action,
                            proof=f"{method} {action}\nBlind XSS payload submitted\nOOB callback received → confirmed",
                            remediation="Encode all user-supplied output server-side. Implement strict Content-Security-Policy.",
                            impact=4, likelihood=4, module="Xss",
                        )
                except Exception as e:
                    logger.debug(f"Blind XSS OOB probe {action}: {e}")
        return None

    async def _test_dom_xss(self, js_url: str, limiter, sem) -> Finding | None:
        async with sem:
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        r = await client.get(js_url)
                body = r.text
                for sink in DOM_SINKS:
                    if sink in body:
                        pattern = rf'{re.escape(sink)}.*(location\.(hash|search|href)|document\.URL|document\.referrer)'
                        if re.search(pattern, body):
                            return Finding(
                                title=f"Potential DOM XSS: '{sink}' with location source",
                                severity="Medium",
                                description=f"JS file uses dangerous sink '{sink}' with a location-based source — possible DOM XSS.",
                                affected_url=js_url,
                                proof=f"{js_url}\nSink: {sink}\nManual verification required.",
                                remediation="Use textContent instead of innerHTML. Avoid eval(). Sanitize location.hash/search before use.",
                                impact=4, likelihood=2,
                                module="Xss",
                            )
            except Exception as e:
                logger.debug(f"DOM XSS probe {js_url}: {type(e).__name__}: {e}")
        return None
