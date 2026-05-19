"""
modules/vulns/ssti.py — Server-Side Template Injection

False-positive strategy:
  1. Use distinctive expected values that are very unlikely to appear naturally
     ({{13*37}} = 481, not 49 which appears on prices/counts everywhere)
  2. Baseline comparison: fetch the page with a benign value first;
     if the expected string already appears, skip (not an injection signal)
  3. Only report when expected is present in injected response but absent in baseline
"""
import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

# Use unusual expected values — 481, 7777777 are rare on real pages
SSTI_PROBES = [
    ("{{13*37}}",    "481",     "Jinja2/Twig"),
    ("${13*37}",     "481",     "FreeMarker/Thymeleaf"),
    ("#{13*37}",     "481",     "Ruby ERB"),
    ("*{13*37}",     "481",     "Spring SpEL"),
    ("<%= 13*37 %>", "481",     "ERB/JSP"),
    ("{{7*'7'}}",    "7777777", "Jinja2 (string multiply)"),
]


class Ssti:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        forms = ctx.get("forms", [])
        limiter = ctx["limiter"]
        sem = asyncio.Semaphore(10)

        verifier = ctx.get("verifier")

        async def probe_param(url: str):
            parsed = urlparse(url)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            async with sem:
                for param in list(params.keys())[:3]:
                    # Baseline: fetch with benign value to see if expected appears naturally
                    # Also serves as a reflection check — if "hello_ssti_check" isn't reflected
                    # at all, the endpoint ignores this param (SPA) and we skip.
                    sentinel = "hello_ssti_check"
                    baseline_params = dict(params)
                    baseline_params[param] = [sentinel]
                    baseline_url = parsed._replace(query=urlencode(baseline_params, doseq=True)).geturl()
                    try:
                        async with limiter.acquire():
                            async with make_client(timeout=PROBE_TIMEOUT) as c:
                                baseline_r = await c.get(baseline_url)
                        baseline_text = baseline_r.text
                    except Exception:
                        baseline_text = ""

                    # Skip non-reflecting parameters (SPA catch-alls, ignored params)
                    if sentinel not in baseline_text:
                        continue

                    for payload, expected, engine in SSTI_PROBES:
                        # Skip if expected already appears naturally in the baseline
                        if expected in baseline_text:
                            continue
                        p = dict(params)
                        p[param] = [payload]
                        probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                        try:
                            async with limiter.acquire():
                                async with make_client(timeout=PROBE_TIMEOUT) as c:
                                    r = await c.get(probe_url)
                            # Payload was executed if expected is in response but NOT literally reflected
                            if expected in r.text and payload not in r.text:
                                ssti_finding = Finding(
                                    title=f"SSTI: Server-Side Template Injection ({engine}) in '{param}'",
                                    severity="Critical",
                                    description=(
                                        f"Parameter '{param}' evaluates template expressions. "
                                        f"Payload '{payload}' returned '{expected}', indicating {engine} template injection. "
                                        f"This allows remote code execution."
                                    ),
                                    affected_url=probe_url,
                                    proof=(
                                        f"Baseline GET {baseline_url} → '{expected}' NOT present\n"
                                        f"Injected GET {probe_url} → '{expected}' PRESENT\n"
                                        f"HTTP {r.status_code}"
                                    ),
                                    remediation="Never pass user input directly to template render functions. Use sandboxed environments or static templates.",
                                    impact=5, likelihood=4, module="Ssti",
                                    references=["https://portswigger.net/web-security/server-side-template-injection"],
                                )
                                # ── Playwright screenshot verification ────────
                                if verifier and verifier.available:
                                    confirmed, shot = await verifier.verify_ssti(probe_url, expected)
                                    if confirmed:
                                        ssti_finding.verified   = True
                                        ssti_finding.screenshot = shot
                                        ssti_finding.title      = f"SSTI: Server-Side Template Injection ({engine}) in '{param}' [VERIFIED]"
                                        ssti_finding.proof     += f"\n\nPlaywright verified: evaluated result '{expected}' rendered in headless Chromium."
                                findings.append(ssti_finding)
                                return  # one finding per endpoint is enough
                        except Exception as e:
                            logger.debug(f"SSTI probe {probe_url}: {type(e).__name__}: {e}")

        async def probe_form(form: dict):
            action = form.get("action", "")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            if not action or not inputs:
                return
            # Skip ASP.NET hidden fields — they're not template-rendered
            testable = [i for i in inputs if not i.startswith("__")]
            if not testable:
                return
            async with sem:
                # Baseline
                baseline_data = {i: "hello" for i in inputs}
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            baseline_r = await (c.post(action, data=baseline_data) if method == "POST"
                                                else c.get(action, params=baseline_data))
                    baseline_text = baseline_r.text
                except Exception:
                    baseline_text = ""

                for payload, expected, engine in SSTI_PROBES[:3]:
                    if expected in baseline_text:
                        continue
                    data = {i: "hello" for i in inputs}
                    data[testable[0]] = payload
                    try:
                        async with limiter.acquire():
                            async with make_client(timeout=PROBE_TIMEOUT) as c:
                                r = await (c.post(action, data=data) if method == "POST"
                                           else c.get(action, params=data))
                        if expected in r.text and payload not in r.text:
                            findings.append(Finding(
                                title=f"SSTI via Form Field '{testable[0]}' ({engine})",
                                severity="Critical",
                                description=f"Form field evaluates template syntax. Payload '{payload}' returned '{expected}'.",
                                affected_url=action,
                                proof=f"{method} {action}\nPayload: {payload}\nResponse contains: {expected}",
                                remediation="Sanitize inputs before passing to template engines. Use auto-escaping.",
                                impact=5, likelihood=4, module="Ssti",
                            ))
                            return
                    except Exception as e:
                        logger.debug(f"SSTI form probe {action}: {type(e).__name__}: {e}")

        await asyncio.gather(
            *[probe_param(u) for u in endpoints[:100]],
            *[probe_form(f) for f in forms[:20]],
        )
        logger.info(f"Ssti completed — {len(findings)} finding(s)")
        return findings
