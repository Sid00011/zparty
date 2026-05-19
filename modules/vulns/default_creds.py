"""
modules/vulns/default_creds.py — Default credential testing

Tries known default username/password pairs against discovered admin panels
and all login forms. On success, takes a Playwright screenshot as proof.
"""
import asyncio
import logging
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

# ── Default credential database ───────────────────────────────────────────────
PANEL_CREDS: dict[str, list[tuple[str, str]]] = {
    "jenkins":      [("admin","admin"),("jenkins","jenkins"),("admin","password"),("admin","jenkins")],
    "grafana":      [("admin","admin"),("admin","grafana"),("admin","password"),("grafana","grafana")],
    "phpmyadmin":   [("root",""),("root","root"),("root","password"),("root","toor"),("admin","admin")],
    "adminer":      [("root",""),("admin","admin"),("adminer","adminer")],
    "tomcat":       [("tomcat","tomcat"),("admin","admin"),("tomcat","s3cret"),("manager","manager")],
    "kibana":       [("elastic","elastic"),("kibana","changeme"),("admin","admin")],
    "elasticsearch":[("elastic","elastic"),("elastic","changeme")],
    "wordpress":    [("admin","admin"),("admin","password"),("wordpress","wordpress"),("admin","wordpress")],
    "drupal":       [("admin","admin"),("admin","password"),("drupal","drupal")],
    "joomla":       [("admin","admin"),("admin","password"),("joomla","joomla")],
    "gitlab":       [("root","5iveL!fe"),("root","password"),("admin","admin"),("root","root")],
    "sonarqube":    [("admin","admin"),("sonar","sonar")],
    "rabbitmq":     [("guest","guest"),("admin","admin"),("rabbitmq","rabbitmq")],
    "mongoexpress": [("admin","pass"),("admin","admin"),("mongo","mongo")],
    "jupyter":      [("",""),("admin","admin"),("jupyter","jupyter")],
    "webmin":       [("admin","admin"),("root","root"),("webmin","webmin")],
    "cpanel":       [("admin","admin"),("cpanel","cpanel")],
    "plesk":        [("admin","admin"),("plesk","plesk")],
}

# Generic credentials to try on any login form
GENERIC_CREDS: list[tuple[str, str]] = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "admin123"),
    ("admin",         "1234"),
    ("admin",         ""),
    ("administrator", "administrator"),
    ("administrator", "admin"),
    ("administrator", "password"),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("test",          "test"),
    ("test",          "password"),
    ("user",          "user"),
    ("user",          "password"),
    ("guest",         "guest"),
    ("demo",          "demo"),
    ("superadmin",    "superadmin"),
    ("sa",            "sa"),
]

# Keywords that suggest successful login
SUCCESS_INDICATORS = [
    "dashboard", "logout", "sign out", "signout", "log out", "logoff",
    "welcome", "profile", "account", "my account", "settings",
    "admin panel", "control panel", "management", "portal",
    "/dashboard", "/home", "/main", "/admin/home",
]

FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "unauthorized", "denied", "bad credentials", "no match",
]

# URL patterns that indicate login panels
PANEL_URL_KEYWORDS = {
    "jenkins":      ["/jenkins", "jenkins."],
    "grafana":      ["/grafana", "grafana.", ":3000"],
    "phpmyadmin":   ["/phpmyadmin", "/pma", "phpmyadmin."],
    "adminer":      ["/adminer", "adminer.php"],
    "tomcat":       ["/manager", "/host-manager", "tomcat."],
    "kibana":       ["/kibana", "kibana.", ":5601"],
    "wordpress":    ["/wp-admin", "/wp-login"],
    "gitlab":       ["/gitlab", "gitlab.", "/users/sign_in"],
    "sonarqube":    ["/sonarqube", "sonar.", ":9000"],
    "rabbitmq":     ["/rabbitmq", "rabbitmq.", ":15672"],
}


def _detect_panel(url: str) -> str | None:
    url_low = url.lower()
    for panel, keywords in PANEL_URL_KEYWORDS.items():
        if any(kw in url_low for kw in keywords):
            return panel
    return None


def _login_succeeded(response_text: str, final_url: str) -> bool:
    text_low = response_text.lower()
    url_low  = final_url.lower()
    has_success = any(ind in text_low or ind in url_low for ind in SUCCESS_INDICATORS)
    has_failure = any(ind in text_low for ind in FAILURE_INDICATORS)
    return has_success and not has_failure


class DefaultCreds:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        forms     = ctx.get("forms", [])
        endpoints = ctx.get("endpoints", [])
        limiter   = ctx["limiter"]
        verifier  = ctx.get("verifier")
        sem       = asyncio.Semaphore(3)  # slow — avoid lockouts
        seen: set[str] = set()

        # ── 1. Test discovered admin panels ───────────────────────────────────
        async def probe_panel(url: str):
            panel_type = _detect_panel(url)
            creds = PANEL_CREDS.get(panel_type, []) if panel_type else []
            creds = creds + GENERIC_CREDS[:5]  # always try top generic

            for username, password in creds:
                key = f"panel:{url}:{username}"
                if key in seen:
                    continue
                seen.add(key)
                f = await self._try_login_url(url, username, password, limiter, sem, verifier, panel_type)
                if f:
                    findings.append(f)
                    return  # stop on first success

        # ── 2. Test discovered login forms ────────────────────────────────────
        async def probe_form(form: dict):
            action = form.get("action", "")
            inputs = form.get("inputs", [])
            if not action or not inputs:
                return
            key = f"form:{action}"
            if key in seen:
                return
            seen.add(key)

            import re
            user_fields = [i for i in inputs if re.search(r'user|email|login|uname|uid', i, re.I)]
            pass_fields = [i for i in inputs if re.search(r'pass|pwd|secret', i, re.I)]
            if not user_fields or not pass_fields:
                return

            user_field = user_fields[0]
            pass_field = pass_fields[0]

            for username, password in GENERIC_CREDS[:10]:
                f = await self._try_form(
                    form, user_field, pass_field, username, password,
                    limiter, sem, verifier
                )
                if f:
                    findings.append(f)
                    return

        # Gather panel URLs from scan results and endpoints
        panel_urls = [
            ep for ep in endpoints
            if any(kw in ep.lower() for kws in PANEL_URL_KEYWORDS.values() for kw in kws)
        ]
        found_paths = ctx.get("scan", {}).get("found_paths", [])
        panel_urls += [p["path"] for p in found_paths
                       if any(kw in p["path"].lower()
                              for kws in PANEL_URL_KEYWORDS.values() for kw in kws)]

        await asyncio.gather(
            *[probe_panel(url) for url in list(set(panel_urls))[:20]],
            *[probe_form(f) for f in forms[:30]],
        )
        logger.info(f"DefaultCreds completed — {len(findings)} finding(s)")
        return findings

    async def _try_login_url(self, url, username, password, limiter, sem, verifier, panel_type) -> Finding | None:
        async with sem:
            await maybe_jitter()
            try:
                data = {"username": username, "password": password,
                        "j_username": username, "j_password": password,  # Jenkins
                        "user_login": username, "user_pass": password,    # WordPress
                        "Email": username, "Password": password}
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=True) as c:
                        r = await c.post(url, data=data)
                if _login_succeeded(r.text, str(r.url)):
                    return await self._make_finding(url, username, password, panel_type, verifier)
            except Exception as e:
                logger.debug(f"DefaultCreds panel {url}: {e}")
        return None

    async def _try_form(self, form, user_field, pass_field, username, password, limiter, sem, verifier) -> Finding | None:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        async with sem:
            await maybe_jitter()
            try:
                data = {i: "test" for i in inputs}
                data[user_field] = username
                data[pass_field] = password
                csrf_field = form.get("csrf_field")
                csrf_token = form.get("csrf_token")
                if csrf_field and csrf_token:
                    data[csrf_field] = csrf_token

                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=True) as c:
                        r = await (c.post(action, data=data) if method == "POST"
                                   else c.get(action, params=data))
                if _login_succeeded(r.text, str(r.url)):
                    return await self._make_finding(action, username, password, "login form", verifier)
            except Exception as e:
                logger.debug(f"DefaultCreds form {action}: {e}")
        return None

    async def _make_finding(self, url, username, password, panel_type, verifier) -> Finding:
        title = f"Default Credentials: {username}/{password} on {panel_type or 'login'}"
        finding = Finding(
            title=title,
            severity="Critical",
            description=(
                f"Login succeeded with default credentials '{username}'/'{password}' "
                f"at {url}. An attacker can gain full administrative access."
            ),
            affected_url=url,
            proof=f"POST {url}\nusername={username}&password={password}\nLogin successful",
            remediation="Change all default credentials immediately. Enforce strong password policy.",
            impact=5, likelihood=5, module="DefaultCreds",
            references=["https://owasp.org/www-project-top-ten/"],
            cvss_score=9.8, cwe="CWE-798",
        )
        if verifier and verifier.available:
            try:
                confirmed, shot = await verifier.verify_sqli(url)
                if confirmed:
                    finding.verified   = True
                    finding.screenshot = shot
                    finding.title     += " [VERIFIED]"
            except Exception:
                pass
        return finding
