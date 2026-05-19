import asyncio
import hashlib
import logging
from pathlib import Path
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

CRITICAL_PATHS = {
    ".git", ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
    ".htpasswd", "web.config", "phpinfo.php", "wp-config.php", "config.php",
    "database.yml", "secrets.yml", "backup.sql", "dump.sql", "database.sql",
    ".DS_Store", "adminer.php", "elmah.axd", "trace.axd",
}

HIGH_RISK_PATHS = {
    "admin", "administrator", "phpmyadmin", "manager/html", "jmx-console",
    "web-console", "actuator/env", "actuator/beans", "actuator/configprops",
    "server-status", "wp-admin",
}

# For certain sensitive files, verify the response body actually looks right.
# This prevents SPA/catch-all routes from generating false positives.
CONTENT_VALIDATORS = {
    ".git/HEAD":       lambda b: b.startswith("ref: refs/"),
    ".git/config":     lambda b: "[core]" in b or "[remote" in b,
    ".env":            lambda b: any("=" in line and not line.startswith("#")
                                     for line in b.splitlines()[:20]),
    ".env.local":      lambda b: any("=" in line and not line.startswith("#")
                                     for line in b.splitlines()[:20]),
    ".env.production": lambda b: any("=" in line and not line.startswith("#")
                                     for line in b.splitlines()[:20]),
    "phpinfo.php":     lambda b: "PHP Version" in b or "phpinfo()" in b,
    "wp-config.php":   lambda b: "DB_NAME" in b or "table_prefix" in b,
    "config.php":      lambda b: "<?php" in b or "DB_" in b or "database" in b.lower(),
    "adminer.php":     lambda b: "Adminer" in b or "adminer" in b.lower(),
    ".htpasswd":       lambda b: any(":" in line for line in b.splitlines()[:5]),
    "web.config":      lambda b: "<configuration" in b or "<?xml" in b,
    "database.yml":    lambda b: ("adapter:" in b or "host:" in b or "database:" in b),
    "secrets.yml":     lambda b: ("secret" in b.lower() and (":" in b)),
    "backup.sql":      lambda b: "CREATE TABLE" in b or "INSERT INTO" in b,
    "dump.sql":        lambda b: "CREATE TABLE" in b or "INSERT INTO" in b,
    "database.sql":    lambda b: "CREATE TABLE" in b or "INSERT INTO" in b,
    "elmah.axd":       lambda b: "ELMAH" in b or "Error Log" in b,
    "trace.axd":       lambda b: "Trace" in b and ("Request" in b or "Session" in b),
}

BUILTIN_WORDLIST = [
    # Auth / admin panels
    "admin", "administrator", "login", "login.php", "login.jsp", "login.aspx",
    "signin", "signup", "register", "logout", "dashboard", "panel", "console",
    "manager", "management", "controlpanel", "cp", "backend", "backoffice",
    # APIs
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest", "ws", "rpc",
    "swagger.json", "openapi.json", "api-docs", "api/swagger", "v1", "v2",
    # Spring Boot actuators (high-value targets)
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "actuator/beans", "actuator/configprops", "actuator/info",
    # Apache / server status
    "server-status", "server-info", "status", "health", "healthz", "ping",
    # PHP
    "phpinfo.php", "info.php", "test.php", "config.php", "wp-admin",
    "wp-login.php", "phpmyadmin", "adminer.php", "install.php", "setup.php",
    # JSP / Java / Tomcat
    "index.jsp", "login.jsp", "admin.jsp", "manager/html", "host-manager/html",
    "jmx-console", "web-console", "invoker/JMXInvokerServlet",
    # ASP / .NET
    "login.aspx", "admin.aspx", "default.aspx", "web.config", "elmah.axd",
    "trace.axd", "ScriptResource.axd", "WebResource.axd",
    # Sensitive files
    ".git", ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
    ".htaccess", ".htpasswd", "web.config", "config.yml", "config.yaml",
    "database.yml", "secrets.yml", ".DS_Store", "backup.zip", "backup.sql",
    "dump.sql", "database.sql",
    # Code artifacts / leaks
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "CHANGELOG", "CHANGELOG.md", "README", "readme.md", "package.json",
    "composer.json", "Gemfile", "requirements.txt", ".npmrc", "yarn.lock",
    # Common dirs
    "upload", "uploads", "files", "backup", "backups", "old", "dev", "test",
    "staging", "temp", "tmp", "cache", "logs", "log", "data", "static",
    "assets", "images", "img", "css", "js", "fonts", "media", "public",
    # Databases
    "phpmyadmin", "adminer", "db", "database", "pgsql",
]


def _body_hash(text: str) -> str:
    return hashlib.md5(text.encode(errors="ignore")).hexdigest()


def _is_spa_response(body: str, baseline_hash: str, baseline_len: int) -> bool:
    """Return True if this response looks like the SPA catch-all (index.html)."""
    h = _body_hash(body)
    if h == baseline_hash:
        return True
    # Within 5% of baseline length AND shares Angular/React/Vue markers
    if baseline_len > 0:
        ratio = len(body) / baseline_len
        if 0.92 < ratio < 1.08:
            spa_markers = ["<app-root", "ng-version", "react-root", "__NEXT_DATA__",
                           "data-reactroot", "id=\"app\"", "id=\"root\"", "nuxt"]
            if any(m in body for m in spa_markers):
                return True
    return False


class DirBruteforce:
    async def run(self, ctx: dict) -> list[Finding]:
        url = ctx["target_url"].rstrip("/")
        limiter = ctx["limiter"]
        cfg = ctx["config"]
        findings = []
        found_paths = []
        sem = asyncio.Semaphore(20)

        wordlist_path = cfg.get("wordlists", {}).get("directories", "")
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
            # Cap to 2000 — the full 220K wordlist creates 220K asyncio Tasks at once,
            # stalling the event loop and consuming ~500MB RAM for no practical gain
            # within the 120s module budget.
            words = words[:2000]
        else:
            words = BUILTIN_WORDLIST

        logger.info(f"Dir brute-force: {len(words)} paths against {url}")

        # ── Baseline fingerprint ──────────────────────────────────────────────
        # Probe a random nonexistent path to learn how this server handles 404s.
        # Servers may use: 200 (SPA), 301/302 catch-all redirect, or real 404.
        baseline_hash = ""
        baseline_len = 0
        spa_detected = False
        redirect_catchall = False
        redirect_catchall_dest = ""   # normalised destination of catch-all redirect
        try:
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=True) as client:
                    br = await client.get(url + "/")
            baseline_hash = _body_hash(br.text)
            baseline_len = len(br.text)

            rand_path = url + "/zparty_baseline_check_xyz_nonexistent"
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
                    nr = await client.get(rand_path)

            if nr.status_code == 200 and _body_hash(nr.text) == baseline_hash:
                # Every path returns the same 200 body → SPA catch-all
                spa_detected = True
                logger.info(f"SPA/catch-all (200) detected at {url}")
            elif nr.status_code in (301, 302, 307, 308):
                # Server redirects unknown paths → catch-all redirect
                redirect_catchall = True
                redirect_catchall_dest = nr.headers.get("location", "").split("?")[0]
                logger.info(f"Redirect catch-all detected at {url} → {redirect_catchall_dest}")
        except Exception as e:
            logger.debug(f"Baseline fetch failed: {e}")

        async def probe(path: str):
            probe_url = f"{url}/{path}"
            async with sem:
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
                            r = await client.get(probe_url)

                    if r.status_code not in (200, 301, 302, 307, 401, 403):
                        return

                    body = r.text
                    is_critical = any(cp in path for cp in CRITICAL_PATHS)
                    is_high = any(hp in path for hp in HIGH_RISK_PATHS)

                    # ── SPA catch-all guard (200) ─────────────────────────────
                    if r.status_code == 200 and spa_detected:
                        if _is_spa_response(body, baseline_hash, baseline_len):
                            return

                    # ── Redirect catch-all guard (3xx) ────────────────────────
                    # If the site redirects ALL unknown paths, only report when:
                    # a) This path's redirect goes somewhere *different* from the
                    #    catch-all (e.g., to an admin login rather than homepage), OR
                    # b) The path is Critical/High (worth verifying manually anyway)
                    if redirect_catchall and r.status_code in (301, 302, 307, 308):
                        loc = r.headers.get("location", "").split("?")[0]
                        if loc == redirect_catchall_dest or loc in ("/", ""):
                            if not (is_critical or is_high):
                                return  # Same generic redirect → false positive

                    # ── 401/403 filtering ─────────────────────────────────────
                    # Webservers often return 403 for random directories as a default.
                    # Only report 401/403 for Critical and High-risk paths.
                    if r.status_code in (401, 403) and not (is_critical or is_high):
                        return

                    # ── Content validation for sensitive files ────────────────
                    path_key = path.lstrip("/")
                    validator = CONTENT_VALIDATORS.get(path_key)
                    if validator is not None:
                        try:
                            body_sample = body[:4096]
                            if not validator(body_sample):
                                logger.debug(f"Content validation failed for {probe_url} — skipping")
                                return
                        except Exception:
                            return

                    found_paths.append({"path": probe_url, "status": r.status_code})

                    if is_critical:
                        severity = "Critical"
                    elif is_high or r.status_code == 200:
                        severity = "High" if is_high else "Medium"
                    else:
                        severity = "Low"

                    findings.append(Finding(
                        title=f"{'Sensitive File' if is_critical else 'Exposed Path'}: /{path}",
                        severity=severity,
                        description=(
                            f"/{path} returned HTTP {r.status_code}. "
                            f"{'This file may contain credentials or sensitive configuration.'if is_critical else 'This path is accessible and may expose sensitive functionality.'}"
                        ),
                        affected_url=probe_url,
                        proof=f"GET {probe_url} → HTTP {r.status_code}",
                        remediation="Restrict access, remove sensitive files from web root, or configure proper authentication.",
                        impact=5 if is_critical else (4 if is_high else 2),
                        likelihood=4,
                        module="DirBruteforce",
                    ))
                    logger.info(f"[{r.status_code}] {probe_url}")
                except Exception as e:
                    logger.debug(f"Dir probe {probe_url}: {type(e).__name__}: {e}")

        await asyncio.gather(*[probe(w) for w in words])

        ctx["scan"]["found_paths"] = found_paths
        # Add discovered paths to endpoints for vuln modules
        ctx["endpoints"].extend([x["path"] for x in found_paths])
        return findings
