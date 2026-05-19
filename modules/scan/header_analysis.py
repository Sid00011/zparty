import logging
from core.finding import Finding
from core.http_client import make_client

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "content-security-policy":      ("Missing Content-Security-Policy", "High",
                                     "Add a Content-Security-Policy header to prevent XSS and data injection.",
                                     "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"),
    "x-frame-options":              ("Missing X-Frame-Options", "Medium",
                                     "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
                                     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"),
    "x-content-type-options":       ("Missing X-Content-Type-Options", "Low",
                                     "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
                                     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    "strict-transport-security":    ("Missing Strict-Transport-Security", "Medium",
                                     "Add HSTS with at minimum max-age=31536000.",
                                     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
    "referrer-policy":              ("Missing Referrer-Policy", "Low",
                                     "Add Referrer-Policy to control information in the Referer header.",
                                     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"),
    "permissions-policy":           ("Missing Permissions-Policy", "Low",
                                     "Add Permissions-Policy to control browser feature access.",
                                     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"),
}

COOKIE_FLAGS = ["httponly", "secure", "samesite"]


class HeaderAnalysis:
    async def run(self, ctx: dict) -> list[Finding]:
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        findings = []
        logger.info(f"Header analysis: {url}")

        try:
            async with limiter.acquire():
                async with make_client() as client:
                    r = await client.get(url)

            hdrs = {k.lower(): v for k, v in r.headers.items()}

            for header, (title, severity, remediation, ref) in SECURITY_HEADERS.items():
                if header not in hdrs:
                    findings.append(Finding(
                        title=title,
                        severity=severity,
                        description=f"The response to {url} is missing the '{header}' security header.",
                        affected_url=url,
                        proof=f"GET {url}\nResponse headers:\n" + "\n".join(f"  {k}: {v}" for k, v in hdrs.items()),
                        remediation=remediation,
                        impact=2,
                        likelihood=3,
                        module="HeaderAnalysis",
                        references=[ref],
                    ))

            set_cookie_vals = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else [r.headers.get("set-cookie", "")]
            for cookie in set_cookie_vals:
                if not cookie:
                    continue
                cookie_low = cookie.lower()
                missing = [f for f in COOKIE_FLAGS if f not in cookie_low]
                if missing:
                    findings.append(Finding(
                        title=f"Insecure Cookie Flags: {', '.join(missing).title()}",
                        severity="Medium",
                        description=f"Cookie is missing: {', '.join(missing)} flags.",
                        affected_url=url,
                        proof=f"Set-Cookie: {cookie[:200]}",
                        remediation="Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                        impact=3,
                        likelihood=3,
                        module="HeaderAnalysis",
                    ))

        except Exception as e:
            logger.warning(f"Header analysis error: {type(e).__name__}: {e}")

        ctx["scan"]["header_findings"] = [f.to_dict() for f in findings]
        return findings
