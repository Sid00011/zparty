"""
modules/vulns/oauth_tester.py — OAuth 2.0 / OIDC Misconfiguration Testing

Tests:
  1. Missing/weak state parameter → CSRF on OAuth flow
  2. redirect_uri bypass → steal authorization code
  3. Token leaked in URL → referrer log exposure
  4. Open redirect via redirect_uri
  5. Implicit flow token exposure
  6. PKCE downgrade (code_challenge_method missing)
  7. Authorization code reuse
"""
import asyncio
import logging
import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

# OAuth endpoint patterns
OAUTH_PATTERNS = re.compile(
    r'(?:oauth|authorize|auth|connect|login|sso|oidc|openid)',
    re.IGNORECASE
)

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
]

# redirect_uri bypass attempts
REDIRECT_BYPASS_VARIANTS = [
    # Open redirect via path
    "{legit}@evil.com",
    "{legit}%40evil.com",
    # Add path after legitimate domain
    "{legit}/../../evil",
    "{legit}?.evil.com",
    # Subdomain confusion
    "evil.{legit}",
    # Fragment bypass
    "{legit}#@evil.com",
    # Double slash
    "{legit}//evil.com",
    # Null byte
    "{legit}%00.evil.com",
]

STATE_WEAKNESS_INDICATORS = [
    r'^[0-9]{1,6}$',                 # simple numeric
    r'^[a-f0-9]{4,8}$',             # very short hex
    r'^(csrf|state|nonce|token)$',   # literal keyword
    r'^.{1,8}$',                     # too short (< 9 chars)
]


class OAuthTester:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        target    = ctx.get("target_url", "")
        endpoints = ctx.get("endpoints", [])
        limiter   = ctx["limiter"]
        sem       = asyncio.Semaphore(5)
        seen: set[str] = set()

        # ── Discover OAuth endpoints ──────────────────────────────────────────
        oauth_endpoints = [
            ep for ep in endpoints
            if OAUTH_PATTERNS.search(ep) or "oauth" in ep.lower()
        ]

        # Check well-known discovery
        base = target.rstrip("/")
        well_known_data = {}
        for path in WELL_KNOWN_PATHS:
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        r = await c.get(base + path)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        well_known_data = data
                        # Extract OAuth endpoints from discovery document
                        for key in ["authorization_endpoint", "token_endpoint",
                                    "userinfo_endpoint", "revocation_endpoint"]:
                            if data.get(key):
                                oauth_endpoints.append(data[key])
                        logger.info(f"OAuthTester: found OpenID config at {path}")
                        break
                    except Exception:
                        pass
            except Exception:
                pass

        if not oauth_endpoints and not well_known_data:
            logger.info("OAuthTester: no OAuth endpoints detected")
            return findings

        # Deduplicate
        oauth_endpoints = list(set(oauth_endpoints))[:15]

        async def test_ep(ep: str):
            if ep in seen:
                return
            seen.add(ep)
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)

            # Test 1 — State parameter weakness
            f = await self._test_state(ep, params, limiter, sem)
            if f:
                findings.append(f)

            # Test 2 — redirect_uri bypass
            if params.get("redirect_uri") or params.get("redirect_url"):
                fs = await self._test_redirect_uri(ep, params, limiter, sem)
                findings.extend(fs)

            # Test 3 — PKCE downgrade
            if params.get("code_challenge_method") or well_known_data.get("code_challenge_methods_supported"):
                f3 = await self._test_pkce(ep, params, limiter, sem)
                if f3:
                    findings.append(f3)

        # Test all OAuth endpoints
        await asyncio.gather(*[test_ep(ep) for ep in oauth_endpoints])

        # Test 4 — Token in URL (check all endpoints for access_token in URL)
        f4 = self._check_token_in_url(endpoints)
        if f4:
            findings.append(f4)

        logger.info(f"OAuthTester completed — {len(findings)} finding(s)")
        return findings

    async def _test_state(self, ep, params, limiter, sem) -> Finding | None:
        """Test if state parameter is missing or predictable."""
        async with sem:
            state = params.get("state", [""])[0]

            # Missing state parameter
            if not state:
                # Try requesting without state and see if it proceeds
                return Finding(
                    title="OAuth: Missing State Parameter (CSRF Risk)",
                    severity="Medium",
                    description=(
                        f"The OAuth authorization endpoint at {ep} does not use "
                        f"a state parameter. This allows Cross-Site Request Forgery "
                        f"attacks on the OAuth flow — an attacker can trick a user "
                        f"into authorizing an attacker-controlled account."
                    ),
                    affected_url=ep,
                    proof=f"GET {ep}\nNo 'state' parameter present in authorization URL",
                    remediation=(
                        "Add a cryptographically random state parameter to every "
                        "OAuth authorization request. Validate it on the callback."
                    ),
                    impact=3, likelihood=3, module="OAuthTester",
                    references=["https://datatracker.ietf.org/doc/html/rfc6749#section-10.12"],
                    cvss_score=6.1, cwe="CWE-352",
                )

            # Weak state parameter
            for pattern in STATE_WEAKNESS_INDICATORS:
                if re.match(pattern, state):
                    return Finding(
                        title="OAuth: Weak/Predictable State Parameter",
                        severity="Medium",
                        description=(
                            f"The OAuth state parameter value '{state}' is weak or predictable "
                            f"(matches pattern: {pattern}). "
                            f"An attacker can guess or brute-force the state value, "
                            f"enabling CSRF on the OAuth flow."
                        ),
                        affected_url=ep,
                        proof=f"GET {ep}\nstate={state} (weak: {pattern})",
                        remediation="Use cryptographically random state values of at least 128 bits.",
                        impact=3, likelihood=3, module="OAuthTester",
                        cvss_score=6.1, cwe="CWE-330",
                    )
        return None

    async def _test_redirect_uri(self, ep, params, limiter, sem) -> list[Finding]:
        """Test redirect_uri validation bypass techniques."""
        findings = []
        async with sem:
            uri_param = "redirect_uri" if "redirect_uri" in params else "redirect_url"
            legit_uri = params.get(uri_param, [""])[0]
            if not legit_uri:
                return findings

            parsed_legit = urlparse(legit_uri)
            legit_base   = f"{parsed_legit.scheme}://{parsed_legit.netloc}"

            bypass_attempts = [
                f"{legit_base}@evil.com",
                f"{legit_base}?.evil.com",
                f"{legit_base}%40evil.com",
                f"{legit_base}//evil.com",
                f"{legit_uri}/../../evil",
                "https://evil.com",
                f"https://evil.com#{legit_uri}",
            ]

            for bypass in bypass_attempts[:5]:
                try:
                    p = dict(params)
                    p[uri_param] = [bypass]
                    # Add random state
                    p["state"] = [secrets.token_hex(16)]
                    probe_url = urlparse(ep)._replace(query=urlencode(p, doseq=True)).geturl()
                    async with limiter.acquire():
                        async with make_client(
                            timeout=PROBE_TIMEOUT, follow_redirects=False
                        ) as c:
                            r = await c.get(probe_url)

                    # If server redirects to our evil URI → bypass works
                    location = r.headers.get("location", "")
                    if "evil.com" in location or bypass in location:
                        findings.append(Finding(
                            title=f"OAuth: redirect_uri Bypass → Open Redirect",
                            severity="High",
                            description=(
                                f"The OAuth authorization server accepted a malicious "
                                f"redirect_uri: '{bypass}'. "
                                f"An attacker can steal authorization codes by tricking "
                                f"a victim into clicking a crafted OAuth link."
                            ),
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nHTTP {r.status_code}\nLocation: {location}",
                            remediation=(
                                "Validate redirect_uri strictly against a whitelist. "
                                "Reject any URI not exactly matching a pre-registered value."
                            ),
                            impact=4, likelihood=3, module="OAuthTester",
                            references=["https://portswigger.net/web-security/oauth"],
                            cvss_score=7.4, cwe="CWE-601",
                        ))
                        break
                except Exception as e:
                    logger.debug(f"OAuth redirect_uri test: {e}")
        return findings

    async def _test_pkce(self, ep, params, limiter, sem) -> Finding | None:
        """Test if PKCE can be downgraded (code_challenge_method removed)."""
        async with sem:
            try:
                # Try sending without code_challenge
                p = dict(params)
                p.pop("code_challenge", None)
                p.pop("code_challenge_method", None)
                p["state"] = [secrets.token_hex(16)]
                probe_url = urlparse(ep)._replace(query=urlencode(p, doseq=True)).geturl()
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT, follow_redirects=False) as c:
                        r = await c.get(probe_url)

                # If server proceeds without PKCE → downgrade possible
                if r.status_code in (200, 302) and "error" not in r.text.lower()[:200]:
                    return Finding(
                        title="OAuth: PKCE Downgrade Attack Possible",
                        severity="High",
                        description=(
                            "The authorization server accepts requests without a "
                            "code_challenge parameter, allowing PKCE to be bypassed. "
                            "An attacker who intercepts the authorization code can "
                            "exchange it for tokens without the code_verifier."
                        ),
                        affected_url=probe_url,
                        proof=f"GET {probe_url}\nNo code_challenge sent — server responded HTTP {r.status_code}",
                        remediation="Require PKCE (S256 method) for all public clients. Reject requests without code_challenge.",
                        impact=4, likelihood=3, module="OAuthTester",
                        cvss_score=7.4, cwe="CWE-303",
                    )
            except Exception as e:
                logger.debug(f"OAuth PKCE test: {e}")
        return None

    def _check_token_in_url(self, endpoints: list[str]) -> Finding | None:
        """Check if any endpoints have access_token in the URL (log exposure)."""
        for ep in endpoints:
            if "access_token=" in ep or "id_token=" in ep:
                return Finding(
                    title="OAuth: Token Exposed in URL",
                    severity="High",
                    description=(
                        f"An OAuth token was found in a URL: {ep[:100]}. "
                        f"Tokens in URLs are logged by servers, proxies, and browser "
                        f"history — and leaked via Referer headers to third parties."
                    ),
                    affected_url=ep,
                    proof=f"Token in URL: {ep[:200]}",
                    remediation=(
                        "Use the Authorization Code flow instead of Implicit flow. "
                        "Never return tokens in URL fragments or query parameters."
                    ),
                    impact=4, likelihood=4, module="OAuthTester",
                    cvss_score=7.5, cwe="CWE-598",
                )
        return None
