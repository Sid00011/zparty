"""
modules/vulns/idor_chain.py — Chained IDOR Detection

Strategy:
  1. Harvest every numeric ID and UUID from all response bodies during scan
  2. For each endpoint that accepts an ID-like parameter, substitute IDs
     that belong to other objects/users
  3. Compare responses — if a different user's data is returned: IDOR
  4. Chain: use IDs found in endpoint A as input to endpoint B

This catches the class of IDOR that scanners miss because they only
test with a single ID value and never try to cross-reference.
"""
import asyncio
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

# Patterns that look like IDs
ID_PATTERNS = [
    re.compile(r'\b(\d{1,10})\b'),                          # numeric
    re.compile(r'"id"\s*:\s*(\d+)'),                         # JSON id field
    re.compile(r'"user_?id"\s*:\s*(\d+)'),                   # JSON user_id
    re.compile(r'"order_?id"\s*:\s*(\d+)'),                  # order_id
    re.compile(r'"account_?id"\s*:\s*(\d+)'),                # account_id
    re.compile(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I),  # UUID
    re.compile(r'/(\d{1,10})(?:/|$|\?)'),                    # path segment ID
]

# Params that likely hold IDs
ID_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "order_id", "orderid", "item_id", "itemid", "product_id", "productid",
    "post_id", "postid", "comment_id", "commentid", "doc_id", "docid",
    "file_id", "fileid", "record_id", "recordid", "ref", "key",
    "customer_id", "member_id", "profile_id", "invoice_id", "ticket_id",
}

# Signs that the response contains sensitive data
SENSITIVE_INDICATORS = [
    "email", "password", "phone", "address", "credit_card", "ssn",
    "date_of_birth", "bank", "account", "balance", "transaction",
    "api_key", "token", "secret", "private", "medical", "diagnosis",
]


def _harvest_ids(text: str) -> set[str]:
    """Extract all ID-like values from a response body."""
    ids = set()
    for pattern in ID_PATTERNS:
        for match in pattern.findall(text):
            val = match.strip()
            if val and val not in {"0", "1"} and len(val) <= 36:
                ids.add(val)
    return ids


def _is_sensitive(text: str) -> bool:
    text_low = text.lower()
    return any(ind in text_low for ind in SENSITIVE_INDICATORS)


class IdorChain:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        limiter   = ctx["limiter"]
        sem       = asyncio.Semaphore(8)
        seen: set[str] = set()

        # ── Step 1: Harvest IDs from all endpoints ────────────────────────────
        harvested_ids: set[str] = set()
        baseline_responses: dict[str, str] = {}  # url → body

        async def harvest(ep: str):
            try:
                async with limiter.acquire():
                    async with make_client(timeout=PROBE_TIMEOUT) as c:
                        r = await c.get(ep)
                if r.status_code == 200:
                    ids = _harvest_ids(r.text)
                    harvested_ids.update(ids)
                    baseline_responses[ep] = r.text
            except Exception:
                pass

        await asyncio.gather(*[harvest(ep) for ep in endpoints[:80]])
        logger.info(f"IdorChain: harvested {len(harvested_ids)} IDs from {len(endpoints)} endpoints")

        if not harvested_ids:
            return findings

        # ── Step 2: For each endpoint with ID params, try other IDs ──────────
        async def probe(ep: str):
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            id_params = [p for p in params if p.lower() in ID_PARAM_NAMES]

            # Also check path segments
            path_parts = parsed.path.split("/")
            path_ids   = [(i, part) for i, part in enumerate(path_parts)
                          if part.isdigit() and len(part) <= 10]

            if not id_params and not path_ids:
                return

            # Get baseline for this endpoint
            baseline = baseline_responses.get(ep, "")
            current_ids = _harvest_ids(baseline) or {"1"}

            # Try IDs from OTHER endpoints (cross-reference)
            other_ids = harvested_ids - current_ids
            test_ids  = list(other_ids)[:10]
            # Also try sequential IDs
            for base_id in list(current_ids)[:3]:
                if base_id.isdigit():
                    n = int(base_id)
                    test_ids += [str(n+1), str(n-1), str(n+100), "1", "2", "admin"]

            async with sem:
                for test_id in list(set(test_ids))[:15]:
                    # Test query param IDs
                    for param in id_params:
                        key = f"{ep}:{param}:{test_id}"
                        if key in seen:
                            continue
                        seen.add(key)
                        p = dict(params)
                        p[param] = [test_id]
                        probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                        f = await self._check_idor(
                            probe_url, param, test_id, baseline, ep, limiter
                        )
                        if f:
                            findings.append(f)
                            return

                    # Test path segment IDs
                    for idx, orig_id in path_ids:
                        if test_id == orig_id:
                            continue
                        new_parts  = list(path_parts)
                        new_parts[idx] = test_id
                        new_path   = "/".join(new_parts)
                        probe_url  = parsed._replace(path=new_path).geturl()
                        key = f"path:{probe_url}"
                        if key in seen:
                            continue
                        seen.add(key)
                        f = await self._check_idor(
                            probe_url, f"path[{idx}]", test_id, baseline, ep, limiter
                        )
                        if f:
                            findings.append(f)
                            return

        await asyncio.gather(*[probe(ep) for ep in endpoints[:100]])
        logger.info(f"IdorChain completed — {len(findings)} finding(s)")
        return findings

    async def _check_idor(
        self, probe_url, param, test_id, baseline, original_ep, limiter
    ) -> Finding | None:
        try:
            await maybe_jitter()
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT) as c:
                    r = await c.get(probe_url)

            if r.status_code not in (200, 201):
                return None

            body = r.text
            if not body or body == baseline:
                return None

            # Response must be meaningfully different AND contain sensitive data
            # OR be clearly different JSON structure
            different_enough = (
                len(body) > 50 and
                abs(len(body) - len(baseline)) > 20
            )
            has_sensitive = _is_sensitive(body)
            is_json = "application/json" in r.headers.get("content-type", "")

            if not (different_enough and (has_sensitive or is_json)):
                return None

            # Double-check: try an ID that definitely doesn't exist
            # If that also returns data, it's not IDOR — it's just a 200-for-all
            parsed = urlparse(probe_url)
            params = parse_qs(parsed.query)
            null_p = dict(params)
            null_param = list(params.keys())[0] if params else None
            if null_param:
                null_p[null_param] = ["999999999"]
                null_url = parsed._replace(query=urlencode(null_p, doseq=True)).geturl()
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            null_r = await c.get(null_url)
                    if null_r.status_code == 200 and len(null_r.text) > 50:
                        return None  # Returns data for any ID → not IDOR
                except Exception:
                    pass

            return Finding(
                title=f"IDOR: Unauthorized Access via '{param}' (ID={test_id})",
                severity="High",
                description=(
                    f"Changing '{param}' to '{test_id}' (from another object/user) "
                    f"returns different data at {probe_url}. "
                    f"This indicates broken object-level authorization — any user "
                    f"can access any other user's data by guessing IDs."
                ),
                affected_url=probe_url,
                proof=(
                    f"Original:    GET {original_ep}\n"
                    f"IDOR probe:  GET {probe_url}\n"
                    f"HTTP {r.status_code} — different response ({len(body)} bytes)\n"
                    f"Sample: {body[:300]}"
                ),
                remediation=(
                    "Enforce object-level authorization on every endpoint. "
                    "Verify that the authenticated user owns the requested resource. "
                    "Never rely on obscurity of IDs."
                ),
                impact=4, likelihood=4, module="IdorChain",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                cvss_score=8.1, cwe="CWE-639",
            )
        except Exception as e:
            logger.debug(f"IdorChain probe {probe_url}: {e}")
        return None
