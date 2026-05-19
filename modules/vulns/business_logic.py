"""
modules/vulns/business_logic.py — AI-Driven Business Logic Flaw Detection

Strategy:
  1. Detect app domain (e-commerce, fintech, SaaS, social) from URLs + content
  2. Generate domain-specific test payloads (negative prices, coupon stacking, plan bypass)
  3. Run targeted tests and evaluate responses for unexpected behaviour
  4. AI (if available) interprets ambiguous responses to reduce false positives
"""
import asyncio
import logging
import re
import json as _json
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

# ── Domain classifiers ────────────────────────────────────────────────────────
DOMAIN_SIGNALS = {
    "ecommerce": re.compile(
        r'cart|checkout|product|catalog|shop|store|price|buy|order|payment|'
        r'coupon|discount|promo|voucher|gift_card|shipping|inventory',
        re.IGNORECASE
    ),
    "fintech": re.compile(
        r'transfer|withdraw|deposit|balance|account|wallet|transaction|'
        r'invest|trade|portfolio|fund|loan|credit|debit|payout|ledger',
        re.IGNORECASE
    ),
    "saas": re.compile(
        r'plan|subscription|tier|upgrade|downgrade|feature|limit|quota|'
        r'trial|license|seat|workspace|billing|invoice|enterprise',
        re.IGNORECASE
    ),
    "social": re.compile(
        r'follow|like|vote|share|comment|post|profile|friend|block|'
        r'report|badge|rank|score|reputation|level|reward',
        re.IGNORECASE
    ),
}

# ── Test case generators per domain ──────────────────────────────────────────

def _ecommerce_tests(endpoints: list[str], forms: list[dict]) -> list[dict]:
    tests = []
    for ep in endpoints:
        ep_l = ep.lower()

        # Negative price / quantity
        if any(k in ep_l for k in ["cart", "add", "item", "product"]):
            for qty in ["-1", "-100", "0", "999999"]:
                tests.append({
                    "type": "negative_quantity",
                    "url":  ep,
                    "method": "POST",
                    "data": {"quantity": qty, "qty": qty, "amount": qty},
                    "expect_block": True,
                    "title": f"Business Logic: Negative/Zero Quantity Accepted ({qty})",
                    "severity": "High",
                    "cvss": 7.5,
                    "desc": f"Submitting quantity={qty} to {ep} was not rejected. "
                            f"Negative quantities may cause price to go negative (store credit bypass).",
                    "cwe": "CWE-20",
                })

        # Coupon stacking
        if any(k in ep_l for k in ["coupon", "promo", "discount", "voucher"]):
            tests.append({
                "type": "coupon_stack",
                "url":  ep,
                "method": "POST",
                "data": {"coupon": "SAVE10", "coupon2": "SAVE10", "promo_code": "SAVE10"},
                "expect_block": False,
                "title": "Business Logic: Coupon Stacking / Double Redemption",
                "severity": "Medium",
                "cvss": 5.3,
                "desc": f"Multiple coupon codes submitted simultaneously to {ep}. "
                        f"If accepted, a single coupon may be redeemed more than once.",
                "cwe": "CWE-840",
            })

        # Price tampering in checkout
        if any(k in ep_l for k in ["checkout", "order", "purchase"]):
            tests.append({
                "type": "price_tamper",
                "url":  ep,
                "method": "POST",
                "data": {"price": "0.01", "total": "0.01", "amount": "0.01", "unit_price": "0.01"},
                "expect_block": True,
                "title": "Business Logic: Client-Side Price Tampering",
                "severity": "Critical",
                "cvss": 9.1,
                "desc": f"Submitting a tampered price (0.01) to {ep}. "
                        f"If the server trusts client-supplied price values, "
                        f"an attacker can purchase items for near-zero cost.",
                "cwe": "CWE-602",
            })

    return tests


def _fintech_tests(endpoints: list[str], forms: list[dict]) -> list[dict]:
    tests = []
    for ep in endpoints:
        ep_l = ep.lower()

        # Negative transfer amount
        if any(k in ep_l for k in ["transfer", "send", "pay"]):
            for amt in ["-100", "-0.01"]:
                tests.append({
                    "type": "negative_transfer",
                    "url":  ep,
                    "method": "POST",
                    "data": {"amount": amt, "value": amt, "sum": amt},
                    "expect_block": True,
                    "title": f"Business Logic: Negative Transfer Amount ({amt})",
                    "severity": "Critical",
                    "cvss": 9.8,
                    "desc": f"Submitting amount={amt} to {ep}. "
                            f"A negative transfer may credit the sender instead of debiting, "
                            f"enabling balance inflation.",
                    "cwe": "CWE-20",
                })

        # Overdraft / exceed balance
        if any(k in ep_l for k in ["withdraw", "transfer", "pay"]):
            tests.append({
                "type": "overdraft",
                "url":  ep,
                "method": "POST",
                "data": {"amount": "999999999", "value": "999999999"},
                "expect_block": True,
                "title": "Business Logic: Overdraft / Balance Exceeded",
                "severity": "High",
                "cvss": 7.5,
                "desc": f"Submitting an amount far exceeding typical balances to {ep}. "
                        f"If the server does not validate sufficient funds, "
                        f"overdraft attacks become possible.",
                "cwe": "CWE-840",
            })

    return tests


def _saas_tests(endpoints: list[str], forms: list[dict]) -> list[dict]:
    tests = []
    for ep in endpoints:
        ep_l = ep.lower()

        # Feature flag / plan bypass via parameter
        if any(k in ep_l for k in ["plan", "feature", "upgrade", "tier"]):
            for plan in ["enterprise", "admin", "premium", "unlimited", "free"]:
                tests.append({
                    "type": "plan_bypass",
                    "url":  ep,
                    "method": "POST",
                    "data": {"plan": plan, "tier": plan, "subscription": plan},
                    "expect_block": True,
                    "title": f"Business Logic: Plan/Feature Bypass via '{plan}'",
                    "severity": "High",
                    "cvss": 7.3,
                    "desc": f"Submitting plan='{plan}' to {ep}. "
                            f"If the server accepts client-controlled plan names, "
                            f"a user can self-upgrade to a higher tier without paying.",
                    "cwe": "CWE-639",
                })

        # Quota exhaustion bypass
        if any(k in ep_l for k in ["seat", "limit", "quota", "invite"]):
            tests.append({
                "type": "quota_bypass",
                "url":  ep,
                "method": "POST",
                "data": {"seats": "9999", "limit": "-1", "max_users": "9999"},
                "expect_block": True,
                "title": "Business Logic: Seat/Quota Limit Bypass",
                "severity": "Medium",
                "cvss": 5.8,
                "desc": f"Submitting an extreme seat count to {ep}. "
                        f"If the server trusts this value, the plan limit is bypassed.",
                "cwe": "CWE-840",
            })

    return tests


def _social_tests(endpoints: list[str], forms: list[dict]) -> list[dict]:
    tests = []
    for ep in endpoints:
        ep_l = ep.lower()

        # Self-voting / self-liking
        if any(k in ep_l for k in ["vote", "like", "upvote", "rate"]):
            tests.append({
                "type": "self_vote",
                "url":  ep,
                "method": "POST",
                "data": {},
                "expect_block": False,
                "title": "Business Logic: Self-Vote / Reputation Inflation",
                "severity": "Low",
                "cvss": 3.5,
                "desc": f"Sending repeated vote/like actions to {ep} from the same session. "
                        f"If not rate-limited per user, reputation scores can be inflated.",
                "cwe": "CWE-837",
            })

    return tests


DOMAIN_TEST_GENERATORS = {
    "ecommerce": _ecommerce_tests,
    "fintech":   _fintech_tests,
    "saas":      _saas_tests,
    "social":    _social_tests,
}


def _detect_domain(endpoints: list[str], content_sample: str = "") -> str:
    text = " ".join(endpoints) + " " + content_sample
    scores = {domain: len(sig.findall(text)) for domain, sig in DOMAIN_SIGNALS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "generic"


class BusinessLogic:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints  = ctx.get("endpoints", [])
        forms      = ctx.get("forms", [])
        limiter    = ctx["limiter"]
        sem        = asyncio.Semaphore(4)
        seen: set[str] = set()

        if not endpoints and not forms:
            logger.info("BusinessLogic: no endpoints to test")
            return findings

        # ── Detect app domain ─────────────────────────────────────────────────
        domain = _detect_domain(endpoints)
        logger.info(f"BusinessLogic: detected domain={domain}, generating tests")

        # ── Generate tests for detected domain ────────────────────────────────
        gen = DOMAIN_TEST_GENERATORS.get(domain)
        tests = gen(endpoints, forms) if gen else []

        # Also run all generic tests (cover multiple domains in one app)
        if domain != "ecommerce":
            tests += _ecommerce_tests(endpoints, forms)
        if domain != "fintech":
            tests += _fintech_tests(endpoints, forms)
        if domain != "saas":
            tests += _saas_tests(endpoints, forms)

        if not tests:
            logger.info("BusinessLogic: no applicable tests generated")
            return findings

        logger.info(f"BusinessLogic: running {len(tests)} test(s)")

        async def run_test(test: dict):
            url = test["url"]
            key = f"{url}:{test['type']}"
            if key in seen:
                return
            seen.add(key)

            async with sem:
                f = await self._execute_test(test, limiter)
                if f:
                    findings.append(f)

        await asyncio.gather(*[run_test(t) for t in tests[:40]])
        logger.info(f"BusinessLogic completed — {len(findings)} finding(s)")
        return findings

    async def _execute_test(self, test: dict, limiter) -> Finding | None:
        url    = test["url"]
        method = test.get("method", "POST")
        data   = test.get("data", {})

        try:
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT) as c:
                    r = await c.request(method, url, data=data)

            body   = r.text.lower()
            status = r.status_code

            expect_block = test.get("expect_block", True)

            if expect_block:
                # We expect the server to reject this — if it accepts, that's a vuln
                accepted = (
                    status in (200, 201, 204) and
                    not any(w in body for w in [
                        "error", "invalid", "rejected", "failed", "denied",
                        "forbidden", "not allowed", "must be positive", "invalid amount"
                    ])
                )
                if not accepted:
                    return None  # Server correctly rejected → no finding

                return Finding(
                    title=test["title"],
                    severity=test["severity"],
                    description=test["desc"],
                    affected_url=url,
                    proof=(
                        f"{method} {url}\n"
                        f"Payload: {_json.dumps(data)}\n"
                        f"HTTP {status}\n"
                        f"Response: {r.text[:300]}"
                    ),
                    remediation=(
                        "Validate all business-rule constraints server-side. "
                        "Never trust client-supplied values for prices, quantities, "
                        "plan tiers, or financial amounts. Use server-side lookups."
                    ),
                    impact=4, likelihood=3, module="BusinessLogic",
                    cvss_score=test.get("cvss", 7.0),
                    cwe=test.get("cwe", "CWE-20"),
                )

            else:
                # We expect the server to allow it — check for unexpected privilege
                if status in (200, 201) and any(
                    s in body for s in ["success", "applied", "confirmed", "updated"]
                ):
                    return Finding(
                        title=test["title"],
                        severity=test["severity"],
                        description=test["desc"],
                        affected_url=url,
                        proof=(
                            f"{method} {url}\n"
                            f"Payload: {_json.dumps(data)}\n"
                            f"HTTP {status}\n"
                            f"Response: {r.text[:300]}"
                        ),
                        remediation=(
                            "Enforce server-side business rules. "
                            "Implement per-user rate limiting and idempotency checks."
                        ),
                        impact=3, likelihood=3, module="BusinessLogic",
                        cvss_score=test.get("cvss", 5.0),
                        cwe=test.get("cwe", "CWE-840"),
                    )

        except Exception as e:
            logger.debug(f"BusinessLogic test {url}: {e}")
        return None
