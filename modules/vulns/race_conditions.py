import asyncio
import logging
from core.finding import Finding
from core.http_client import make_client

logger = logging.getLogger(__name__)

RACE_INDICATORS = ["coupon", "voucher", "discount", "redeem", "transfer",
                   "purchase", "apply", "checkout", "pay", "withdraw"]


class RaceConditions:
    async def run(self, ctx: dict) -> list[Finding]:
        findings = []
        forms = ctx.get("forms", [])
        limiter = ctx["limiter"]

        candidates = [
            f for f in forms
            if any(ind in f.get("action", "").lower() for ind in RACE_INDICATORS)
            or any(ind in " ".join(f.get("inputs", [])).lower() for ind in RACE_INDICATORS)
        ]

        logger.info(f"Race condition: {len(candidates)} candidate forms")

        for form in candidates[:5]:
            f = await self._test_race(form, limiter)
            if f:
                findings.append(f)

        return findings

    async def _test_race(self, form: dict, limiter) -> Finding | None:
        action = form.get("action", "")
        method = form.get("method", "POST")
        inputs = form.get("inputs", [])
        if not action:
            return None

        data = {i: "ZPARTY_RACE_TEST" for i in inputs}
        CONCURRENCY = 20
        responses = []

        async def send_one():
            try:
                async with make_client() as client:
                    if method == "POST":
                        r = await client.post(action, data=data)
                    else:
                        r = await client.get(action, params=data)
                responses.append(r.status_code)
            except Exception:
                responses.append(0)

        await asyncio.gather(*[send_one() for _ in range(CONCURRENCY)])

        success_count = sum(1 for s in responses if s in (200, 201, 302))
        if success_count > 1:
            return Finding(
                title=f"Race Condition at {action}",
                severity="High",
                description=f"{success_count}/{CONCURRENCY} simultaneous requests succeeded — the operation is not atomic.",
                affected_url=action,
                proof=f"{method} {action} sent {CONCURRENCY}x concurrently\nSuccess responses: {success_count}\nStatus codes: {responses}",
                remediation="Use database-level locking (SELECT FOR UPDATE), atomic operations, or idempotency keys to prevent duplicate processing.",
                impact=4, likelihood=4,
                module="RaceConditions",
                references=["https://portswigger.net/web-security/race-conditions"],
            )
        return None
