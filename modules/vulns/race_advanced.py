"""
modules/vulns/race_advanced.py — AI-Targeted Race Condition Testing

Strategy:
  1. Identify financial / state-changing endpoints from context + URL patterns
  2. Fire 50 concurrent identical requests within a tight window (< 5ms)
  3. Detect double-spend / duplicate execution by comparing response counts
  4. Verify: legitimate requests should produce exactly ONE success response
"""
import asyncio
import logging
import re
import time
from collections import Counter
from urllib.parse import urlparse, parse_qs
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

# Endpoint patterns likely to be stateful / financial
RACE_PATTERNS = re.compile(
    r'(?:checkout|purchase|buy|order|pay|payment|transfer|withdraw|redeem|'
    r'coupon|discount|refund|vote|like|follow|subscribe|register|signup|'
    r'reset|confirm|verify|invite|claim|apply|submit|book|reserve)',
    re.IGNORECASE
)

# HTTP methods that mutate state
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Response fields that indicate success / value
SUCCESS_INDICATORS = [
    "success", "confirmed", "processed", "approved", "created",
    "order_id", "transaction_id", "payment_id", "booking_id",
    "balance", "credits", "points", "amount",
]

DUPLICATE_INDICATORS = [
    "already", "duplicate", "exists", "conflict", "used",
    "invalid", "expired", "exceeded", "limit",
]


def _is_race_candidate(ep: str, method: str = "GET") -> bool:
    return RACE_PATTERNS.search(ep) is not None


def _count_successes(responses: list) -> tuple[int, list]:
    """Return (success_count, unique_bodies)."""
    successes = []
    for r in responses:
        if r is None:
            continue
        status = getattr(r, "status_code", 0)
        body   = getattr(r, "text", "")
        body_l = body.lower()
        if status in (200, 201) and any(s in body_l for s in SUCCESS_INDICATORS):
            if not any(d in body_l for d in DUPLICATE_INDICATORS):
                successes.append(body[:300])
    return len(successes), list(set(successes))


class RaceAdvanced:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        forms     = ctx.get("forms", [])
        limiter   = ctx["limiter"]
        seen: set[str] = set()

        # Collect race candidates from endpoints + forms
        candidates = []

        for ep in endpoints:
            if _is_race_candidate(ep):
                candidates.append({"url": ep, "method": "GET", "data": None})

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            if _is_race_candidate(action) or method in MUTATING_METHODS:
                candidates.append({
                    "url":    action,
                    "method": method,
                    "data":   form.get("data", {}),
                })

        # Also check AI-suggested targets
        ai_targets = ctx.get("_ai_targets", [])
        for t in ai_targets:
            url = t.get("url", "") if isinstance(t, dict) else str(t)
            if url and url not in seen:
                candidates.append({"url": url, "method": "POST", "data": {}})

        if not candidates:
            logger.info("RaceAdvanced: no race candidates found")
            return findings

        logger.info(f"RaceAdvanced: testing {len(candidates)} candidate(s)")

        for cand in candidates[:10]:
            url = cand["url"]
            if url in seen:
                continue
            seen.add(url)

            f = await self._test_race(url, cand["method"], cand["data"], limiter)
            if f:
                findings.append(f)

        logger.info(f"RaceAdvanced completed — {len(findings)} finding(s)")
        return findings

    async def _test_race(self, url: str, method: str, data: dict | None, limiter) -> Finding | None:
        CONCURRENCY = 20
        GATE_SIZE   = 15  # requests released simultaneously

        try:
            # Warmup: single request to check it works at all
            async with make_client(timeout=PROBE_TIMEOUT) as c:
                if method == "GET":
                    warm = await c.get(url)
                else:
                    warm = await c.request(method, url, data=data or {})
            if warm.status_code >= 500:
                return None
            baseline_body = warm.text.lower()

            # If baseline already shows error/duplicate, skip
            if any(d in baseline_body for d in DUPLICATE_INDICATORS):
                return None

            # ── Gate-based race: prepare all requests, release simultaneously ──
            gate   = asyncio.Barrier(GATE_SIZE)
            results: list = [None] * CONCURRENCY

            async def _fire(i: int):
                try:
                    await gate.wait()  # all goroutines wait here then fire together
                    async with make_client(timeout=10) as c:
                        if method == "GET":
                            r = await c.get(url)
                        else:
                            r = await c.request(method, url, data=data or {})
                    results[i] = r
                except Exception as e:
                    logger.debug(f"race fire {i}: {e}")

            workers = [asyncio.create_task(_fire(i)) for i in range(CONCURRENCY)]
            t_start = time.monotonic()
            await asyncio.gather(*workers, return_exceptions=True)
            elapsed = time.monotonic() - t_start

            success_count, unique_bodies = _count_successes(results)

            logger.debug(
                f"RaceAdvanced {url}: {success_count}/{CONCURRENCY} successes "
                f"in {elapsed:.2f}s"
            )

            # Verdict: >= 2 successful responses where only 1 should exist → race condition
            if success_count >= 2:
                status_counts = Counter(
                    getattr(r, "status_code", 0) for r in results if r is not None
                )
                return Finding(
                    title=f"Race Condition: Duplicate Execution at {urlparse(url).path}",
                    severity="High",
                    description=(
                        f"Sending {CONCURRENCY} concurrent {method} requests to {url} "
                        f"produced {success_count} success responses. "
                        f"A properly implemented endpoint should accept the action exactly once. "
                        f"This may allow double-spend, coupon reuse, or duplicate order creation."
                    ),
                    affected_url=url,
                    proof=(
                        f"{method} {url} x{CONCURRENCY} concurrent\n"
                        f"Responses: {dict(status_counts)}\n"
                        f"Success count: {success_count}/{CONCURRENCY}\n"
                        f"Window: {elapsed:.2f}s\n"
                        f"Sample response: {(unique_bodies[0] if unique_bodies else '')[:200]}"
                    ),
                    remediation=(
                        "Implement idempotency keys (e.g., X-Idempotency-Key header). "
                        "Use database-level uniqueness constraints and optimistic locking. "
                        "Apply per-user rate limiting at the application layer."
                    ),
                    impact=4, likelihood=3, module="RaceAdvanced",
                    references=[
                        "https://portswigger.net/research/smashing-the-state-machine",
                        "https://owasp.org/www-community/attacks/Race_condition",
                    ],
                    cvss_score=7.5, cwe="CWE-362",
                )

        except AttributeError:
            # asyncio.Barrier is Python 3.11+; fall back to Event-based gate
            return await self._test_race_legacy(url, method, data, limiter)
        except Exception as e:
            logger.debug(f"RaceAdvanced {url}: {e}")
        return None

    async def _test_race_legacy(self, url: str, method: str, data: dict | None, limiter) -> Finding | None:
        """Fallback race tester using asyncio.Event as a start gate (Python < 3.11)."""
        CONCURRENCY = 20
        gate   = asyncio.Event()
        results: list = [None] * CONCURRENCY

        async def _fire(i: int):
            await gate.wait()
            try:
                async with make_client(timeout=10) as c:
                    if method == "GET":
                        r = await c.get(url)
                    else:
                        r = await c.request(method, url, data=data or {})
                results[i] = r
            except Exception:
                pass

        workers = [asyncio.create_task(_fire(i)) for i in range(CONCURRENCY)]
        await asyncio.sleep(0)   # let all tasks reach gate.wait()
        t_start = time.monotonic()
        gate.set()               # release all at once
        await asyncio.gather(*workers, return_exceptions=True)
        elapsed = time.monotonic() - t_start

        success_count, unique_bodies = _count_successes(results)
        if success_count >= 2:
            status_counts = Counter(
                getattr(r, "status_code", 0) for r in results if r is not None
            )
            return Finding(
                title=f"Race Condition: Duplicate Execution at {urlparse(url).path}",
                severity="High",
                description=(
                    f"Sending {CONCURRENCY} concurrent {method} requests to {url} "
                    f"produced {success_count} success responses where only 1 should occur."
                ),
                affected_url=url,
                proof=(
                    f"{method} {url} x{CONCURRENCY} concurrent\n"
                    f"Responses: {dict(status_counts)}\n"
                    f"Success count: {success_count}/{CONCURRENCY}\n"
                    f"Window: {elapsed:.2f}s"
                ),
                remediation=(
                    "Use idempotency keys, database-level uniqueness constraints, "
                    "and optimistic locking to prevent duplicate execution."
                ),
                impact=4, likelihood=3, module="RaceAdvanced",
                cvss_score=7.5, cwe="CWE-362",
            )
        return None
