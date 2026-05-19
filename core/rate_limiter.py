"""
core/rate_limiter.py
Non-serialising concurrent rate limiter.

The OLD design had a global asyncio.Lock() inside the semaphore which forced every
request — across all 16 concurrent vuln modules — to queue single-file.  With
delay=0.2 s that capped real throughput at 5 req/s total, guaranteeing every module
timed out on any target with more than ~20 endpoints.

NEW design: the semaphore caps concurrency (how many HTTP requests can be in-flight
at once); each slot sleeps a small fixed delay independently so we're polite to the
target server but we don't serialize.  With max_concurrent=30 and delay=0.05 s the
effective rate is ~30/0.55 ≈ 54 req/s on a 0.5 s server — plenty for 120 s budgets.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Semaphore-based concurrency limiter with a per-slot polite delay.

    max_concurrent  — maximum simultaneous in-flight HTTP requests
    delay           — seconds each slot sleeps before firing the request
                      (keeps the target from seeing a burst)
    """

    def __init__(self, requests_per_second: float, max_concurrent: int, delay: float):
        self.rps = requests_per_second
        self.delay = delay
        self._semaphore = asyncio.Semaphore(max_concurrent)
        # No global lock — concurrent coroutines each sleep delay independently

    @asynccontextmanager
    async def acquire(self):
        async with self._semaphore:
            if self.delay > 0:
                await asyncio.sleep(self.delay)
            yield

    @classmethod
    def from_config(cls, cfg: dict) -> "RateLimiter":
        rl_cfg = cfg.get("rate_limit", {})
        return cls(
            requests_per_second=rl_cfg.get("requests_per_second", 20),
            max_concurrent=rl_cfg.get("max_concurrent_threads", 30),
            delay=rl_cfg.get("delay_between_requests", 0.05),
        )
