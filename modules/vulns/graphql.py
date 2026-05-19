import asyncio
import logging
import json
import time
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]

INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } types { name fields { name } } } }"}

DEPTH_ATTACK = {"query": "{ __typename " + "user { " * 15 + "__typename " + "}" * 15 + " }"}

BATCH_LOGIN = [{"query": 'mutation { login(username: "admin", password: "test") { token } }'}] * 100


class GraphQL:
    async def run(self, ctx: dict) -> list[Finding]:
        findings = []
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        endpoints = ctx.get("endpoints", [])

        gql_endpoints = list(set(
            [f"{url.rstrip('/')}{p}" for p in GRAPHQL_PATHS] +
            [ep for ep in endpoints if "graph" in ep.lower() or "gql" in ep.lower()]
        ))

        for ep in gql_endpoints:
            ep_findings = await self._test_endpoint(ep, limiter)
            findings.extend(ep_findings)

        return findings

    async def _test_endpoint(self, url: str, limiter) -> list[Finding]:
        findings = []

        try:
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT) as client:
                    r = await client.post(url,
                        json=INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"})
            if r.status_code == 200 and "__schema" in r.text:
                findings.append(Finding(
                    title="GraphQL Introspection Enabled",
                    severity="Medium",
                    description="GraphQL introspection is enabled, exposing the full API schema to unauthenticated clients.",
                    affected_url=url,
                    proof=f"POST {url}\n{json.dumps(INTROSPECTION_QUERY)}\nHTTP {r.status_code}\n{r.text[:400]}",
                    remediation="Disable introspection in production. Use query allow-listing.",
                    impact=2, likelihood=5,
                    module="GraphQL",
                    references=["https://graphql.org/learn/introspection/"],
                ))

                await self._test_depth(url, limiter, findings)
                await self._test_batching(url, limiter, findings)

        except Exception as e:
            logger.debug(f"GraphQL probe {url}: {e}")

        return findings

    async def _test_depth(self, url: str, limiter, findings: list) -> None:
        try:
            import httpx as _httpx
            deep_timeout = _httpx.Timeout(connect=8.0, read=30.0, write=8.0, pool=5.0)
            async with limiter.acquire():
                async with make_client(timeout=deep_timeout) as client:
                    start = time.monotonic()
                    r = await client.post(url,
                        json=DEPTH_ATTACK,
                        headers={"Content-Type": "application/json"})
                    elapsed = time.monotonic() - start

            if elapsed > 5 or r.status_code == 500:
                findings.append(Finding(
                    title="GraphQL Query Depth Attack — No Depth Limit",
                    severity="High",
                    description=f"Deeply nested GraphQL query caused {elapsed:.1f}s delay or server error (HTTP {r.status_code}).",
                    affected_url=url,
                    proof=f"POST {url}\nDepth=15 nested query\nHTTP {r.status_code}, {elapsed:.1f}s",
                    remediation="Implement query depth limiting (max depth 10). Use graphql-depth-limit or equivalent.",
                    impact=3, likelihood=4,
                    module="GraphQL",
                ))
        except Exception:
            pass

    async def _test_batching(self, url: str, limiter, findings: list) -> None:
        try:
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT) as client:
                    r = await client.post(url,
                        json=BATCH_LOGIN,
                        headers={"Content-Type": "application/json"})
            if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                findings.append(Finding(
                    title="GraphQL Query Batching Allows Rate-Limit Bypass",
                    severity="High",
                    description="100 login mutations were accepted as a single batched request, bypassing per-request rate limits.",
                    affected_url=url,
                    proof=f"POST {url}\n100-item mutation batch\nHTTP {r.status_code}\n{len(r.json())} responses returned",
                    remediation="Disable or limit query batching. Implement per-operation rate limiting.",
                    impact=4, likelihood=3,
                    module="GraphQL",
                ))
        except Exception:
            pass
