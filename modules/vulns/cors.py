import asyncio
import logging
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

EVIL_ORIGIN = "https://evil.zparty-test.com"


class CorsCheck:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = list(set([ctx["target_url"]] + ctx.get("endpoints", [])))[:60]
        limiter = ctx["limiter"]
        sem = asyncio.Semaphore(10)

        async def probe(url: str):
            async with sem:
                try:
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await c.get(url, headers={"Origin": EVIL_ORIGIN})
                    acao = r.headers.get("access-control-allow-origin", "")
                    acac = r.headers.get("access-control-allow-credentials", "")

                    if acao == "*" and acac.lower() == "true":
                        findings.append(Finding(
                            title="CORS: Wildcard + Credentials Allowed",
                            severity="Critical",
                            description="Server responds with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true — any origin can make credentialed cross-origin requests.",
                            affected_url=url,
                            proof=f"Origin: {EVIL_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            remediation="Never combine ACAO: * with ACAC: true. Explicitly whitelist trusted origins.",
                            impact=5, likelihood=4, module="CorsCheck",
                            references=["https://portswigger.net/web-security/cors"],
                        ))
                    elif acao == EVIL_ORIGIN:
                        sev = "Critical" if acac.lower() == "true" else "High"
                        findings.append(Finding(
                            title="CORS: Arbitrary Origin Reflected" + (" with Credentials" if acac.lower() == "true" else ""),
                            severity=sev,
                            description=f"Server reflects the attacker-controlled Origin ({EVIL_ORIGIN}) in ACAO header{'with credentials allowed' if acac.lower() == 'true' else ''}.",
                            affected_url=url,
                            proof=f"Origin: {EVIL_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            remediation="Validate the Origin header against a strict server-side whitelist. Do not reflect arbitrary origins.",
                            impact=5 if acac.lower() == "true" else 4,
                            likelihood=4, module="CorsCheck",
                        ))
                except Exception as e:
                    logger.debug(f"CORS probe {url}: {type(e).__name__}: {e}")

        await asyncio.gather(*[probe(u) for u in endpoints])
        logger.info(f"CorsCheck completed — {len(findings)} finding(s)")
        return findings
