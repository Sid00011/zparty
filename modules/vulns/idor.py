import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT

logger = logging.getLogger(__name__)

ID_PARAMS = {"id", "user_id", "account", "userid", "uid", "order", "order_id",
             "invoice", "profile", "doc_id", "file_id", "record", "item", "item_id"}


class Idor:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        limiter = ctx["limiter"]
        sem = asyncio.Semaphore(10)

        async def probe(url: str):
            parsed = urlparse(url)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            async with sem:
                for param, vals in params.items():
                    if param.lower() not in ID_PARAMS:
                        continue
                    val = vals[0]
                    if not val.isdigit():
                        continue
                    original_id = int(val)

                    try:
                        async with limiter.acquire():
                            async with make_client(timeout=PROBE_TIMEOUT) as c:
                                r_orig = await c.get(url)
                        if r_orig.status_code not in (200, 206):
                            continue
                        orig_len = len(r_orig.text)

                        for alt_id in [original_id - 1, original_id + 1, original_id + 100]:
                            if alt_id <= 0:
                                continue
                            p = dict(params)
                            p[param] = [str(alt_id)]
                            alt_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()

                            async with limiter.acquire():
                                async with make_client(timeout=PROBE_TIMEOUT) as c:
                                    r_alt = await c.get(alt_url)

                            if (r_alt.status_code == 200
                                    and len(r_alt.text) > 100
                                    and abs(len(r_alt.text) - orig_len) > 50):
                                findings.append(Finding(
                                    title=f"Possible IDOR via '{param}' parameter",
                                    severity="High",
                                    description=f"Changing '{param}' from {original_id} to {alt_id} returns a different 200 response ({len(r_alt.text)} vs {orig_len} bytes), suggesting objects are accessible without ownership check.",
                                    affected_url=alt_url,
                                    proof=f"Original: GET {url} → {orig_len} bytes\nModified: GET {alt_url} → {len(r_alt.text)} bytes\nHTTP {r_alt.status_code}",
                                    remediation="Enforce object-level authorization on every resource endpoint. Verify the authenticated user owns the requested resource before returning it.",
                                    impact=4, likelihood=3, module="Idor",
                                    references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
                                ))
                                return
                    except Exception as e:
                        logger.debug(f"IDOR probe {url}: {type(e).__name__}: {e}")

        await asyncio.gather(*[probe(u) for u in endpoints[:100]])
        logger.info(f"Idor completed — {len(findings)} finding(s)")
        return findings
