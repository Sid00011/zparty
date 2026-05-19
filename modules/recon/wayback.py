import logging
import httpx
from core.http_client import make_client

logger = logging.getLogger(__name__)

CDX_API = "http://web.archive.org/cdx/search/cdx"


class WaybackMiner:
    async def run(self, ctx: dict) -> dict:
        from urllib.parse import urlparse
        domain = urlparse(ctx["target_url"]).hostname
        limiter = ctx["limiter"]
        logger.info(f"Wayback mining: {domain}")

        urls = []
        interesting = []
        wayback_timeout = httpx.Timeout(connect=10.0, read=20.0, write=8.0, pool=5.0)
        try:
            async with limiter.acquire():
                async with make_client(timeout=wayback_timeout) as client:
                    r = await client.get(CDX_API, params={
                        "url": f"{domain}/*",
                        "output": "json",
                        "fl": "original,statuscode,mimetype",
                        "collapse": "urlkey",
                        "limit": "2000",
                    })

            if r.status_code == 200:
                rows = r.json()
                for row in rows[1:]:
                    original, status, mime = row[0], row[1], row[2]
                    urls.append(original)
                    low = original.lower()
                    if any(x in low for x in [".env", ".git", "backup", "config",
                                               "api/v0", "api/v1", ".sql", ".zip", ".tar"]):
                        interesting.append({"url": original, "status": status, "mime": mime})

        except Exception as e:
            logger.warning(f"Wayback API error: {type(e).__name__}: {e}")

        result = {
            "total_archived": len(urls),
            "interesting_artifacts": interesting,
            "sample_urls": urls[:100],
        }
        ctx["recon"]["wayback"] = result
        ctx["endpoints"].extend([x["url"] for x in interesting])
        return result
