import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse
from core.http_client import make_client

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (r'AIza[0-9A-Za-z_-]{35}',       "Google API Key"),
    (r'AKIA[0-9A-Z]{16}',            "AWS Access Key"),
    (r'sk-[a-zA-Z0-9]{32,}',        "OpenAI/Stripe Secret Key"),
    (r'ghp_[a-zA-Z0-9]{36}',        "GitHub PAT"),
    (r'xox[baprs]-[0-9A-Za-z\-]+',  "Slack Token"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key"),
    (r'password\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded Password"),
    (r'api[_-]?key\s*[:=]\s*["\'][^"\']{8,}["\']', "API Key"),
    (r'/api/v\d+/[a-z_/]+admin',    "Internal Admin Endpoint"),
]

JS_RE = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)


class JsAnalysis:
    async def run(self, ctx: dict) -> dict:
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        logger.info(f"JS analysis: {url}")

        js_urls = set()
        secrets = []
        endpoints = []

        try:
            async with limiter.acquire():
                async with make_client() as client:
                    r = await client.get(url)
                    body = r.text

            for match in JS_RE.finditer(body):
                src = match.group(1)
                js_urls.add(urljoin(url, src))

            async def analyze_js(js_url: str):
                try:
                    async with limiter.acquire():
                        async with make_client() as client:
                            resp = await client.get(js_url)
                    content = resp.text
                    for pattern, label in SECRET_PATTERNS:
                        for hit in re.findall(pattern, content):
                            secrets.append({
                                "file": js_url,
                                "type": label,
                                "snippet": hit[:80],
                            })
                            logger.warning(f"Potential secret [{label}] in {js_url}")

                    for ep in re.findall(r'["\']/(api/[^\s"\']+)["\']', content):
                        endpoints.append(urljoin(url, "/" + ep))

                    if resp.headers.get("sourcemap") or ".js.map" in content:
                        secrets.append({"file": js_url, "type": "Source Map Exposed", "snippet": ""})
                except Exception as e:
                    logger.debug(f"JS fetch failed {js_url}: {e}")

            await asyncio.gather(*[analyze_js(u) for u in list(js_urls)[:30]])

        except Exception as e:
            logger.warning(f"JS analysis error: {type(e).__name__}: {e}")

        result = {
            "js_files": list(js_urls),
            "secrets_found": secrets,
            "api_endpoints": list(set(endpoints)),
        }
        ctx["recon"]["js"] = result
        ctx["endpoints"].extend(result["api_endpoints"])
        return result
