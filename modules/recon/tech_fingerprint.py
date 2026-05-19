import logging
from core.http_client import make_client

logger = logging.getLogger(__name__)

FRAMEWORKS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java/Tomcat",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "rack.session": "Ruby/Rack",
    "_rails": "Ruby on Rails",
    "ASP.NET_SessionId": "ASP.NET",
}

SERVER_SIGNATURES = {
    "Apache": "Apache",
    "nginx": "nginx",
    "Microsoft-IIS": "IIS",
    "LiteSpeed": "LiteSpeed",
    "cloudflare": "Cloudflare",
}


class TechFingerprint:
    async def run(self, ctx: dict) -> dict:
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        logger.info(f"Tech fingerprint: {url}")

        stack = {
            "web_server": None,
            "backend": None,
            "cms": None,
            "frameworks": [],
            "powered_by": None,
            "cookies": [],
            "headers": {},
        }

        try:
            async with limiter.acquire():
                async with make_client() as client:
                    r = await client.get(url)

            headers = dict(r.headers)
            stack["headers"] = headers

            server = headers.get("server", "")
            for sig, name in SERVER_SIGNATURES.items():
                if sig.lower() in server.lower():
                    stack["web_server"] = name
                    break

            powered = headers.get("x-powered-by", "")
            if powered:
                stack["powered_by"] = powered

            cookies = [c for c in headers.get("set-cookie", "").split(";") if c]
            stack["cookies"] = cookies
            for cookie_name, framework in FRAMEWORKS.items():
                if any(cookie_name.lower() in c.lower() for c in cookies):
                    stack["frameworks"].append(framework)

            body = r.text
            if "wp-content" in body or "wp-includes" in body:
                stack["cms"] = "WordPress"
            elif "Drupal.settings" in body or "/sites/default/files" in body:
                stack["cms"] = "Drupal"
            elif "Joomla" in body:
                stack["cms"] = "Joomla"
            elif "/typo3/" in body:
                stack["cms"] = "TYPO3"

        except Exception as e:
            logger.warning(f"Tech fingerprint error: {type(e).__name__}: {e}")

        ctx["recon"]["tech"] = stack
        return stack
