import logging
from core.finding import Finding
from core.http_client import make_client

logger = logging.getLogger(__name__)

WAF_SIGNATURES = {
    "Cloudflare":    [("cf-ray", None), (None, "cloudflare")],
    "AWS WAF":       [(None, "awswaf"), ("x-amzn-requestid", None)],
    "Akamai":        [("x-check-cacheable", None), (None, "akamai")],
    "F5 BIG-IP":     [("x-cnection", None), (None, "bigip")],
    "Sucuri":        [("x-sucuri-id", None), (None, "sucuri")],
    "ModSecurity":   [(None, "mod_security"), (None, "modsecurity")],
    "Barracuda":     [(None, "barracuda"), ("barra_counter_session", None)],
    "Imperva":       [("x-iinfo", None), (None, "imperva")],
}

MALICIOUS_PROBE = "<script>alert(1)</script>' OR 1=1--"


class WafDetection:
    async def run(self, ctx: dict) -> dict:
        url = ctx["target_url"]
        limiter = ctx["limiter"]
        logger.info(f"WAF detection: {url}")
        result = {"detected": False, "waf": None, "evidence": ""}

        try:
            async with limiter.acquire():
                async with make_client() as client:
                    normal = await client.get(url)

            probe_url = f"{url}?q={MALICIOUS_PROBE}"
            async with limiter.acquire():
                async with make_client() as client:
                    probe = await client.get(probe_url)

            if probe.status_code in (403, 406, 429, 503) and normal.status_code < 400:
                result["detected"] = True
                result["block_status"] = probe.status_code

            all_headers = {k.lower(): v.lower() for k, v in probe.headers.items()}
            body = probe.text.lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                for header_key, body_pattern in sigs:
                    if header_key and header_key.lower() in all_headers:
                        result["waf"] = waf_name
                        result["evidence"] = f"Header: {header_key}"
                        result["detected"] = True
                        break
                    if body_pattern and body_pattern.lower() in body:
                        result["waf"] = waf_name
                        result["evidence"] = f"Body pattern: {body_pattern}"
                        result["detected"] = True
                        break
                if result.get("waf"):
                    break

        except Exception as e:
            logger.warning(f"WAF detection error: {type(e).__name__}: {e}")

        ctx["scan"]["waf"] = result
        if result["detected"]:
            logger.info(f"WAF detected: {result.get('waf', 'unknown')}")
        return result
