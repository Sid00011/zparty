import logging
import whois
from core.finding import Finding

logger = logging.getLogger(__name__)


class WhoisLookup:
    async def run(self, ctx: dict) -> dict:
        url = ctx["target_url"]
        from urllib.parse import urlparse
        domain = urlparse(url).hostname
        logger.info(f"WHOIS lookup: {domain}")
        try:
            w = whois.whois(domain)
            data = {
                "domain": domain,
                "registrar": getattr(w, "registrar", None),
                "creation_date": str(getattr(w, "creation_date", None)),
                "expiration_date": str(getattr(w, "expiration_date", None)),
                "name_servers": getattr(w, "name_servers", []),
                "emails": getattr(w, "emails", []),
                "org": getattr(w, "org", None),
            }
            ctx["recon"]["whois"] = data
            return data
        except Exception as e:
            logger.warning(f"WHOIS failed: {e}")
            return {}
