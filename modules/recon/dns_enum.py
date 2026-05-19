import asyncio
import logging
import dns.resolver
import dns.exception
from core.finding import Finding

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


class DnsEnum:
    async def run(self, ctx: dict) -> dict:
        from urllib.parse import urlparse
        domain = urlparse(ctx["target_url"]).hostname
        logger.info(f"DNS enumeration: {domain}")
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                results[rtype] = [str(r) for r in answers]
                logger.debug(f"  {rtype}: {results[rtype]}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results[rtype] = []
            except Exception as e:
                logger.debug(f"  {rtype} error: {e}")
                results[rtype] = []

        ctx["recon"]["dns"] = results
        # Expose CNAMEs for takeover module
        ctx["recon"]["cnames"] = results.get("CNAME", [])
        return results
