import asyncio
import logging
import dns.resolver
from core.finding import Finding
from core.http_client import make_client

logger = logging.getLogger(__name__)

VULNERABLE_CNAME_FINGERPRINTS = {
    "github.io":            ("GitHub Pages", "There is no GitHub Pages site here"),
    "amazonaws.com":        ("AWS S3",        "NoSuchBucket"),
    "s3.amazonaws.com":     ("AWS S3",        "NoSuchBucket"),
    "cloudfront.net":       ("CloudFront",    "Bad request"),
    "heroku.com":           ("Heroku",        "No such app"),
    "herokudns.com":        ("Heroku",        "No such app"),
    "azurewebsites.net":    ("Azure",         "404 Web Site not found"),
    "azureedge.net":        ("Azure CDN",     ""),
    "netlify.com":          ("Netlify",       "Not found"),
    "fastly.net":           ("Fastly",        "Fastly error"),
    "wpengine.com":         ("WP Engine",     ""),
    "kinsta.com":           ("Kinsta",        ""),
    "bitbucket.io":         ("Bitbucket",     "Repository not found"),
    "surge.sh":             ("Surge.sh",      "project not found"),
    "readme.io":            ("ReadMe",        "project not found"),
    "zendesk.com":          ("Zendesk",       "Help Center Closed"),
    "helpscoutdocs.com":    ("HelpScout",     "No settings were found"),
    "shopify.com":          ("Shopify",       "Sorry, this shop is currently unavailable"),
    "unbouncepages.com":    ("Unbounce",      "The requested URL was not found"),
    "fly.dev":              ("Fly.io",        ""),
    "render.com":           ("Render",        ""),
}


class SubdomainTakeover:
    async def run(self, ctx: dict) -> list[Finding]:
        findings = []
        cnames = ctx.get("recon", {}).get("cnames", [])
        subdomains = ctx.get("subdomains", [])
        limiter = ctx["limiter"]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5

        all_cnames = list(cnames)

        for sub in subdomains[:100]:
            try:
                answers = await asyncio.to_thread(resolver.resolve, sub, "CNAME")
                for ans in answers:
                    all_cnames.append((sub, str(ans)))
            except Exception:
                pass

        for entry in all_cnames:
            if isinstance(entry, tuple):
                sub, cname_target = entry
            else:
                sub, cname_target = entry, entry

            cname_target = cname_target.rstrip(".")

            for service_domain, (service_name, fingerprint) in VULNERABLE_CNAME_FINGERPRINTS.items():
                if service_domain in cname_target:
                    f = await self._verify_takeover(sub, cname_target, service_name, fingerprint, limiter)
                    if f:
                        findings.append(f)
                    break

        return findings

    async def _verify_takeover(self, subdomain: str, cname: str, service: str,
                                fingerprint: str, limiter) -> Finding | None:
        probe = f"https://{subdomain}" if not subdomain.startswith("http") else subdomain
        try:
            async with limiter.acquire():
                async with make_client() as client:
                    r = await client.get(probe)

            if (fingerprint and fingerprint.lower() in r.text.lower()) or r.status_code == 404:
                return Finding(
                    title=f"Subdomain Takeover: {subdomain} → {service}",
                    severity="High",
                    description=f"{subdomain} has a CNAME pointing to {cname} ({service}), which appears unclaimed.",
                    affected_url=probe,
                    proof=f"CNAME: {subdomain} → {cname}\nHTTP {r.status_code}\nFingerprint: '{fingerprint}' in body",
                    remediation=f"Remove the dangling DNS CNAME for {subdomain}, or claim the {service} resource it points to.",
                    impact=4, likelihood=4,
                    module="SubdomainTakeover",
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                )
        except Exception as e:
            logger.debug(f"Takeover verify error {subdomain}: {e}")
        return None
