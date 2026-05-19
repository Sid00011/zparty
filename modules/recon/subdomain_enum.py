import asyncio
import logging
import dns.resolver
import dns.exception
from pathlib import Path
from core.http_client import make_client

logger = logging.getLogger(__name__)


class SubdomainEnum:
    async def run(self, ctx: dict) -> dict:
        from urllib.parse import urlparse
        domain = urlparse(ctx["target_url"]).hostname
        cfg = ctx["config"]
        limiter = ctx["limiter"]

        discovered = set()

        crt_subs = await self._crtsh(domain, limiter)
        discovered.update(crt_subs)

        wordlist_path = cfg.get("wordlists", {}).get("subdomains", "")
        if wordlist_path and Path(wordlist_path).exists():
            brute_subs = await self._bruteforce(domain, wordlist_path)
            discovered.update(brute_subs)
        else:
            logger.warning(f"Subdomain wordlist not found: {wordlist_path}")

        live = list(discovered)
        ctx["subdomains"] = live
        ctx["recon"]["subdomains"] = live
        logger.info(f"Found {len(live)} subdomains")
        return {"subdomains": live}

    async def _crtsh(self, domain: str, limiter) -> set:
        subs = set()
        try:
            async with limiter.acquire():
                async with make_client() as client:
                    r = await client.get(
                        "https://crt.sh/",
                        params={"q": f"%.{domain}", "output": "json"},
                    )
            if r.status_code == 200:
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for line in name.splitlines():
                        line = line.strip().lstrip("*.")
                        if line.endswith(domain):
                            subs.add(line)
        except Exception as e:
            logger.warning(f"crt.sh failed: {e}")
        return subs

    async def _bruteforce(self, domain: str, wordlist: str) -> set:
        discovered = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3

        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

        async def check(word: str):
            fqdn = f"{word}.{domain}"
            try:
                await asyncio.to_thread(resolver.resolve, fqdn, "A")
                discovered.add(fqdn)
                logger.debug(f"Subdomain found: {fqdn}")
            except Exception:
                pass

        # Cap at 20 — asyncio.to_thread is limited by the OS thread pool (~8-16 threads);
        # a higher semaphore doesn't add concurrency, just queues more work.
        sem = asyncio.Semaphore(20)

        async def guarded(word):
            async with sem:
                await check(word)

        await asyncio.gather(*[guarded(w) for w in words[:5000]])
        return discovered
