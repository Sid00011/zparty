import ssl
import socket
import logging
from datetime import datetime
from urllib.parse import urlparse
from core.finding import Finding

logger = logging.getLogger(__name__)


class SslAnalysis:
    async def run(self, ctx: dict) -> dict:
        import asyncio
        url = ctx["target_url"]
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            logger.info("Target is not HTTPS — skipping SSL analysis")
            return {"skipped": True, "reason": "not HTTPS"}

        logger.info(f"SSL analysis: {host}:{port}")
        result = {}

        try:
            ctx_ssl = ssl.create_default_context()
            conn = await asyncio.to_thread(self._get_cert, host, port, ctx_ssl)
            result = conn
        except Exception as e:
            logger.warning(f"SSL analysis failed: {e}")
            result = {"error": str(e)}

        ctx["recon"]["ssl"] = result
        return result

    def _get_cert(self, host: str, port: int, ctx_ssl) -> dict:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

        not_after = cert.get("notAfter", "")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
        days_left = (expiry - datetime.utcnow()).days if expiry else None

        sans = []
        for field_type, value in cert.get("subjectAltName", []):
            if field_type == "DNS":
                sans.append(value)

        issuer = dict(x[0] for x in cert.get("issuer", []))

        return {
            "tls_version": version,
            "issuer": issuer,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "not_after": not_after,
            "days_until_expiry": days_left,
            "sans": sans,
            "self_signed": issuer == dict(x[0] for x in cert.get("subject", [])),
            "deprecated_tls": version in ("TLSv1", "TLSv1.1"),
        }
