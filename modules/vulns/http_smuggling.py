import asyncio
import logging
import socket
import time
from core.finding import Finding

logger = logging.getLogger(__name__)

CANARY = "ZPARTY-SMUGGLE-PROBE"


class HttpSmuggling:
    async def run(self, ctx: dict) -> list[Finding]:
        url = ctx["target_url"]
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"

        findings = []
        logger.info(f"HTTP Smuggling probe: {host}:{port}")

        for variant, payload in self._build_payloads(host, path):
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(self._send_raw, host, port, use_tls, payload),
                    timeout=15,
                )
                if CANARY in result or "400" in result[:50]:
                    if self._is_suspicious(result, variant):
                        findings.append(Finding(
                            title=f"Possible HTTP Request Smuggling ({variant})",
                            severity="High",
                            description=f"Server shows signs of HTTP request smuggling ({variant} variant). The smuggled prefix appeared in a follow-up response.",
                            affected_url=url,
                            proof=f"Variant: {variant}\nResponse snippet: {result[:300]}",
                            remediation="Ensure frontend and backend agree on one transfer encoding. Disable chunked encoding on the edge if not needed. Update reverse proxy.",
                            impact=5, likelihood=3,
                            module="HttpSmuggling",
                            references=["https://portswigger.net/web-security/request-smuggling"],
                        ))
            except asyncio.TimeoutError:
                logger.debug(f"Smuggling probe {variant} timed out")
            except Exception as e:
                logger.debug(f"Smuggling {variant} error: {e}")

        return findings

    def _build_payloads(self, host: str, path: str) -> list[tuple[str, bytes]]:
        # CL.TE variant
        cl_te = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(CANARY) + 6}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"0\r\n\r\n"
            f"GET /{CANARY} HTTP/1.1\r\n\r\n"
        ).encode()

        # TE.CL variant
        te_cl = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"{len(CANARY):x}\r\n{CANARY}\r\n0\r\n\r\n"
        ).encode()

        return [("CL.TE", cl_te), ("TE.CL", te_cl)]

    def _send_raw(self, host: str, port: int, use_tls: bool, payload: bytes) -> str:
        sock = socket.create_connection((host, port), timeout=10)
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        try:
            sock.sendall(payload)
            time.sleep(2)
            data = b""
            sock.settimeout(3)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        finally:
            sock.close()
        return data.decode(errors="replace")

    def _is_suspicious(self, response: str, variant: str) -> bool:
        return CANARY in response or ("400" in response[:30] and variant == "CL.TE")
