"""
core/tor_proxy.py — Tor anonymity integration

Manages a Tor daemon for anonymous scanning:
  - Auto-detects or starts a Tor process
  - Routes all HTTP traffic through SOCKS5 on 127.0.0.1:9050
  - Rotates Tor exit node (new IP) via NEWNYM signal:
      * between every vuln module  → different IP per module
      * every N requests           → continuous rotation
  - Auto-downloads Tor Expert Bundle on Windows if not installed
  - Graceful fallback if Tor is unavailable — scan continues without it

Tor exit nodes are public knowledge, so this is not perfect stealth
against services that block Tor. Against everything else: new IP
per module means your real IP never touches the target.

Requires:  pip install stem
Tor:       apt install tor  |  brew install tor  |  auto-downloaded on Windows
"""
import asyncio
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
TOR_SOCKS_HOST  = "127.0.0.1"
TOR_SOCKS_PORT  = 9050
TOR_CONTROL_PORT = 9051
TOR_PROXY_URL   = f"socks5://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"

_BIN_DIR = Path(__file__).parent.parent / "bin"

# Windows Tor Expert Bundle — minimal tor binary, no browser
_TOR_WIN_VERSION = "15.0.13"
_TOR_WIN_URL = (
    f"https://dist.torproject.org/torbrowser/{_TOR_WIN_VERSION}/"
    f"tor-expert-bundle-windows-x86_64-{_TOR_WIN_VERSION}.tar.gz"
)


# ── stem availability ─────────────────────────────────────────────────────────
_STEM_AVAILABLE = False
try:
    import stem
    from stem import Signal
    from stem.control import Controller
    _STEM_AVAILABLE = True
except ImportError:
    pass


# ── Binary location ───────────────────────────────────────────────────────────

def _find_tor() -> str | None:
    """Return path to tor binary or None."""
    # 1. System PATH
    found = shutil.which("tor")
    if found:
        return found
    # 2. Project bin/
    _BIN_DIR.mkdir(parents=True, exist_ok=True)
    candidates = [
        _BIN_DIR / "tor" / "tor" / "tor.exe",   # extracted bundle: bin/tor/tor/tor.exe
        _BIN_DIR / "tor" / "tor.exe",            # flat layout
        _BIN_DIR / "tor.exe",                    # directly in bin/
        _BIN_DIR / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        _BIN_DIR / "tor" / "tor" / "tor",        # Linux/macOS
        _BIN_DIR / "tor" / "tor",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return str(c)
    return None


async def _download_tor_windows() -> str | None:
    """Download Tor Expert Bundle for Windows into bin/tor/."""
    import tarfile
    import urllib.request

    dest_dir = _BIN_DIR / "tor"
    dest_dir.mkdir(parents=True, exist_ok=True)
    tar_path = _BIN_DIR / "tor-bundle.tar.gz"

    logger.info(f"Downloading Tor Expert Bundle {_TOR_WIN_VERSION} ...")
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: urllib.request.urlretrieve(_TOR_WIN_URL, str(tar_path))
        )
        with tarfile.open(str(tar_path), "r:gz") as tf:
            tf.extractall(str(dest_dir))
        tar_path.unlink(missing_ok=True)

        # Find tor.exe inside the extracted layout
        for root, _, files in os.walk(str(dest_dir)):
            for f in files:
                if f.lower() == "tor.exe":
                    found = os.path.join(root, f)
                    logger.info(f"Tor downloaded: {found}")
                    return found

        logger.warning("Tor extracted but tor.exe not found inside archive")
        return None
    except Exception as e:
        logger.warning(f"Tor download failed: {e}")
        tar_path.unlink(missing_ok=True)
        return None


# ── TorManager ────────────────────────────────────────────────────────────────

class TorManager:
    """
    Lifecycle manager for a Tor daemon used during scanning.

    Usage:
        tor = TorManager(cfg)
        await tor.start()
        # all requests now route through SOCKS5 9050
        await tor.rotate()   # new exit node = new IP
        await tor.stop()
    """

    def __init__(self, cfg: dict):
        tor_cfg            = cfg.get("tor", {})
        self.enabled       = tor_cfg.get("enabled", False)
        self.auto_start    = tor_cfg.get("auto_start", True)
        self.socks_port    = int(tor_cfg.get("socks_port", TOR_SOCKS_PORT))
        self.control_port  = int(tor_cfg.get("control_port", TOR_CONTROL_PORT))
        self.control_pass  = tor_cfg.get("control_password", "")
        self.rotate_every  = int(tor_cfg.get("rotate_every", 10))  # requests
        self.rotate_between_modules = tor_cfg.get("rotate_between_modules", True)

        self._proc: subprocess.Popen | None = None
        self._started_by_us = False
        self._request_count = 0
        self._active = False
        self._lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def proxy_url(self) -> str:
        return f"socks5://{TOR_SOCKS_HOST}:{self.socks_port}"

    # ── Start ─────────────────────────────────────────────────────────────────

    async def start(self) -> bool:
        """
        Start Tor if not already running.
        Returns True if Tor is ready to use.
        """
        if not self.enabled:
            return False

        # Already listening?
        if self._port_open(self.socks_port):
            logger.info(f"Tor already running on :{self.socks_port}")
            self._active = True
            return True

        if not self.auto_start:
            logger.warning("Tor not running and auto_start=false — anonymity disabled")
            return False

        # Find or download binary
        tor_bin = _find_tor()
        if not tor_bin and platform.system() == "Windows":
            logger.info("Tor not found — downloading Expert Bundle ...")
            tor_bin = await _download_tor_windows()
        if not tor_bin:
            logger.warning(
                "Tor binary not found. Install with:\n"
                "  Linux:  sudo apt install tor\n"
                "  macOS:  brew install tor\n"
                "  Windows: auto-download will retry on next scan"
            )
            return False

        # Write a minimal torrc
        torrc = _BIN_DIR / "torrc"
        torrc.write_text(
            f"SocksPort {self.socks_port}\n"
            f"ControlPort {self.control_port}\n"
            f"CookieAuthentication 0\n"
            f"HashedControlPassword \"\"\n"
            f"DataDirectory {_BIN_DIR / 'tor_data'}\n"
            f"Log notice stderr\n",
            encoding="utf-8",
        )
        (_BIN_DIR / "tor_data").mkdir(parents=True, exist_ok=True)

        logger.info(f"Starting Tor daemon ({tor_bin}) ...")
        try:
            self._proc = subprocess.Popen(
                [tor_bin, "-f", str(torrc)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._started_by_us = True
        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
            return False

        # Wait for SOCKS port to open (up to 30 s)
        for i in range(30):
            await asyncio.sleep(1)
            if self._port_open(self.socks_port):
                logger.info(f"Tor ready on :{self.socks_port} (took {i+1}s)")
                self._active = True
                return True

        logger.warning("Tor started but SOCKS port didn't open in 30s")
        return False

    # ── Stop ──────────────────────────────────────────────────────────────────

    async def stop(self) -> None:
        """Stop the Tor process we started (does not stop a pre-existing Tor)."""
        self._active = False
        if self._proc and self._started_by_us:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
                logger.info("Tor daemon stopped")
            except Exception as e:
                logger.debug(f"Tor stop: {e}")
            self._proc = None

    # ── Rotate identity ───────────────────────────────────────────────────────

    async def rotate(self) -> bool:
        """
        Send NEWNYM signal to Tor — get a new circuit and new exit node IP.
        Requires stem: pip install stem
        Waits 2s for new circuit to establish.
        Returns True on success.
        """
        if not self._active:
            return False

        if not _STEM_AVAILABLE:
            logger.debug("stem not installed — cannot rotate Tor identity (pip install stem)")
            return False

        async with self._lock:
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, self._send_newnym)
                if result:
                    logger.info("Tor identity rotated — new exit node")
                    await asyncio.sleep(2)  # let new circuit establish
                return result
            except Exception as e:
                logger.debug(f"Tor rotate failed: {e}")
                return False

    def _send_newnym(self) -> bool:
        """Blocking NEWNYM — run in executor."""
        try:
            with Controller.from_port(port=self.control_port) as ctrl:
                ctrl.authenticate(password=self.control_pass)
                ctrl.signal(Signal.NEWNYM)
            return True
        except Exception as e:
            logger.debug(f"NEWNYM error: {e}")
            return False

    # ── Per-request counter ───────────────────────────────────────────────────

    async def on_request(self) -> None:
        """
        Call this on each request. Auto-rotates every `rotate_every` requests.
        """
        if not self._active or self.rotate_every <= 0:
            return
        self._request_count += 1
        if self._request_count % self.rotate_every == 0:
            asyncio.create_task(self.rotate())

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _port_open(port: int) -> bool:
        try:
            with socket.create_connection((TOR_SOCKS_HOST, port), timeout=1):
                return True
        except OSError:
            return False

    async def get_current_ip(self) -> str | None:
        """
        Check what IP Tor is currently presenting to the outside world.
        Queries https://check.torproject.org/api/ip via Tor.
        """
        if not self._active:
            return None
        try:
            import httpx
            async with httpx.AsyncClient(
                proxy=self.proxy_url,
                timeout=httpx.Timeout(10),
                verify=False,
            ) as c:
                r = await c.get("https://check.torproject.org/api/ip")
                data = r.json()
                ip = data.get("IP")
                is_tor = data.get("IsTor", False)
                logger.info(f"Current exit IP: {ip} (IsTor={is_tor})")
                return ip
        except Exception as e:
            logger.debug(f"IP check failed: {e}")
            return None


# ── Global instance ───────────────────────────────────────────────────────────
_tor: TorManager | None = None


def get_tor() -> TorManager | None:
    return _tor


def init_tor(cfg: dict) -> TorManager:
    global _tor
    _tor = TorManager(cfg)
    return _tor
