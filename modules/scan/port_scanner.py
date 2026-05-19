import asyncio
import logging
import shutil
import socket
import sys
from pathlib import Path
from core.finding import Finding

logger = logging.getLogger(__name__)

INTERESTING_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 7001: "WebLogic", 8080: "Alt-HTTP", 8443: "Alt-HTTPS",
    8888: "Dev-HTTP", 9200: "Elasticsearch", 27017: "MongoDB",
}

HIGH_RISK_PORTS = {6379, 27017, 9200, 2375, 3306, 1433, 5432}

_TOOLS_DIR = Path(__file__).parent.parent.parent / "tools"
_TOOLS_NMAP = _TOOLS_DIR / "nmap" / ("nmap.exe" if sys.platform == "win32" else "nmap")
_NMAP_PATH_FILE = _TOOLS_DIR / "nmap_path.txt"

# Well-known Windows install locations
_WIN_NMAP_LOCATIONS = [
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    Path(r"C:\Program Files\Nmap\nmap.exe"),
]


def _find_nmap_binary() -> str | None:
    # 1. Bundled nmap binary
    if _TOOLS_NMAP.exists():
        return str(_TOOLS_NMAP)
    # 2. Path saved by install_tools.py
    if _NMAP_PATH_FILE.exists():
        saved = _NMAP_PATH_FILE.read_text(encoding="utf-8").strip()
        if saved and Path(saved).exists():
            return saved
    # 3. Well-known Windows install directories
    for p in _WIN_NMAP_LOCATIONS:
        if p.exists():
            return str(p)
    # 4. System PATH
    return shutil.which("nmap")


class PortScanner:
    async def run(self, ctx: dict) -> list[Finding]:
        from urllib.parse import urlparse
        host = urlparse(ctx["target_url"]).hostname
        logger.info(f"Port scanning: {host}")
        findings = []
        open_ports = {}

        nmap_bin = _find_nmap_binary()
        if nmap_bin:
            try:
                import nmap
                import os as _os
                # Keep PATH modified for the full scan so python-nmap subprocess works
                nmap_dir = str(Path(nmap_bin).parent)
                old_path = _os.environ.get("PATH", "")
                _os.environ["PATH"] = nmap_dir + _os.pathsep + old_path
                try:
                    nm = nmap.PortScanner()
                    # Force absolute binary path so scan() subprocess always finds it
                    nm._nmap_path = nmap_bin
                    await asyncio.to_thread(
                        nm.scan, host,
                        "21-25,53,80,110,143,443,445,1433,1521,2375,3306,"
                        "3389,5432,5900,6379,7001,8080,8443,8888,9200,27017",
                        # -sV (service detection) is slow on remote hosts — skip it.
                        # --host-timeout caps the whole scan well under the 120s module limit.
                        "--open -T4 --host-timeout 80s"
                    )
                finally:
                    _os.environ["PATH"] = old_path

                if host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            state = nm[host][proto][port]
                            open_ports[port] = {
                                "state": state["state"],
                                "service": state.get("name", ""),
                                "version": state.get("version", ""),
                                "product": state.get("product", ""),
                            }
                logger.info(f"nmap scan complete — {len(open_ports)} open ports")
            except Exception as e:
                logger.warning(f"nmap failed ({e}), falling back to socket scan")
                open_ports = await self._socket_scan(host)
        else:
            logger.warning("nmap not found — using socket scan (run install_tools.py for nmap)")
            open_ports = await self._socket_scan(host)

        ctx["scan"]["open_ports"] = open_ports

        for port, info in open_ports.items():
            service = info.get("service") or INTERESTING_PORTS.get(port, "unknown")
            severity = "High" if port in HIGH_RISK_PORTS else "Medium"
            if port not in (80, 443):
                findings.append(Finding(
                    title=f"Open Port: {port}/{service}",
                    severity=severity,
                    description=f"Port {port} ({service}) is open and reachable from the internet. {info.get('version', '')}".strip(),
                    affected_url=f"{ctx['target_url']}:{port}",
                    proof=f"Port {port} state: {info.get('state', 'open')}",
                    remediation="Restrict access to this port via firewall. Only expose ports necessary for the application.",
                    impact=4 if port in HIGH_RISK_PORTS else 2,
                    likelihood=5,
                    module="PortScanner",
                ))
                logger.warning(f"Open port: {port}/{service}")

        return findings

    async def _socket_scan(self, host: str) -> dict:
        open_ports = {}
        sem = asyncio.Semaphore(200)

        async def check(port):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=2.5
                    )
                    writer.close()
                    open_ports[port] = {
                        "state": "open",
                        "service": INTERESTING_PORTS.get(port, "unknown"),
                    }
                except Exception:
                    pass

        all_ports = (list(range(1, 1025)) +
                     [1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 7001,
                      8080, 8443, 8888, 9200, 27017])
        await asyncio.gather(*[check(p) for p in all_ports])
        logger.info(f"Socket scan complete — {len(open_ports)} open ports")
        return open_ports
