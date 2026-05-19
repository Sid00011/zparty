"""
install_tools.py -- Download and install bundled tools for Zparty.
Run once: python install_tools.py
"""
import sys
import shutil
import subprocess
import os
from pathlib import Path

TOOLS_DIR = Path(__file__).parent / "tools"

# Common nmap install paths on Windows (winget / NSIS installer)
NMAP_WIN_PATHS = [
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    Path(r"C:\Program Files\Nmap\nmap.exe"),
]


def _find_nmap() -> str | None:
    """Return nmap path or None."""
    # Check PATH first
    found = shutil.which("nmap")
    if found:
        return found
    # Check well-known install dirs
    for p in NMAP_WIN_PATHS:
        if p.exists():
            return str(p)
    return None


def _winget_install_nmap() -> None:
    if not shutil.which("winget"):
        return
    print("  Running: winget install -e --id Insecure.Nmap")
    try:
        subprocess.run(
            ["winget", "install", "-e", "--id", "Insecure.Nmap",
             "--accept-package-agreements", "--accept-source-agreements"],
            timeout=120,
        )
    except Exception as e:
        print(f"  winget error: {e}")


def install_nmap_windows() -> None:
    nmap = _find_nmap()
    if nmap:
        print(f"[nmap] Found at {nmap}")
        _write_bundled_path(nmap)
        return

    print("[nmap] Not found on PATH. Trying winget install...")
    _winget_install_nmap()

    # Re-check (winget may have just installed it)
    # Reload PATH from registry so the new install is visible
    try:
        new_path = subprocess.check_output(
            ["powershell", "-Command",
             "[System.Environment]::GetEnvironmentVariable('PATH','Machine') + ';' + "
             "[System.Environment]::GetEnvironmentVariable('PATH','User')"],
            text=True, timeout=10,
        ).strip()
        os.environ["PATH"] = new_path
    except Exception:
        pass

    nmap = _find_nmap()
    if nmap:
        print(f"[nmap] Installed and found at {nmap}")
        _write_bundled_path(nmap)
        return

    # Not found even after install attempt
    print()
    print("[nmap] Could not install automatically.")
    print()
    print("  Manual options:")
    print()
    print("  Option A -- winget (Windows 10/11 built-in, run in admin shell):")
    print("    winget install -e --id Insecure.Nmap")
    print()
    print("  Option B -- download installer:")
    print("    https://nmap.org/download.html#windows")
    print("    Run the .exe and tick 'Add nmap to PATH'")
    print()
    print("  Zparty's socket scanner works without nmap.")
    print("  nmap only adds service/version detection on open ports.")


def _write_bundled_path(nmap_path: str) -> None:
    """Save the nmap location so port_scanner can find it without PATH lookup."""
    ref = TOOLS_DIR / "nmap_path.txt"
    TOOLS_DIR.mkdir(exist_ok=True)
    ref.write_text(nmap_path, encoding="utf-8")
    print(f"  Saved path reference -> tools/nmap_path.txt")


def install_nmap_linux() -> None:
    nmap = shutil.which("nmap")
    if nmap:
        print(f"[nmap] Found at {nmap} -- nothing to do.")
        return
    print("[nmap] Not found. Install via:")
    print("  Ubuntu/Debian : sudo apt install nmap")
    print("  Fedora/RHEL   : sudo dnf install nmap")
    print("  macOS         : brew install nmap")


def main() -> None:
    print()
    print("=== Zparty Tool Installer ===")
    print()
    TOOLS_DIR.mkdir(exist_ok=True)

    if sys.platform == "win32":
        install_nmap_windows()
    else:
        install_nmap_linux()

    print()
    print("Done. Start the UI with:  python ui_launch.py")
    print()


if __name__ == "__main__":
    main()
