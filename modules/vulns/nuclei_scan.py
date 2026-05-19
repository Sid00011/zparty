"""
modules/vulns/nuclei_scan.py — Nuclei template-based vulnerability scanner

Nuclei (projectdiscovery.io) is a fast, configurable vulnerability scanner
with 9 000+ community-maintained templates covering CVEs, misconfigs,
default credentials, exposed panels, and more.

This module:
  1. Locates or auto-downloads the nuclei binary (GitHub Releases)
  2. Runs nuclei against the target with JSONL output
  3. Maps each nuclei finding to a Zparty Finding object
  4. Honours all auth headers configured in config.yaml
  5. Hard-caps at 300 s to stay inside pipeline budget
"""
import asyncio
import json
import logging
import os
import platform
import shutil
import stat
import urllib.request
import zipfile
from pathlib import Path
from core.finding import Finding

logger = logging.getLogger(__name__)

# ── Binary location ───────────────────────────────────────────────────────────
_BIN_DIR     = Path(__file__).parent.parent.parent / "bin"
_NUCLEI_VER  = "v3.3.7"

# ── Severity mapping ──────────────────────────────────────────────────────────
_SEV_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
    "unknown":  "Info",
}
_IMPACT_MAP = {
    "Critical": 5,
    "High":     4,
    "Medium":   3,
    "Low":      2,
    "Info":     1,
}


# ─────────────────────────────── helpers ──────────────────────────────────────

def _binary_path() -> str | None:
    """Return path to usable nuclei binary, or None if not found."""
    found = shutil.which("nuclei")
    if found:
        return found
    _BIN_DIR.mkdir(parents=True, exist_ok=True)
    name = "nuclei.exe" if platform.system() == "Windows" else "nuclei"
    local = _BIN_DIR / name
    if local.exists() and os.access(str(local), os.X_OK):
        return str(local)
    return None


async def _download_nuclei() -> str | None:
    """
    Download the nuclei binary for the current OS/arch from GitHub Releases.
    Extracts the binary into bin/ and marks it executable.
    """
    system  = platform.system().lower()      # windows / linux / darwin
    machine = platform.machine().lower()

    arch = "amd64"
    if machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"

    ver = _NUCLEI_VER.lstrip("v")
    fname = f"nuclei_{ver}_{system}_{arch}.zip"
    url   = (
        f"https://github.com/projectdiscovery/nuclei/releases/download/"
        f"{_NUCLEI_VER}/{fname}"
    )
    dest_zip = _BIN_DIR / fname
    bin_name = "nuclei.exe" if system == "windows" else "nuclei"
    dest_bin = _BIN_DIR / bin_name

    logger.info(f"Downloading nuclei {_NUCLEI_VER} from GitHub …")
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: urllib.request.urlretrieve(url, str(dest_zip))
        )
        with zipfile.ZipFile(str(dest_zip), "r") as z:
            for member in z.namelist():
                if member.lower().endswith(bin_name):
                    with z.open(member) as src, open(str(dest_bin), "wb") as dst:
                        dst.write(src.read())
                    break
        dest_zip.unlink(missing_ok=True)
        # Mark executable on Unix
        if system != "windows":
            mode = dest_bin.stat().st_mode
            dest_bin.chmod(mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        logger.info(f"Nuclei binary ready at {dest_bin}")
        return str(dest_bin)
    except Exception as e:
        logger.warning(f"Nuclei auto-download failed: {type(e).__name__}: {e}")
        if dest_zip.exists():
            dest_zip.unlink(missing_ok=True)
        return None


# ─────────────────────────────── module ───────────────────────────────────────

class NucleiScan:
    """
    Run Nuclei against the target and convert findings to Zparty Finding objects.

    Tags used by default:
      cve, exposure, misconfig, default-login, panel, takeover

    Severities: critical, high, medium, low   (info skipped — too noisy)
    """

    async def run(self, ctx: dict) -> list[Finding]:
        cfg    = ctx.get("config", {})
        v_cfg  = cfg.get("modules", {}).get("vulns", {})
        if not v_cfg.get("nuclei", True):
            return []

        target = ctx.get("target_url", "")
        if not target:
            return []

        # Locate or download binary
        binary = _binary_path()
        if not binary:
            logger.info("Nuclei not found in PATH — attempting auto-download …")
            binary = await _download_nuclei()
        if not binary:
            logger.warning("Nuclei unavailable — skipping template scan")
            return []

        # Bootstrap templates on first run (nuclei needs ~/.nuclei-templates)
        await self._ensure_templates(binary)

        rate = cfg.get("rate_limit", {}).get("requests_per_second", 20)
        return await self._run(binary, target, rate, cfg)

    async def _ensure_templates(self, binary: str) -> None:
        """
        Run `nuclei -update-templates` on first use so templates are available.
        Cached after first successful bootstrap — subsequent runs skip this step.
        Template directory is typically ~/.nuclei-templates (cross-platform).
        """
        import os
        home = Path.home()
        # Nuclei stores templates in ~/nuclei-templates on all platforms
        candidate_dirs = [home / "nuclei-templates"]
        # Windows: also check APPDATA
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            candidate_dirs.append(Path(appdata) / "nuclei-templates")
        # Also check the nuclei config dir (e.g. AppData\Roaming\nuclei\templates)
        appdata_roaming = os.environ.get("APPDATA", "")
        if appdata_roaming:
            candidate_dirs.append(Path(appdata_roaming) / "nuclei" / "templates")

        templates_exist = any(
            d.exists() and any(d.iterdir())
            for d in candidate_dirs
            if d.exists()
        )
        if templates_exist:
            return  # already bootstrapped

        logger.info("Nuclei: bootstrapping templates (first run) — this takes ~30 s …")
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, _ = await asyncio.wait_for(proc.communicate(), timeout=120.0)
                logger.info("Nuclei templates ready.")
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
                logger.warning("Nuclei template download timed out — scan may find fewer results")
        except Exception as exc:
            logger.warning(f"Nuclei template bootstrap failed: {exc}")

    async def _run(
        self, binary: str, target: str, rate: int, cfg: dict
    ) -> list[Finding]:
        findings: list[Finding] = []

        cmd = [
            binary,
            "-u", target,
            "-jsonl",
            "-severity", "critical,high,medium,low",
            "-tags",     "cve,exposure,misconfig,default-login,panel,takeover",
            "-rate-limit", str(rate),
            "-timeout",  "10",
            "-retries",  "1",
            "-duc",            # disable update check — no network noise
            "-silent",
            "-no-color",
        ]

        # Honour auth config
        auth = cfg.get("auth", {})
        if auth.get("bearer"):
            cmd += ["-H", f"Authorization: Bearer {auth['bearer']}"]
        elif auth.get("cookie"):
            cmd += ["-H", f"Cookie: {auth['cookie']}"]
        elif auth.get("type") == "apikey":
            hdr = auth.get("apikey", {}).get("header", "X-API-Key")
            key = auth.get("apikey", {}).get("key", "")
            if key:
                cmd += ["-H", f"{hdr}: {key}"]

        logger.info(f"Nuclei starting → {target}  (cmd: {' '.join(cmd[:6])} …)")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=300.0
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
                logger.warning("Nuclei timed out after 300 s — using partial results")
                stdout, stderr = b"", b""

            if stderr:
                dbg = stderr.decode(errors="replace").strip()
                if dbg:
                    logger.debug(f"Nuclei stderr: {dbg[:400]}")

            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                finding = self._parse(line)
                if finding:
                    findings.append(finding)

        except FileNotFoundError:
            logger.error(f"Nuclei binary not found: {binary}")
        except Exception as exc:
            logger.error(f"Nuclei error: {type(exc).__name__}: {exc}")

        logger.info(f"NucleiScan completed — {len(findings)} finding(s)")
        return findings

    # ── JSONL parser ──────────────────────────────────────────────────────────

    def _parse(self, line: bytes) -> Finding | None:
        try:
            data: dict = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None

        info         = data.get("info", {})
        template_id  = data.get("template-id", "unknown")
        name         = info.get("name") or template_id
        sev_raw      = (info.get("severity") or "info").lower()
        severity     = _SEV_MAP.get(sev_raw, "Info")
        description  = (info.get("description") or
                        f"Nuclei template '{template_id}' matched the target.")
        remediation  = (info.get("remediation") or
                        "Refer to the linked advisory for remediation guidance.")

        matched_at   = data.get("matched-at") or data.get("host") or ""
        matcher_name = data.get("matcher-name") or ""
        extracted    = data.get("extracted-results") or []

        # CVSS / CWE from nuclei's classification block
        cls          = info.get("classification") or {}
        cvss_score   = float(cls.get("cvss-score") or 0.0)
        cvss_vector  = cls.get("cvss-metrics") or ""
        cwe_list     = cls.get("cwe-id") or []
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        cwe = cwe_list[0] if cwe_list else ""

        # References — nuclei stores as list or string
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        # Build a human-readable proof snippet
        proof_lines = [f"Nuclei template : {template_id}"]
        if matched_at:
            proof_lines.append(f"Matched at      : {matched_at}")
        if matcher_name:
            proof_lines.append(f"Matcher         : {matcher_name}")
        if extracted:
            sample = [str(x) for x in extracted[:3]]
            proof_lines.append(f"Extracted       : {', '.join(sample)}")
        # curl command for easy reproduction
        if matched_at.startswith("http"):
            proof_lines.append(f"\nReproduce: curl -sk '{matched_at}'")

        impact     = _IMPACT_MAP.get(severity, 1)
        likelihood = max(1, impact - 1)  # nuclei = confirmed → likelihood high

        return Finding(
            title=f"[Nuclei] {name}",
            severity=severity,
            description=description,
            affected_url=matched_at,
            proof="\n".join(proof_lines),
            remediation=remediation,
            impact=impact,
            likelihood=likelihood,
            module="NucleiScan",
            references=refs[:6],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe=cwe,
        )
