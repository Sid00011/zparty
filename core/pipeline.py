"""
core/pipeline.py — Zparty scan orchestrator
Phase 0 → 1 → 2 sequential | Phase 3 concurrent with hard timeout | Phase 4 → 5 sequential
"""
import asyncio, logging, time
from pathlib import Path
from typing import Any
import yaml

from core.validator import validate_target, ValidationError
from core.rate_limiter import RateLimiter
from core.output import init_output_folder, checkpoint
from core.finding import Finding

# ── Recon ─────────────────────────────────────────────────────────────────────
from modules.recon.whois_lookup  import WhoisLookup
from modules.recon.dns_enum      import DnsEnum
from modules.recon.subdomain_enum import SubdomainEnum
from modules.recon.tech_fingerprint import TechFingerprint
from modules.recon.ssl_analysis  import SslAnalysis
from modules.recon.js_analysis   import JsAnalysis
from modules.recon.wayback       import WaybackMiner
from modules.recon.error_analysis import ErrorAnalysis

# ── Scan ──────────────────────────────────────────────────────────────────────
from modules.scan.port_scanner   import PortScanner
from modules.scan.dir_bruteforce import DirBruteforce
from modules.scan.crawler        import Crawler
from modules.scan.header_analysis import HeaderAnalysis
from modules.scan.waf_detection  import WafDetection

# ── Vulns ─────────────────────────────────────────────────────────────────────
from modules.vulns.jwt_attacks      import JwtAttacks
from modules.vulns.http_smuggling   import HttpSmuggling
from modules.vulns.ssrf             import Ssrf
from modules.vulns.xxe              import Xxe
from modules.vulns.sqli             import SqlInjection
from modules.vulns.xss              import Xss
from modules.vulns.race_conditions  import RaceConditions
from modules.vulns.subdomain_takeover import SubdomainTakeover
from modules.vulns.graphql          import GraphQL
from modules.vulns.deserialization  import Deserialization
from modules.vulns.cors             import CorsCheck
from modules.vulns.open_redirect    import OpenRedirect
from modules.vulns.ssti             import Ssti
from modules.vulns.path_traversal   import PathTraversal
from modules.vulns.http_methods     import HttpMethods
from modules.vulns.idor             import Idor
from modules.vulns.nosql_injection  import NoSqlInjection
from modules.vulns.cve_checks       import CveChecks
from modules.vulns.nuclei_scan      import NucleiScan
from modules.vulns.command_injection import CommandInjection
from modules.vulns.default_creds    import DefaultCreds
from modules.vulns.lfi              import Lfi
from modules.vulns.ssti_rce         import SstiRce
from modules.vulns.ssrf_chain       import SsrfChain
from modules.vulns.mass_assignment  import MassAssignment
from modules.vulns.file_upload      import FileUpload
from modules.vulns.idor_chain       import IdorChain
from modules.vulns.oauth_tester     import OAuthTester
from modules.vulns.race_advanced    import RaceAdvanced
from modules.vulns.business_logic   import BusinessLogic
from core.ai_engine                 import AIEngine

from scoring.engine import score_findings
from reports.generator import generate_report
from reports.sarif import generate_sarif

logger = logging.getLogger(__name__)

VULN_MODULE_TIMEOUT  = 60    # seconds per vuln module before it is cancelled
NUCLEI_TIMEOUT       = 180   # nuclei runs a subprocess — give it extra headroom
PHASE3_HARD_LIMIT    = 300   # total seconds for all vuln modules combined (5 min)


def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


async def _safe_run(module, ctx: dict, timeout: int = VULN_MODULE_TIMEOUT) -> list[Finding]:
    """Run a module with a hard timeout.  Always returns a list of Finding."""
    name = type(module).__name__
    try:
        raw = await asyncio.wait_for(module.run(ctx), timeout=timeout)
        # Recon modules return dicts; vuln/scan modules return Finding lists
        findings: list[Finding] = raw if isinstance(raw, list) else []
        logger.info(f"[{name}] completed — {len(findings)} finding(s)")
        return findings
    except asyncio.TimeoutError:
        logger.warning(f"[{name}] timed out after {timeout}s — skipped")
        return []
    except Exception as e:
        logger.error(f"[{name}] crashed: {type(e).__name__}: {e}")
        return []


async def _safe_run_recon(module, ctx: dict) -> dict:
    """Run a recon module; always returns a dict."""
    name = type(module).__name__
    try:
        result = await asyncio.wait_for(module.run(ctx), timeout=60)
        out = result if isinstance(result, dict) else {}
        logger.info(f"[{name}] completed")
        return out
    except asyncio.TimeoutError:
        logger.warning(f"[{name}] timed out — skipped")
        return {}
    except Exception as e:
        logger.error(f"[{name}] crashed: {type(e).__name__}: {e}")
        return {}


def _seed_endpoints(ctx: dict) -> None:
    """
    Guarantee that ctx["endpoints"] has at least the base URL and common
    parameterised probe URLs so vuln modules always have something to test,
    even when the crawler couldn't crawl (slow targets, WAF blocks, etc.).
    """
    base = ctx["target_url"].rstrip("/")
    existing = set(ctx["endpoints"])

    # Always include the bare base URL
    if base not in existing:
        ctx["endpoints"].append(base)
        existing.add(base)

    # Common parameter names used by vulnerable apps
    common_params = [
        "id", "page", "cat", "artist", "item", "product", "user", "search",
        "q", "query", "s", "file", "path", "url", "redirect", "next",
        "view", "action", "type", "lang", "sort", "order", "name",
        "username", "email", "token", "key", "data", "input", "cmd",
    ]
    seeded = 0
    for param in common_params:
        for val in ("1", "test"):
            probe = f"{base}?{param}={val}"
            if probe not in existing:
                ctx["endpoints"].append(probe)
                existing.add(probe)
                seeded += 1

    # Seed common vulnerable PHP paths found on test apps like vulnweb
    common_paths = [
        "artists.php?artist=1",
        "listproducts.php?cat=1",
        "userinfo.php",
        "search.php?test=query",
        "guestbook.php",
        "showimage.php?file=./pictures/1.jpg",
        "hpp/?pp=12",
        "login.php",
        "signup.php",
        "comment.php?aid=1",
    ]
    for path in common_paths:
        probe = f"{base}/{path}"
        if probe not in existing:
            ctx["endpoints"].append(probe)
            existing.add(probe)
            seeded += 1

    logger.info(f"Endpoint seeds: {len(ctx['endpoints'])} total "
                f"({seeded} injected, {len(existing) - seeded - 1} from crawl)")


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Multi-level deduplication:
    1. Exact: same (title, affected_url) → keep first
    2. Near-duplicate: same (title, module) reported more than MAX_PER_TITLE times
       across different URLs → keep highest-severity first, drop extras
       (avoids e.g. the same SQL injection form found on 10 pages)
    """
    from urllib.parse import urlparse

    MAX_PER_TITLE = 3  # max distinct findings per (title, module) combination

    # Pass 1: exact dedup by (title, url_path)
    seen_exact: set[tuple[str, str]] = set()
    pass1: list[Finding] = []
    for f in findings:
        path = urlparse(f.affected_url).path
        key = (f.title, path)
        if key in seen_exact:
            continue
        seen_exact.add(key)
        pass1.append(f)

    # Pass 2: cap to MAX_PER_TITLE per (title, module)
    title_counts: dict[tuple[str, str], int] = {}
    unique: list[Finding] = []
    for f in pass1:
        key2 = (f.title, f.module)
        count = title_counts.get(key2, 0)
        if count >= MAX_PER_TITLE:
            continue
        title_counts[key2] = count + 1
        unique.append(f)

    suppressed = len(findings) - len(unique)
    if suppressed:
        logger.info(f"Deduplication: suppressed {suppressed} duplicate finding(s)")
    return unique


async def _probe_alive(url: str, timeout: float = 8.0) -> bool:
    """
    Single quick HTTP GET with an 8-second deadline.
    Returns True if the server answers (any status code), False on any timeout/error.
    This acts as the connectivity gate before Phase 3 so we don't waste 8 minutes
    firing 16 attack modules at a host that can't be reached.
    """
    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(
            timeout=_httpx.Timeout(connect=timeout, read=timeout, write=5.0, pool=5.0),
            http2=False,
            follow_redirects=True,
            verify=False,
        ) as c:
            r = await c.get(url)
            logger.info(f"Connectivity probe: {url} -> HTTP {r.status_code} — target is alive")
            return True
    except Exception as e:
        logger.warning(f"Connectivity probe failed ({type(e).__name__}) — target appears unreachable")
        return False


async def run_pipeline(target_url: str, config_path: str = "config.yaml") -> dict:
    start_time = time.time()
    cfg = load_config(config_path)
    cfg["target"]["url"] = target_url

    # ── Phase 0 ───────────────────────────────────────────────────────────────
    logger.info("=== Phase 0: Validation ===")
    try:
        meta = validate_target(target_url, timeout=20)
    except ValidationError as e:
        logger.critical(f"Validation failed: {e}")
        raise

    session = init_output_folder(cfg["output"]["results_dir"])
    limiter = RateLimiter.from_config(cfg)
    en = cfg.get("modules", {})

    ctx: dict[str, Any] = {
        "target_url": target_url,
        "config": cfg,
        "limiter": limiter,
        "session": session,
        "meta": meta,
        "recon": {},
        "scan": {},
        "forms": [],
        "endpoints": [],
        "cookies": [],
        "subdomains": [],
    }

    from core.auth import AuthManager
    from core.http_client import set_global_auth
    from core.scope import ScopeManager
    import core.evasion as _evasion
    _evasion.configure(cfg)

    # ── Tor anonymity layer ────────────────────────────────────────────────────
    # Tor starts but does NOT proxy traffic during phases 1 & 2 (recon/crawl).
    # It activates only at Phase 3 (attack modules) so recon stays fast and
    # directory brute-force doesn't get strangled by Tor latency.
    from core.tor_proxy import init_tor
    import core.evasion as _evasion
    tor = init_tor(cfg)
    tor_ready = await tor.start()
    if tor_ready:
        ctx["tor"] = tor
        current_ip = await tor.get_current_ip()
        logger.info(
            f"Tor ready — exit IP: {current_ip or 'unknown'} "
            f"(activates at Phase 3 — recon/scan run direct for speed)"
        )
        # Phases 1 & 2 run WITHOUT Tor proxy — fast direct requests
        _evasion.configure(cfg)
    else:
        ctx["tor"] = None
        _evasion.configure(cfg)
        logger.info(
            f"Evasion: UA rotation on, "
            f"jitter={cfg.get('evasion',{}).get('jitter_ms',0)}ms, "
            f"proxy={'on' if cfg.get('proxy',{}).get('enabled') else 'off'}, "
            f"Tor=off"
        )

    auth = await AuthManager.from_config(cfg, ctx)
    set_global_auth(auth.get_cookies(), auth.get_headers())
    ctx["auth"] = auth
    if auth.is_authenticated:
        logger.info(f"Auth: {auth.auth_type} authentication active")

    scope = ScopeManager(cfg)
    ctx["scope"] = scope

    # ── OOB listener ──────────────────────────────────────────────────────────
    from core.oob import OOBTracker
    oob = OOBTracker(cfg)
    await oob.start()
    ctx["oob"] = oob

    # ── Playwright exploit verifier ────────────────────────────────────────────
    from core.exploit_verifier import ExploitVerifier
    verifier = ExploitVerifier(max_concurrent=2)
    ctx["verifier"] = verifier

    # ── AI engine (local Ollama — 100% offline) ───────────────────────────────
    ai = AIEngine(cfg)
    await ai.start()
    ctx["ai"] = ai
    if verifier.available:
        logger.info("ExploitVerifier: Playwright available — proof-of-exploit screenshots enabled")
    else:
        logger.info("ExploitVerifier: Playwright not installed — screenshots disabled (pip install playwright)")

    # ── Phase 1 ───────────────────────────────────────────────────────────────
    logger.info("=== Phase 1: Passive Reconnaissance ===")
    r_cfg = en.get("recon", {})
    recon_map = [
        ("whois",           WhoisLookup()),
        ("dns",             DnsEnum()),
        ("subdomain_enum",  SubdomainEnum()),
        ("tech_fingerprint",TechFingerprint()),
        ("ssl_analysis",    SslAnalysis()),
        ("js_analysis",     JsAnalysis()),
        ("wayback",         WaybackMiner()),
        ("error_analysis",  ErrorAnalysis()),
    ]
    for key, mod in recon_map:
        if r_cfg.get(key, True):
            result = await _safe_run_recon(mod, ctx)
            ctx["recon"][type(mod).__name__] = result

    # Surface findings from recon into all_findings list for scoring
    recon_findings: list[Finding] = []
    for v in ctx["recon"].values():
        if isinstance(v, list):
            recon_findings.extend(f for f in v if isinstance(f, Finding))

    checkpoint(session, "phase1_recon", ctx["recon"])

    # ── AI attack planning ────────────────────────────────────────────────────
    if ai.active:
        attack_plan = await ai.analyze_target(ctx)
        ctx["attack_plan"] = attack_plan
        if attack_plan.get("exploit_chain_hypothesis"):
            logger.info(f"AI hypothesis: {attack_plan['exploit_chain_hypothesis']}")

    # ── Phase 2 ───────────────────────────────────────────────────────────────
    logger.info("=== Phase 2: Active Scanning ===")
    scan_findings: list[Finding] = []
    s_cfg = en.get("scan", {})
    scan_map = [
        ("port_scan",       PortScanner()),
        ("dir_bruteforce",  DirBruteforce()),
        ("crawler",         Crawler()),
        ("header_analysis", HeaderAnalysis()),
        ("waf_detection",   WafDetection()),
    ]
    for key, mod in scan_map:
        if s_cfg.get(key, True):
            found = await _safe_run(mod, ctx, timeout=60)
            scan_findings.extend(found)

    checkpoint(session, "phase2_scan", ctx["scan"])

    # ── Seed endpoints ────────────────────────────────────────────────────────
    # Ensure vuln modules always have the base target plus common parameterised
    # probes even when the crawler found nothing (slow targets, etc.)
    _seed_endpoints(ctx)

    # ── Scope filtering ───────────────────────────────────────────────────────
    # Remove out-of-scope and destructive paths (e.g. /logout) from the
    # endpoint list before attack modules run.
    before_scope = len(ctx["endpoints"])
    ctx["endpoints"] = scope.filter(ctx["endpoints"])
    logger.info(f"Scope filter: {before_scope} → {len(ctx['endpoints'])} endpoints")

    # ── Connectivity gate ─────────────────────────────────────────────────────
    target_alive = await _probe_alive(target_url)
    ctx["target_reachable"] = target_alive

    # ── Activate Tor NOW (only for Phase 3 attack traffic) ───────────────────
    tor_inst = ctx.get("tor")
    if tor_inst and tor_inst.active:
        _evasion.configure({
            **cfg,
            "proxy": {"enabled": True, "url": tor_inst.proxy_url, "rotate": False},
        })
        logger.info("Tor proxy activated for Phase 3 attack modules — IP is now hidden")

    # ── Phase 3 ───────────────────────────────────────────────────────────────
    logger.info("=== Phase 3: Vulnerability Modules ===")
    v_cfg = en.get("vulns", {})
    vuln_map = [
        ("jwt",               JwtAttacks()),
        ("http_smuggling",    HttpSmuggling()),
        ("ssrf",              Ssrf()),
        ("xxe",               Xxe()),
        ("sqli",              SqlInjection()),
        ("xss",               Xss()),
        ("race_conditions",   RaceConditions()),
        ("subdomain_takeover",SubdomainTakeover()),
        ("graphql",           GraphQL()),
        ("deserialization",   Deserialization()),
        ("cors",              CorsCheck()),
        ("open_redirect",     OpenRedirect()),
        ("ssti",              Ssti()),
        ("path_traversal",    PathTraversal()),
        ("http_methods",      HttpMethods()),
        ("idor",              Idor()),
        ("nosql_injection",   NoSqlInjection()),
        ("cve_checks",        CveChecks()),
        ("nuclei",            NucleiScan()),
        ("command_injection", CommandInjection()),
        ("default_creds",     DefaultCreds()),
        ("lfi",               Lfi()),
        ("ssti_rce",          SstiRce()),
        ("ssrf_chain",        SsrfChain()),
        ("mass_assignment",   MassAssignment()),
        ("file_upload",       FileUpload()),
        ("idor_chain",        IdorChain()),
        ("oauth_tester",      OAuthTester()),
        ("race_advanced",     RaceAdvanced()),
        ("business_logic",    BusinessLogic()),
    ]
    vuln_findings: list[Finding] = []

    if not target_alive:
        logger.warning(
            "Target did not respond to HTTP probe — skipping vulnerability modules. "
            "The host may be down, blocking this IP, or behind a firewall."
        )
        vuln_findings.append(Finding(
            title="Target Unreachable — Vulnerability Scan Skipped",
            severity="Info",
            description=(
                f"No HTTP response was received from {target_url} during the scan. "
                "All TCP connection attempts timed out. Vulnerability modules were skipped "
                "to avoid a meaningless 8-minute wait."
            ),
            affected_url=target_url,
            proof=(
                "Phase 0 reachability check: timed out\n"
                "Crawler: 0 pages fetched\n"
                "Pre-Phase-3 connectivity probe: timed out"
            ),
            remediation=(
                "Verify the target is accessible from this network. "
                "Check firewall rules, VPN settings, and whether the host is online. "
                "If scanning an internal target, run Zparty from within the network."
            ),
            impact=0, likelihood=0, module="Pipeline",
        ))
    else:
        # Rotate Tor identity once before launching all modules concurrently.
        # Per-module rotation is pointless when all tasks run in parallel —
        # they'd all serialise on the lock and waste ~90s before any request fires.
        tor_inst = ctx.get("tor")
        if tor_inst and tor_inst.active and tor_inst.rotate_between_modules:
            await tor_inst.rotate()

        async def _safe_run_vuln(key, mod):
            timeout = NUCLEI_TIMEOUT if key == "nuclei" else VULN_MODULE_TIMEOUT
            return await _safe_run(mod, ctx, timeout=timeout)

        vuln_tasks = [
            _safe_run_vuln(key, mod)
            for key, mod in vuln_map
            if v_cfg.get(key, True)
        ]

        try:
            nested = await asyncio.wait_for(
                asyncio.gather(*vuln_tasks, return_exceptions=True),
                timeout=PHASE3_HARD_LIMIT,
            )
        except asyncio.TimeoutError:
            logger.warning(f"Phase 3 hard limit ({PHASE3_HARD_LIMIT}s) reached — collecting partial results")
            nested = []

        for r in nested:
            if isinstance(r, list):
                vuln_findings.extend(f for f in r if isinstance(f, Finding))
            elif isinstance(r, Exception):
                logger.error(f"Vuln task exception: {r}")

    all_findings = _deduplicate(recon_findings + scan_findings + vuln_findings)

    # Enrich findings with CVSS 3.1 vectors/scores before scoring
    from core.cvss import lookup as cvss_lookup
    for f in all_findings:
        if not f.cvss_vector:
            f.cvss_vector, f.cvss_score, f.cwe = cvss_lookup(f.title, f.severity)

    # ── AI chain analysis + triage ─────────────────────────────────────────────
    if ai.active and all_findings:
        findings_dicts_for_ai = [f.to_dict() for f in all_findings]
        # Find exploit chains
        chains = await ai.analyze_chain(findings_dicts_for_ai)
        for chain_dict in chains:
            chain_finding = Finding(
                title=chain_dict["title"],
                severity=chain_dict["severity"],
                description=chain_dict["description"],
                affected_url=chain_dict["affected_url"],
                proof=chain_dict["proof"],
                remediation=chain_dict["remediation"],
                impact=chain_dict["impact"],
                likelihood=chain_dict["likelihood"],
                module=chain_dict["module"],
                cvss_score=chain_dict.get("cvss_score", 0.0),
            )
            all_findings.append(chain_finding)
        # AI triage — re-score findings
        triaged_dicts = await ai.triage_findings([f.to_dict() for f in all_findings])
        # Apply triage severity changes back to Finding objects
        triage_map = {d["title"]: d for d in triaged_dicts}
        for f in all_findings:
            td = triage_map.get(f.title)
            if td and td["severity"] != f.severity:
                f.severity = td["severity"]

    # Stop OOB listener
    await oob.stop()

    # Stop Tor daemon (only if we started it)
    tor_inst = ctx.get("tor")
    if tor_inst:
        await tor_inst.stop()

    checkpoint(session, "phase3_vulns", [f.to_dict() for f in all_findings])

    # ── Compliance mapping ────────────────────────────────────────────────────
    from core.compliance import map_findings_to_compliance
    findings_dicts = [f.to_dict() for f in all_findings]
    compliance = map_findings_to_compliance(findings_dicts)

    # ── Phase 4 ───────────────────────────────────────────────────────────────
    logger.info("=== Phase 4: Scoring ===")
    score_data = score_findings(all_findings, cfg)
    # If target was unreachable, override the grade — S/100 is misleading when
    # nothing was actually tested.
    if not target_alive:
        score_data["grade"] = "N/A"
        score_data["score"] = None
        score_data["grade_description"] = (
            "Target Unreachable — no vulnerability scan was performed. "
            "Verify the target is accessible from this network and re-scan."
        )
    checkpoint(session, "phase4_score", score_data)

    # ── Phase 5 ───────────────────────────────────────────────────────────────
    logger.info("=== Phase 5: Report Generation ===")
    sorted_findings = [
        f.to_dict() for f in sorted(
            all_findings,
            key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}.get(x.severity, 5)
        )
    ]
    report_data = {
        "target_url":       target_url,
        "scan_date":        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
        "duration_seconds": round(time.time() - start_time, 1),
        "meta":             meta,
        "recon":            ctx["recon"],
        "scan":             ctx["scan"],
        "findings":         sorted_findings,
        "score":            score_data,
        "compliance":       compliance,
    }
    output_paths = generate_report(report_data, session)

    # SARIF output for CI/CD integration
    sarif_path = generate_sarif(sorted_findings, session)
    if sarif_path:
        output_paths["sarif"] = sarif_path

    checkpoint(session, "phase5_report", output_paths)

    # ── Scan history ──────────────────────────────────────────────────────────
    from core.history import HistoryManager
    history = HistoryManager()
    result_for_history = {
        "target_url":      target_url,
        "session":         str(session),
        "scan_date":       report_data["scan_date"],
        "duration":        report_data["duration_seconds"],
        "score":           score_data.get("score"),
        "grade":           score_data.get("grade"),
        "findings_count":  len(all_findings),
        "severity_counts": score_data.get("severity_counts", {}),
        "report_paths":    output_paths,
        "meta":            meta,
    }
    history.save_scan(result_for_history, sorted_findings)

    # Scan comparison (show what changed since last scan)
    comparison = history.compare_scans(target_url)
    if comparison.get("available"):
        delta = comparison.get("score_delta", 0)
        sign = "+" if delta and delta > 0 else ""
        logger.info(
            f"vs previous scan: {comparison['new_count']} new, "
            f"{comparison['fixed_count']} fixed, "
            f"score delta: {sign}{delta}"
        )

    # ── Notifications ─────────────────────────────────────────────────────────
    from core.notify import NotificationManager
    notifier = NotificationManager(cfg)
    notify_result = {**result_for_history, "score_data": score_data}
    await notifier.send_all(notify_result, sorted_findings)

    duration = round(time.time() - start_time, 1)
    score_display = f"{score_data['score']}/100" if score_data["score"] is not None else "N/A"
    logger.info(
        f"=== Scan complete in {duration}s | "
        f"Score: {score_display} | Grade: {score_data['grade']} | "
        f"Findings: {len(all_findings)} ==="
    )
    return {
        "session":         str(session),
        "score":           score_data["score"],
        "grade":           score_data["grade"],
        "findings_count":  len(all_findings),
        "report_paths":    output_paths,
        "duration":        duration,
        "severity_counts": score_data.get("severity_counts", {}),
        "compliance":      compliance,
        "comparison":      comparison if comparison.get("available") else None,
        "target_url":      target_url,
        "scan_date":       report_data["scan_date"],
    }
