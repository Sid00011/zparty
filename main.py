"""
main.py — Zparty CLI entrypoint.
Usage: python main.py scan https://example.com
"""
import asyncio
import sys
import warnings
# Suppress Windows asyncio subprocess pipe cleanup noise (harmless ResourceWarning
# from Python 3.12+ on Windows when asyncio subprocess pipes are garbage-collected)
warnings.filterwarnings("ignore", category=ResourceWarning, message=".*unclosed transport.*")
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="zparty",
    help="Zparty — Automated Web Penetration Testing Framework",
    add_completion=False,
)
console = Console()

BANNER = r"""
 ____  ____  _   ____  ____  ____  _  _
|_  _||  _ \/ \ |  _ \|_  _||_  _|\ \/ /
  | |  / _/| | || |_) | | |   | |  /  \
  |_| |_|  \_/ ||  __/ |_|   |_| /_/\_\
                |_|
        Automated Pentest Framework
"""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
    output: str = typer.Option("results", "--output", "-o", help="Results directory"),
    cookie: str = typer.Option("", "--cookie", "-C", help='Session cookies: "session=abc; csrf=xyz"'),
    bearer: str = typer.Option("", "--bearer", "-b", help="Bearer token for Authorization header"),
    login_url: str = typer.Option("", "--login-url", help="URL to POST login credentials to"),
    login_user: str = typer.Option("", "--login-user", help="Username for form-based login"),
    login_pass: str = typer.Option("", "--login-pass", help="Password for form-based login"),
    apikey: str = typer.Option("", "--apikey", help='API key (e.g. "X-API-Key:mykey12345")'),
):
    """Run a full automated pentest against TARGET."""
    console.print(Panel(BANNER, style="bold cyan"), justify="center")
    console.print(f"[bold green]Target:[/bold green] {target}")
    console.print(f"[bold green]Config:[/bold green] {config}\n")

    from core.pipeline import run_pipeline, load_config
    from core.validator import ValidationError

    try:
        cfg = load_config(config)
        cfg["output"]["results_dir"] = output

        # CLI auth flags override config.yaml auth section
        if cookie:
            cfg["auth"] = {"type": "cookie", "cookie": cookie}
            console.print(f"[bold green]Auth:[/bold green] cookie (CLI override)")
        elif bearer:
            cfg["auth"] = {"type": "bearer", "bearer": bearer}
            console.print(f"[bold green]Auth:[/bold green] bearer token (CLI override)")
        elif apikey:
            header_name, _, key_value = apikey.partition(":")
            cfg["auth"] = {"type": "apikey", "apikey": {"header": header_name.strip(), "key": key_value.strip()}}
            console.print(f"[bold green]Auth:[/bold green] API key header '{header_name.strip()}' (CLI override)")
        elif login_url and login_user:
            cfg["auth"] = {
                "type": "form",
                "form": {
                    "login_url": login_url,
                    "username_field": "username",
                    "password_field": "password",
                    "username": login_user,
                    "password": login_pass,
                    "success_indicator": "",
                },
            }
            console.print(f"[bold green]Auth:[/bold green] form login → {login_url} (CLI override)")

        result = asyncio.run(run_pipeline(target, config))

        _print_summary(result)

    except ValidationError as e:
        console.print(f"[bold red]Validation error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/bold red] {e}")
        raise typer.Exit(code=1)


def _print_summary(result: dict) -> None:
    grade_colors = {
        "S": "bold bright_green",
        "A": "green",
        "B": "yellow",
        "C": "dark_orange",
        "D": "red",
        "E": "bold red",
        "N/A": "dim",
    }
    grade = result["grade"]
    color = grade_colors.get(grade, "white")
    score_display = f"{result['score']}/100" if result["score"] is not None else "N/A"

    console.print(Panel(
        f"[{color}]Grade: {grade}  |  Score: {score_display}[/{color}]\n"
        f"Findings: {result['findings_count']}   Duration: {result['duration']}s",
        title="[bold]Scan Complete[/bold]",
        style=color,
    ))

    t = Table(title="Output Files")
    t.add_column("Format", style="cyan")
    t.add_column("Path")
    for fmt, path in result.get("report_paths", {}).items():
        t.add_row(fmt.upper(), str(path))
    console.print(t)

    console.print(f"\n[dim]Full results: {result['session']}[/dim]")


@app.command()
def agent(
    target: str = typer.Argument(..., help="Target URL for the autonomous agent"),
    config: str = typer.Option("config.yaml", "--config", "-c"),
    model:  str = typer.Option("llama3.2:3b", "--model", "-m", help="Ollama model"),
    output: str = typer.Option("results", "--output", "-o"),
    cookie: str = typer.Option("", "--cookie", "-C", help='Session cookies'),
    bearer: str = typer.Option("", "--bearer", "-b", help="Bearer token"),
):
    """
    Autonomous AI agent — finds business logic flaws, IDOR, OAuth bugs, and
    race conditions that static scanning misses.

    The agent drives a real browser (Playwright), uses local AI (Ollama) to
    decide each action, and iterates: observe → think → act → repeat.

    Run standalone or after a scan:
      python main.py agent https://target.com
    """
    console.print(Panel(BANNER, style="bold magenta"), justify="center")
    console.print("[bold magenta]AUTONOMOUS AI AGENT[/bold magenta] — Logic Flaw Hunter\n")

    result = asyncio.run(_run_agent(target, config, model, output, cookie, bearer))
    if result:
        console.print(Panel(
            f"[bold magenta]Findings: {result['findings_count']}[/bold magenta]\n"
            f"Duration: {result['duration']}s",
            title="Agent Complete",
            style="magenta",
        ))
        t = Table(title="Output Files")
        t.add_column("Format", style="cyan")
        t.add_column("Path")
        for fmt, path in result.get("report_paths", {}).items():
            t.add_row(fmt.upper(), str(path))
        console.print(t)


async def _run_agent(
    target: str, config_path: str, model: str, output: str,
    cookie: str, bearer: str,
) -> dict | None:
    import time as _time
    from pathlib import Path
    from core.pipeline import load_config
    from core.rate_limiter import RateLimiter
    from core.output import init_output_folder
    from core.ai_agent import AIAgent
    from modules.vulns.idor_chain import IdorChain
    from modules.vulns.oauth_tester import OAuthTester
    from modules.vulns.race_advanced import RaceAdvanced
    from modules.vulns.business_logic import BusinessLogic
    from scoring.engine import score_findings
    from reports.generator import generate_report

    cfg = load_config(config_path)
    cfg["ai"]["enabled"] = True
    cfg["ai"]["model"]   = model
    cfg["output"]["results_dir"] = output

    if cookie:
        cfg["auth"] = {"type": "cookie", "cookie": cookie}
    elif bearer:
        cfg["auth"] = {"type": "bearer", "bearer": bearer}

    from core.auth import AuthManager
    from core.http_client import set_global_auth

    session = init_output_folder(cfg["output"]["results_dir"])
    limiter = RateLimiter.from_config(cfg)

    ctx = {
        "target_url": target,
        "config":     cfg,
        "limiter":    limiter,
        "session":    session,
        "endpoints":  [target],
        "forms":      [],
        "recon":      {},
        "scan":       {},
    }

    auth = await AuthManager.from_config(cfg, ctx)
    set_global_auth(auth.get_cookies(), auth.get_headers())
    ctx["auth"] = auth

    # ── Quick crawl to seed endpoints ─────────────────────────────────────────
    console.print("[cyan]Crawling target to discover endpoints...[/cyan]")
    from modules.scan.crawler import Crawler
    try:
        crawl_result = await asyncio.wait_for(Crawler().run(ctx), timeout=60)
        if isinstance(crawl_result, list):
            pass  # findings added to ctx["endpoints"] by the crawler
    except Exception:
        pass
    if len(ctx["endpoints"]) <= 1:
        from core.pipeline import _seed_endpoints
        _seed_endpoints(ctx)
    console.print(f"[dim]Endpoints: {len(ctx['endpoints'])}[/dim]\n")

    start = _time.time()
    all_findings = []

    # ── Module 1: IDOR Chain ──────────────────────────────────────────────────
    console.print("[cyan]Running IDOR chain analysis...[/cyan]")
    try:
        fs = await asyncio.wait_for(IdorChain().run(ctx), timeout=120)
        all_findings.extend(fs)
        console.print(f"  IDOR chain: [green]{len(fs)} finding(s)[/green]")
    except Exception as e:
        console.print(f"  IDOR chain: [yellow]skipped ({e})[/yellow]")

    # ── Module 2: OAuth Tester ────────────────────────────────────────────────
    console.print("[cyan]Testing OAuth 2.0 / OIDC flows...[/cyan]")
    try:
        fs = await asyncio.wait_for(OAuthTester().run(ctx), timeout=60)
        all_findings.extend(fs)
        console.print(f"  OAuth: [green]{len(fs)} finding(s)[/green]")
    except Exception as e:
        console.print(f"  OAuth: [yellow]skipped ({e})[/yellow]")

    # ── Module 3: Race Conditions ─────────────────────────────────────────────
    console.print("[cyan]Testing race conditions on state-changing endpoints...[/cyan]")
    try:
        fs = await asyncio.wait_for(RaceAdvanced().run(ctx), timeout=120)
        all_findings.extend(fs)
        console.print(f"  Race conditions: [green]{len(fs)} finding(s)[/green]")
    except Exception as e:
        console.print(f"  Race conditions: [yellow]skipped ({e})[/yellow]")

    # ── Module 4: Business Logic ──────────────────────────────────────────────
    console.print("[cyan]Testing business logic flaws...[/cyan]")
    try:
        fs = await asyncio.wait_for(BusinessLogic().run(ctx), timeout=120)
        all_findings.extend(fs)
        console.print(f"  Business logic: [green]{len(fs)} finding(s)[/green]")
    except Exception as e:
        console.print(f"  Business logic: [yellow]skipped ({e})[/yellow]")

    # ── Module 5: AI Agent (browser-driven) ───────────────────────────────────
    console.print("\n[magenta]Starting autonomous AI agent (Playwright + Ollama)...[/magenta]")
    try:
        agent_inst = AIAgent(cfg, session_dir=session / "agent_screenshots")
        fs = await asyncio.wait_for(agent_inst.run(ctx), timeout=300)
        all_findings.extend(fs)
        console.print(f"  AI agent: [green]{len(fs)} finding(s)[/green]")
    except Exception as e:
        console.print(f"  AI agent: [yellow]skipped ({e})[/yellow]")

    duration = round(_time.time() - start, 1)
    console.print()
    for f in all_findings:
        sev_color = {"Critical": "red", "High": "red", "Medium": "yellow",
                     "Low": "blue", "Info": "dim"}.get(
            getattr(f, "severity", "Info"), "white"
        )
        title = getattr(f, "title", str(f))
        console.print(f"  [{sev_color}]{getattr(f, 'severity','?'):8s}[/{sev_color}] {title}")

    # ── Report ────────────────────────────────────────────────────────────────
    score_data = score_findings(all_findings, cfg)
    sorted_findings = [
        f.to_dict() for f in sorted(
            all_findings,
            key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}.get(x.severity, 5)
        )
    ]
    report_data = {
        "target_url":       target,
        "scan_date":        _time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": duration,
        "meta":             {},
        "recon":            {},
        "scan":             {},
        "findings":         sorted_findings,
        "score":            score_data,
        "compliance":       {},
    }
    output_paths = generate_report(report_data, session)
    console.print(f"\n[green]Report saved:[/green] {session}")

    return {
        "findings_count": len(all_findings),
        "duration":       duration,
        "report_paths":   output_paths,
    }


@app.command()
def validate(
    target: str = typer.Argument(..., help="Target URL to validate"),
):
    """Validate a target URL (format + DNS + reachability) without scanning."""
    from core.validator import validate_target, ValidationError
    try:
        meta = validate_target(target)
        console.print(f"[green]Valid target[/green]: {meta}")
    except ValidationError as e:
        console.print(f"[red]Invalid:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def analyze(
    target: str = typer.Argument(
        "", help="Target URL — leave empty to use the last scan automatically"
    ),
    config: str = typer.Option("config.yaml", "--config", "-c"),
    model:  str = typer.Option("llama3.2:3b", "--model", "-m",
                                help="Ollama model to use for AI analysis"),
):
    """
    AI-powered post-scan exploitation.

    Loads the most recent scan report, activates the local AI (Ollama),
    selects the most exploitable findings, runs deep exploitation routines,
    captures Playwright PoC screenshots, and generates a PoC report.

    Run AFTER a scan:
      python main.py scan https://target.com
      python main.py analyze
    """
    console.print(Panel(BANNER, style="bold red"), justify="center")
    console.print("[bold red]AI EXPLOIT ENGINE[/bold red] — Post-Scan Exploitation\n")

    result = asyncio.run(_run_analyze(target, config, model))
    if result:
        console.print(Panel(
            f"[bold red]Confirmed exploits: {result['confirmed']}[/bold red]\n"
            f"Attempted: {result['attempted']}   Duration: {result['duration']}s",
            title="Exploitation Complete",
            style="red",
        ))
        t = Table(title="PoC Report")
        t.add_column("Format", style="cyan")
        t.add_column("Path")
        for fmt, path in result.get("report_paths", {}).items():
            t.add_row(fmt.upper(), str(path))
        console.print(t)


async def _run_analyze(target: str, config_path: str, model: str):
    import glob
    import json as _json
    from pathlib import Path

    from core.pipeline import load_config
    from core.ai_engine import AIEngine
    from core.exploit_verifier import ExploitVerifier
    from core.exploit_engine import ExploitEngine
    from core.rate_limiter import RateLimiter
    from reports.poc_report import generate_poc_report

    cfg = load_config(config_path)
    # Force AI on for this command
    cfg["ai"]["enabled"] = True
    cfg["ai"]["model"]   = model

    # Find latest scan report
    pattern = cfg.get("output", {}).get("results_dir", "results") + "/*/report/report.json"
    reports = sorted(glob.glob(pattern))

    if not reports:
        console.print("[red]No scan reports found. Run a scan first:[/red]")
        console.print("  python main.py scan https://target.com")
        return None

    latest = reports[-1]
    console.print(f"[dim]Loading scan report: {latest}[/dim]\n")

    data     = _json.loads(Path(latest).read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    scan_target = target or data.get("target_url", "")
    session  = Path(latest).parent.parent

    if not findings:
        console.print("[yellow]No findings in report to exploit.[/yellow]")
        return None

    console.print(f"[bold]Target:[/bold] {scan_target}")
    console.print(f"[bold]Findings loaded:[/bold] {len(findings)}")
    console.print(f"[bold]Model:[/bold] {model}")
    console.print()

    # ── PHASE 1: AI analysis (Ollama runs, uses RAM) ──────────────────────────
    console.print("[cyan]PHASE 1: Starting local AI (Ollama)...[/cyan]")
    ai = AIEngine(cfg)
    ready = await ai.start()
    if not ready:
        console.print("[yellow]AI not available — using rule-based target selection[/yellow]")

    ai_chains    = []
    ai_targets   = []

    if ai.active:
        console.print("[cyan]AI reading findings and building attack plan...[/cyan]")
        ai_chains  = await ai.analyze_chain(findings)
        # AI selects best targets using same prompt as ExploitEngine
        from core.exploit_engine import ExploitEngine as _EE
        _tmp_engine = _EE(cfg=cfg, ai=ai, verifier=None)
        ai_targets = await _tmp_engine._ai_select_targets(findings)
        if ai_chains:
            console.print(f"[green]AI found {len(ai_chains)} exploit chain(s)[/green]")
        if ai_targets:
            console.print(f"[green]AI selected {len(ai_targets)} targets to exploit[/green]")
        console.print()
        # ── STOP Ollama — free 2GB RAM before exploitation ────────────────────
        console.print("[dim]Unloading AI model to free RAM...[/dim]")
        await ai.stop()
        await __import__("asyncio").sleep(2)   # let OS reclaim pages

    import psutil
    ram_free = psutil.virtual_memory().available // 1024 // 1024
    console.print(f"[dim]RAM free before exploitation: {ram_free} MB[/dim]\n")

    # ── PHASE 2: Exploitation (Ollama dead, full RAM available) ───────────────
    console.print("[bold red]PHASE 2: Running exploitation routines...[/bold red]\n")
    verifier = ExploitVerifier(max_concurrent=1)   # 1 browser at a time
    if verifier.available:
        console.print("[green]Playwright ready — PoC screenshots enabled[/green]\n")

    limiter = RateLimiter.from_config(cfg)
    ctx = {
        "target_url": scan_target,
        "config":     cfg,
        "limiter":    limiter,
        "endpoints":  [f.get("affected_url","") for f in findings if f.get("affected_url")],
        "forms":      [],
        "recon":      data.get("recon", {}),
        "scan":       data.get("scan", {}),
    }

    start   = __import__("time").time()
    engine  = ExploitEngine(cfg=cfg, ai=None, verifier=verifier)  # ai=None, already done
    # Pass AI-selected targets so engine doesn't need AI at runtime
    if ai_targets:
        ctx["_ai_targets"] = ai_targets
    results = await engine.run(findings, ctx)
    duration = round(__import__("time").time() - start, 1)

    confirmed = sum(1 for r in results if r.success)
    console.print()
    for r in results:
        status = "[green]CONFIRMED[/green]" if r.success else "[yellow]PARTIAL[/yellow]"
        console.print(f"  {status} {r.title}")
        if r.output:
            preview = r.output[:80].replace("\n", " ")
            console.print(f"           [dim]{preview}[/dim]")

    # Generate PoC report
    console.print("\n[cyan]Generating PoC report...[/cyan]")
    poc_path = generate_poc_report(
        target    = scan_target,
        results   = results,
        ai_chains = [c for c in ai_chains if isinstance(c, dict)],
        session   = session,
    )
    console.print(f"[green]PoC report saved:[/green] {poc_path}")

    return {
        "confirmed":    confirmed,
        "attempted":    len(results),
        "duration":     duration,
        "report_paths": {"html": str(poc_path), "json": str(poc_path).replace(".html", ".json")},
    }


if __name__ == "__main__":
    app()
