"""
ui/server.py — Zparty Web UI
Run: python ui_launch.py  →  http://localhost:8000
"""
import asyncio
import json
import logging
import re
import sys
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

app = FastAPI(title="Zparty", docs_url=None, redoc_url=None)

SCANS: dict[str, dict] = {}
TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"

PHASE_LABELS = {
    0: "Validation",
    1: "Passive Reconnaissance",
    2: "Active Scanning",
    3: "Vulnerability Modules",
    4: "Scoring",
    5: "Report Generation",
}
PHASE_RE = re.compile(r"Phase\s+(\d+)", re.IGNORECASE)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content=TEMPLATE_PATH.read_text(encoding="utf-8"))


class ScanRequest(BaseModel):
    target: str
    config: str = "config.yaml"
    cookie: str = ""
    bearer: str = ""


class AgentRequest(BaseModel):
    target: str
    config: str = "config.yaml"
    cookie: str = ""
    bearer: str = ""
    model:  str = "llama3.2:3b"


@app.post("/api/agent")
async def start_agent(req: AgentRequest):
    scan_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    SCANS[scan_id] = {
        "status": "running",
        "phase": 0,
        "logs": [],
        "result": None,
        "progress": 0,
        "queue": queue,
        "mode": "agent",
    }
    asyncio.create_task(_run_agent_scan(
        scan_id, req.target, req.config, req.model, req.cookie, req.bearer
    ))
    return {"scan_id": scan_id}


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    SCANS[scan_id] = {
        "status": "running",
        "phase": 0,
        "logs": [],
        "result": None,
        "progress": 0,
        "queue": queue,
    }
    asyncio.create_task(_run_scan(scan_id, req.target, req.config))
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "status": scan["status"],
        "phase": scan["phase"],
        "progress": scan["progress"],
        "result": scan["result"],
        "log_count": len(scan["logs"]),
    }


@app.websocket("/ws/{scan_id}")
async def ws_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    scan = SCANS.get(scan_id)
    if not scan:
        await websocket.send_json({"type": "error", "message": "Scan not found"})
        await websocket.close()
        return

    # Replay history then drain queue — avoid sending the same message twice
    replayed = set()
    for entry in scan["logs"]:
        try:
            msg_id = id(entry)
            replayed.add(msg_id)
            await websocket.send_json(entry)
        except Exception:
            pass

    queue: asyncio.Queue = scan["queue"]
    # Drain any items already in queue that were also in logs (same object refs)
    drained = []
    while not queue.empty():
        try:
            item = queue.get_nowait()
            if id(item) not in replayed:
                drained.append(item)
        except asyncio.QueueEmpty:
            break
    for item in drained:
        try:
            await websocket.send_json(item)
            if item.get("type") == "done":
                return
        except Exception:
            pass

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=60)
                await websocket.send_json(msg)
                if msg.get("type") == "done":
                    break
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        pass


# ── Report endpoints ──────────────────────────────────────────────────────────
@app.get("/report/{scan_id}/html")
async def serve_html(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("result"):
        raise HTTPException(404, "Report not ready")
    paths = scan["result"].get("report_paths", {})
    p = paths.get("html")
    if not p or not Path(p).exists():
        raise HTTPException(404, "HTML report not found")
    return FileResponse(p, media_type="text/html")


@app.get("/report/{scan_id}/pdf")
async def serve_pdf(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("result"):
        raise HTTPException(404, "Report not ready")
    paths = scan["result"].get("report_paths", {})
    p = paths.get("pdf")
    if not p or not Path(p).exists():
        raise HTTPException(404, "PDF not generated — WeasyPrint may not be installed. Use the HTML report instead.")
    return FileResponse(p, media_type="application/pdf",
                        filename=f"zparty_{scan_id[:8]}.pdf")


@app.get("/report/{scan_id}/json")
async def serve_json_report(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("result"):
        raise HTTPException(404, "Report not ready")
    paths = scan["result"].get("report_paths", {})
    p = paths.get("json")
    if not p or not Path(p).exists():
        raise HTTPException(404, "JSON report not found")
    return FileResponse(p, media_type="application/json",
                        filename=f"zparty_{scan_id[:8]}.json")


@app.get("/report-data/{scan_id}")
async def report_data(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("result"):
        raise HTTPException(404)
    paths = scan["result"].get("report_paths", {})
    p = paths.get("json")
    if p and Path(p).exists():
        return JSONResponse(content=json.loads(Path(p).read_text()))
    raise HTTPException(404)


# ── Exploit endpoint ─────────────────────────────────────────────────────────
@app.post("/api/exploit/{scan_id}")
async def start_exploit(scan_id: str):
    """Start AI exploitation against findings from a completed scan."""
    source = SCANS.get(scan_id)
    if not source or source.get("status") != "done":
        raise HTTPException(400, "Scan not done or not found")

    result = source.get("result", {})
    report_paths = result.get("report_paths", {})
    json_path = report_paths.get("json", "")
    if not json_path or not Path(json_path).exists():
        raise HTTPException(404, "No scan report found — cannot exploit")

    exploit_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    SCANS[exploit_id] = {
        "status": "running",
        "phase": 0,
        "logs": [],
        "result": None,
        "progress": 0,
        "queue": queue,
        "mode": "exploit",
        "source_scan": scan_id,
    }
    asyncio.create_task(_run_exploit(exploit_id, json_path, result.get("target_url", "")))
    return {"exploit_id": exploit_id}


async def _run_exploit(exploit_id: str, report_json_path: str, target_url: str):
    scan  = SCANS[exploit_id]
    queue: asyncio.Queue = scan["queue"]

    EXPLOIT_PHASES = {
        0: "Loading Findings",
        1: "AI Analysis (Ollama)",
        2: "Running Exploit Engine",
        3: "Playwright PoC Screenshots",
        4: "PoC Report",
    }

    def emit(msg: dict):
        scan["logs"].append(msg)
        queue.put_nowait(msg)

    def emit_phase(n: int):
        scan["phase"] = n
        emit({"type": "phase", "phase": n, "label": EXPLOIT_PHASES.get(n, f"Step {n}")})

    class QueueHandler(logging.Handler):
        def emit(self, record: logging.LogRecord):
            if record.name.startswith("stem") and "SocketClosed" in record.getMessage():
                return
            text = self.format(record)
            log_msg = {"type": "log", "level": record.levelname,
                       "text": text, "module": record.name.split(".")[-1]}
            scan["logs"].append(log_msg)
            queue.put_nowait(log_msg)

    handler = QueueHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    try:
        import time as _time
        import json as _json
        from pathlib import Path as _Path
        from core.pipeline import load_config
        from core.rate_limiter import RateLimiter
        from core.output import init_output_folder
        from core.ai_engine import AIEngine
        from core.exploit_verifier import ExploitVerifier
        from core.exploit_engine import ExploitEngine
        from reports.poc_report import generate_poc_report

        emit_phase(0)
        data     = _json.loads(_Path(report_json_path).read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        session  = _Path(report_json_path).parent.parent

        if not findings:
            emit({"type": "error", "message": "No findings to exploit"})
            emit({"type": "done", "score": 0, "grade": "N/A",
                  "findings_count": 0, "duration": 0,
                  "confirmed": 0, "exploit_results": [], "report_paths": {}})
            return

        emit({"type": "log", "level": "INFO", "module": "exploit",
              "text": f"Loaded {len(findings)} findings — starting AI analysis"})

        cfg = load_config("config.yaml")
        cfg["ai"]["enabled"] = True
        limiter = RateLimiter.from_config(cfg)
        ctx = {
            "target_url": target_url or data.get("target_url", ""),
            "config":     cfg,
            "limiter":    limiter,
            "endpoints":  [f.get("affected_url", "") for f in findings if f.get("affected_url")],
            "forms":      [],
            "recon":      data.get("recon", {}),
            "scan":       data.get("scan", {}),
        }

        start = _time.time()

        # Phase 1 — AI selects targets
        emit_phase(1)
        ai = AIEngine(cfg)
        ai_ready = await ai.start()
        ai_chains  = []
        ai_targets = []

        if ai_ready and ai.active:
            emit({"type": "log", "level": "INFO", "module": "AIEngine",
                  "text": "AI model loaded — analysing findings and building attack plan"})
            ai_chains = await ai.analyze_chain(findings)
            tmp_engine = ExploitEngine(cfg=cfg, ai=ai, verifier=None)
            ai_targets = await tmp_engine._ai_select_targets(findings)
            emit({"type": "log", "level": "INFO", "module": "AIEngine",
                  "text": f"AI selected {len(ai_targets)} target(s), found {len(ai_chains)} chain(s)"})
            await ai.stop()
            await asyncio.sleep(1)
        else:
            emit({"type": "log", "level": "WARNING", "module": "AIEngine",
                  "text": "Ollama not available — using rule-based target selection"})

        # Phase 2 — Exploitation
        emit_phase(2)
        verifier = ExploitVerifier(max_concurrent=1)
        if verifier.available:
            emit({"type": "log", "level": "INFO", "module": "Playwright",
                  "text": "Playwright ready — PoC screenshots enabled"})

        engine = ExploitEngine(cfg=cfg, ai=None, verifier=verifier)
        if ai_targets:
            ctx["_ai_targets"] = ai_targets

        results = await engine.run(findings, ctx)

        # Phase 3 — Screenshots note
        emit_phase(3)
        confirmed = [r for r in results if r.success]
        emit({"type": "log", "level": "INFO", "module": "ExploitEngine",
              "text": f"Exploitation complete — {len(confirmed)}/{len(results)} confirmed"})

        for r in results:
            status = "CONFIRMED" if r.success else "partial"
            emit({"type": "exploit_result",
                  "title":     r.title,
                  "success":   r.success,
                  "output":    (r.output or "")[:400],
                  "screenshot": str(r.screenshot) if getattr(r, "screenshot", None) else None})
            emit({"type": "log", "level": "INFO" if r.success else "WARNING",
                  "module": "exploit",
                  "text": f"[{status}] {r.title}"})

        # Phase 4 — PoC Report
        emit_phase(4)
        poc_path = generate_poc_report(
            target    = ctx["target_url"],
            results   = results,
            ai_chains = [c for c in ai_chains if isinstance(c, dict)],
            session   = session,
        )
        duration = round(_time.time() - start, 1)
        emit({"type": "log", "level": "INFO", "module": "exploit",
              "text": f"PoC report saved: {poc_path}"})

        exploit_results_out = [
            {"title": r.title, "success": r.success,
             "output": (r.output or "")[:400],
             "screenshot": str(r.screenshot) if getattr(r, "screenshot", None) else None}
            for r in results
        ]

        scan["result"] = {
            "confirmed":       len(confirmed),
            "attempted":       len(results),
            "duration":        duration,
            "report_paths":    {"html": str(poc_path),
                                "json": str(poc_path).replace(".html", ".json")},
            "exploit_results": exploit_results_out,
        }
        scan["status"]   = "done"
        scan["progress"] = 100

        emit({
            "type":            "done",
            "confirmed":       len(confirmed),
            "attempted":       len(results),
            "duration":        duration,
            "exploit_results": exploit_results_out,
            "report_paths":    scan["result"]["report_paths"],
        })

    except Exception as e:
        logging.exception(f"Exploit error: {e}")
        emit({"type": "error", "message": str(e)})
        scan["status"] = "error"
        emit({"type": "done", "confirmed": 0, "attempted": 0,
              "duration": 0, "exploit_results": [], "report_paths": {}})
    finally:
        root_logger.removeHandler(handler)


# ── Scan runner ───────────────────────────────────────────────────────────────
async def _run_scan(scan_id: str, target: str, config_path: str):
    scan = SCANS[scan_id]
    queue: asyncio.Queue = scan["queue"]
    emitted_phases: set[int] = set()

    def emit(msg: dict):
        scan["logs"].append(msg)
        queue.put_nowait(msg)

    def emit_phase(n: int):
        if n in emitted_phases:
            return
        emitted_phases.add(n)
        scan["phase"] = n
        p_msg = {"type": "phase", "phase": n, "label": PHASE_LABELS.get(n, f"Phase {n}")}
        emit(p_msg)

    class QueueHandler(logging.Handler):
        def emit(self, record: logging.LogRecord):
            if record.name.startswith("stem") and "SocketClosed" in record.getMessage():
                return
            text = self.format(record)
            # Auto-detect phase from pipeline's === Phase N === log lines
            m = PHASE_RE.search(text)
            if m and "===" in text:
                emit_phase(int(m.group(1)))
            log_msg = {
                "type": "log",
                "level": record.levelname,
                "text": text,
                "module": record.name.split(".")[-1],
            }
            scan["logs"].append(log_msg)
            queue.put_nowait(log_msg)

    handler = QueueHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    emit_phase(0)

    try:
        from core.pipeline import run_pipeline

        result = await run_pipeline(target, config_path)

        scan["result"] = result
        scan["status"] = "done"
        scan["progress"] = 100

        emit_phase(5)

        emit({
            "type": "done",
            "score": result.get("score", 0),
            "grade": result.get("grade", "E"),
            "findings_count": result.get("findings_count", 0),
            "duration": result.get("duration", 0),
            "report_paths": result.get("report_paths", {}),
        })

    except Exception as e:
        logging.exception(f"Pipeline error: {e}")
        emit({"type": "error", "message": str(e)})
        scan["status"] = "error"
        emit({
            "type": "done",
            "score": 0,
            "grade": "E",
            "findings_count": 0,
            "duration": 0,
            "report_paths": {},
        })
    finally:
        root_logger.removeHandler(handler)


async def _run_agent_scan(
    scan_id: str, target: str, config_path: str,
    model: str, cookie: str, bearer: str
):
    scan  = SCANS[scan_id]
    queue: asyncio.Queue = scan["queue"]

    AGENT_PHASE_LABELS = {
        0: "Initialising",
        1: "Crawling Target",
        2: "IDOR Chain Analysis",
        3: "OAuth / OIDC Testing",
        4: "Race Conditions",
        5: "Business Logic",
        6: "AI Browser Agent",
        7: "Report",
    }

    def emit(msg: dict):
        scan["logs"].append(msg)
        queue.put_nowait(msg)

    def emit_phase(n: int, label: str = ""):
        scan["phase"] = n
        emit({"type": "phase", "phase": n,
              "label": label or AGENT_PHASE_LABELS.get(n, f"Step {n}")})

    class QueueHandler(logging.Handler):
        def emit(self, record: logging.LogRecord):
            if record.name.startswith("stem") and "SocketClosed" in record.getMessage():
                return
            text = self.format(record)
            log_msg = {"type": "log", "level": record.levelname,
                       "text": text, "module": record.name.split(".")[-1]}
            scan["logs"].append(log_msg)
            queue.put_nowait(log_msg)

    handler = QueueHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    try:
        import time as _time
        from pathlib import Path
        from core.pipeline import load_config, _seed_endpoints
        from core.rate_limiter import RateLimiter
        from core.output import init_output_folder
        from core.auth import AuthManager
        from core.http_client import set_global_auth
        from core.ai_agent import AIAgent
        from modules.vulns.idor_chain import IdorChain
        from modules.vulns.oauth_tester import OAuthTester
        from modules.vulns.race_advanced import RaceAdvanced
        from modules.vulns.business_logic import BusinessLogic
        from modules.scan.crawler import Crawler
        from scoring.engine import score_findings
        from reports.generator import generate_report

        emit_phase(0)
        cfg = load_config(config_path)
        cfg["ai"]["enabled"] = True
        cfg["ai"]["model"]   = model
        if cookie:
            cfg["auth"] = {"type": "cookie", "cookie": cookie}
        elif bearer:
            cfg["auth"] = {"type": "bearer", "bearer": bearer}

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

        # Phase 1 — Crawl
        emit_phase(1)
        try:
            await asyncio.wait_for(Crawler().run(ctx), timeout=60)
        except Exception:
            pass
        if len(ctx["endpoints"]) <= 1:
            _seed_endpoints(ctx)
        emit({"type": "log", "level": "INFO", "module": "agent",
              "text": f"Discovered {len(ctx['endpoints'])} endpoints"})

        all_findings = []
        start = _time.time()

        # Phase 2 — IDOR Chain
        emit_phase(2)
        try:
            fs = await asyncio.wait_for(IdorChain().run(ctx), timeout=120)
            all_findings.extend(fs)
            emit({"type": "log", "level": "INFO", "module": "IdorChain",
                  "text": f"[IdorChain] completed — {len(fs)} finding(s)"})
        except Exception as e:
            emit({"type": "log", "level": "WARNING", "module": "IdorChain",
                  "text": f"[IdorChain] skipped: {e}"})

        # Phase 3 — OAuth
        emit_phase(3)
        try:
            fs = await asyncio.wait_for(OAuthTester().run(ctx), timeout=60)
            all_findings.extend(fs)
            emit({"type": "log", "level": "INFO", "module": "OAuthTester",
                  "text": f"[OAuthTester] completed — {len(fs)} finding(s)"})
        except Exception as e:
            emit({"type": "log", "level": "WARNING", "module": "OAuthTester",
                  "text": f"[OAuthTester] skipped: {e}"})

        # Phase 4 — Race
        emit_phase(4)
        try:
            fs = await asyncio.wait_for(RaceAdvanced().run(ctx), timeout=120)
            all_findings.extend(fs)
            emit({"type": "log", "level": "INFO", "module": "RaceAdvanced",
                  "text": f"[RaceAdvanced] completed — {len(fs)} finding(s)"})
        except Exception as e:
            emit({"type": "log", "level": "WARNING", "module": "RaceAdvanced",
                  "text": f"[RaceAdvanced] skipped: {e}"})

        # Phase 5 — Business Logic
        emit_phase(5)
        try:
            fs = await asyncio.wait_for(BusinessLogic().run(ctx), timeout=120)
            all_findings.extend(fs)
            emit({"type": "log", "level": "INFO", "module": "BusinessLogic",
                  "text": f"[BusinessLogic] completed — {len(fs)} finding(s)"})
        except Exception as e:
            emit({"type": "log", "level": "WARNING", "module": "BusinessLogic",
                  "text": f"[BusinessLogic] skipped: {e}"})

        # Phase 6 — AI Browser Agent
        emit_phase(6)
        try:
            agent_inst = AIAgent(cfg, session_dir=session / "agent_screenshots")
            fs = await asyncio.wait_for(agent_inst.run(ctx), timeout=300)
            all_findings.extend(fs)
            emit({"type": "log", "level": "INFO", "module": "AIAgent",
                  "text": f"[AIAgent] completed — {len(fs)} finding(s)"})
        except Exception as e:
            emit({"type": "log", "level": "WARNING", "module": "AIAgent",
                  "text": f"[AIAgent] skipped: {e}"})

        # Phase 7 — Report
        emit_phase(7)
        from core.cvss import lookup as cvss_lookup
        for f in all_findings:
            if not f.cvss_vector:
                f.cvss_vector, f.cvss_score, f.cwe = cvss_lookup(f.title, f.severity)

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
            "duration_seconds": round(_time.time() - start, 1),
            "meta":             {},
            "recon":            {},
            "scan":             {},
            "findings":         sorted_findings,
            "score":            score_data,
            "compliance":       {},
        }
        output_paths = generate_report(report_data, session)

        result = {
            "session":         str(session),
            "score":           score_data.get("score", 0),
            "grade":           score_data.get("grade", "S"),
            "findings_count":  len(all_findings),
            "report_paths":    output_paths,
            "duration":        round(_time.time() - start, 1),
            "severity_counts": score_data.get("severity_counts", {}),
            "target_url":      target,
        }
        scan["result"]   = result
        scan["status"]   = "done"
        scan["progress"] = 100

        emit({
            "type":           "done",
            "score":          result["score"],
            "grade":          result["grade"],
            "findings_count": result["findings_count"],
            "duration":       result["duration"],
            "severity_counts": result["severity_counts"],
            "report_paths":   result["report_paths"],
        })

    except Exception as e:
        logging.exception(f"Agent error: {e}")
        emit({"type": "error", "message": str(e)})
        scan["status"] = "error"
        emit({"type": "done", "score": 0, "grade": "E",
              "findings_count": 0, "duration": 0, "report_paths": {}})
    finally:
        root_logger.removeHandler(handler)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  ⚡ Zparty UI — http://localhost:8000\n")
    uvicorn.run("ui.server:app", host="0.0.0.0", port=8000,
                reload=False, log_level="warning")
