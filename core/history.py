"""
core/history.py — Scan history persistence and comparison

Stores every scan result in a SQLite database (results/zparty_history.db).
Provides:
  - save_scan()         — persist a completed scan
  - get_history()       — list past scans for a target
  - compare_scans()     — diff two scans: new / fixed / persistent findings
  - get_trend()         — score trend over time for a target
"""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DB_PATH = Path("results") / "zparty_history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    session     TEXT    NOT NULL UNIQUE,
    scan_date   TEXT    NOT NULL,
    timestamp   REAL    NOT NULL,
    duration    REAL    NOT NULL,
    score       REAL,
    grade       TEXT,
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    info        INTEGER DEFAULT 0,
    total       INTEGER DEFAULT 0,
    findings    TEXT,           -- JSON array of finding dicts
    meta        TEXT            -- JSON dict of scan metadata
);

CREATE INDEX IF NOT EXISTS idx_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp);
"""


def _get_db(db_path: Path = _DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


class HistoryManager:
    """Thread-safe (single-writer) scan history manager."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or _DB_PATH

    # ── Write ─────────────────────────────────────────────────────────────────

    def save_scan(self, result: dict, findings: list[dict]) -> int:
        """
        Persist a completed scan.
        result  : pipeline return dict (session, score, grade, findings_count, …)
        findings: list of finding.to_dict() dicts
        Returns the new row id.
        """
        score_data = result.get("score_data", {})
        sev = result.get("severity_counts", score_data.get("severity_counts", {}))
        try:
            conn = _get_db(self._db_path)
            cur = conn.execute(
                """
                INSERT OR REPLACE INTO scans
                  (target, session, scan_date, timestamp, duration,
                   score, grade, critical, high, medium, low, info, total,
                   findings, meta)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    result.get("target_url", ""),
                    result.get("session", ""),
                    result.get("scan_date", ""),
                    time.time(),
                    result.get("duration", 0),
                    result.get("score"),
                    result.get("grade", "?"),
                    sev.get("Critical", 0),
                    sev.get("High", 0),
                    sev.get("Medium", 0),
                    sev.get("Low", 0),
                    sev.get("Info", 0),
                    result.get("findings_count", len(findings)),
                    json.dumps(findings, default=str),
                    json.dumps({
                        "meta": result.get("meta", {}),
                        "report_paths": result.get("report_paths", {}),
                    }, default=str),
                ),
            )
            conn.commit()
            row_id = cur.lastrowid
            conn.close()
            logger.info(f"History: scan saved (id={row_id}, target={result.get('target_url')})")
            return row_id
        except Exception as e:
            logger.warning(f"History: failed to save scan: {e}")
            return -1

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_history(self, target: str, limit: int = 20) -> list[dict]:
        """Return past scans for a target, newest first."""
        try:
            conn = _get_db(self._db_path)
            rows = conn.execute(
                """SELECT id, target, session, scan_date, timestamp, duration,
                          score, grade, critical, high, medium, low, info, total
                   FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT ?""",
                (target, limit),
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"History: get_history failed: {e}")
            return []

    def get_all_targets(self) -> list[str]:
        """Return all unique targets ever scanned."""
        try:
            conn = _get_db(self._db_path)
            rows = conn.execute(
                "SELECT DISTINCT target FROM scans ORDER BY target"
            ).fetchall()
            conn.close()
            return [r["target"] for r in rows]
        except Exception:
            return []

    def get_trend(self, target: str, limit: int = 10) -> list[dict]:
        """Return score trend (date, score, grade, total) for a target."""
        history = self.get_history(target, limit=limit)
        return [
            {"date": h["scan_date"], "score": h["score"],
             "grade": h["grade"], "total": h["total"]}
            for h in reversed(history)
        ]

    # ── Compare ───────────────────────────────────────────────────────────────

    def compare_scans(self, target: str) -> dict:
        """
        Compare the two most recent scans for a target.
        Returns:
          new_findings        — in latest but not in previous
          fixed_findings      — in previous but not in latest
          persistent_findings — in both
          score_delta         — score change (+/-)
        """
        history = self.get_history(target, limit=2)
        if len(history) < 2:
            return {
                "available": False,
                "message": "Need at least 2 scans to compare",
            }

        latest_row, prev_row = history[0], history[1]

        try:
            conn = _get_db(self._db_path)
            def _findings(session: str) -> list[dict]:
                row = conn.execute(
                    "SELECT findings FROM scans WHERE session=?", (session,)
                ).fetchone()
                if row and row["findings"]:
                    return json.loads(row["findings"])
                return []

            latest_findings = _findings(latest_row["session"])
            prev_findings   = _findings(prev_row["session"])
            conn.close()
        except Exception as e:
            logger.warning(f"History: compare failed: {e}")
            return {"available": False, "message": str(e)}

        # Key = (title, affected_url path) for stable comparison
        from urllib.parse import urlparse

        def _key(f: dict) -> str:
            path = urlparse(f.get("affected_url", "")).path
            return f"{f.get('title', '')}||{path}"

        latest_keys = {_key(f): f for f in latest_findings}
        prev_keys   = {_key(f): f for f in prev_findings}

        new_findings        = [f for k, f in latest_keys.items() if k not in prev_keys]
        fixed_findings      = [f for k, f in prev_keys.items()   if k not in latest_keys]
        persistent_findings = [f for k, f in latest_keys.items() if k in prev_keys]

        score_delta = None
        if latest_row["score"] is not None and prev_row["score"] is not None:
            score_delta = round(latest_row["score"] - prev_row["score"], 1)

        return {
            "available":           True,
            "latest_scan_date":    latest_row["scan_date"],
            "previous_scan_date":  prev_row["scan_date"],
            "score_delta":         score_delta,
            "grade_latest":        latest_row["grade"],
            "grade_previous":      prev_row["grade"],
            "new_findings":        new_findings,
            "fixed_findings":      fixed_findings,
            "persistent_findings": persistent_findings,
            "new_count":           len(new_findings),
            "fixed_count":         len(fixed_findings),
            "persistent_count":    len(persistent_findings),
        }
