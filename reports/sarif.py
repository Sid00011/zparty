"""
reports/sarif.py — SARIF 2.1.0 output for CI/CD integration

SARIF (Static Analysis Results Interchange Format) is the standard format
used by GitHub Code Scanning, GitLab SAST, and VS Code to display security
findings inline in pull requests.

Usage:
  from reports.sarif import generate_sarif
  sarif_path = generate_sarif(findings, session_path)
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME     = "Zparty"
TOOL_VERSION  = "1.0.0"
TOOL_URL      = "https://github.com/zparty/zparty"

# Map severity → SARIF level
_SEV_LEVEL = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
    "Info":     "none",
}

# Map severity → SARIF security-severity (CVSS-like 0–10)
_SEV_SECURITY = {
    "Critical": "9.5",
    "High":     "7.5",
    "Medium":   "5.0",
    "Low":      "3.0",
    "Info":     "0.0",
}


def generate_sarif(findings: list[dict], session: Path) -> str | None:
    """
    Generate a SARIF 2.1.0 file from a list of finding dicts.
    Writes to session/report/report.sarif and returns the path.
    """
    report_dir = session / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = report_dir / "report.sarif"

    # Build rule index from unique finding titles
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        title   = f.get("title", "Unknown")
        sev     = f.get("severity", "Info")
        url     = f.get("affected_url", "")
        desc    = f.get("description", "")
        rem     = f.get("remediation", "")
        cwe     = f.get("cwe", "")
        cvss    = f.get("cvss_score", 0.0)
        vector  = f.get("cvss_vector", "")
        refs    = f.get("references", [])
        proof   = f.get("proof", "")

        rule_id = _sanitize_id(title)

        # Register rule if not seen
        if rule_id not in rules_seen:
            tags = [cwe] if cwe else []
            if cvss:
                tags.append(f"CVSS:{cvss}")

            rule = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": desc},
                "helpUri": refs[0] if refs else TOOL_URL,
                "help": {
                    "text": rem,
                    "markdown": f"**Remediation:** {rem}\n\n**CVSS:** {cvss} — {vector}",
                },
                "properties": {
                    "tags":              tags,
                    "security-severity": str(cvss) if cvss else _SEV_SECURITY.get(sev, "0.0"),
                    "precision":         "medium",
                    "problem.severity":  _SEV_LEVEL.get(sev, "note"),
                },
                "defaultConfiguration": {
                    "level": _SEV_LEVEL.get(sev, "note"),
                },
            }
            rules_seen[rule_id] = rule

        # Build result entry
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": url, "uriBaseId": "%SRCROOT%"},
            },
        }

        result_entry = {
            "ruleId":  rule_id,
            "level":   _SEV_LEVEL.get(sev, "note"),
            "message": {
                "text": f"{desc}\n\nProof:\n{proof[:500]}" if proof else desc,
            },
            "locations": [location],
            "properties": {
                "severity":   sev,
                "cvssScore":  cvss,
                "cvssVector": vector,
                "cwe":        cwe,
            },
        }

        # Add web request fingerprint if we have proof with GET/POST
        if proof and (proof.startswith("GET ") or proof.startswith("POST ")):
            result_entry["webRequest"] = {
                "target": url,
                "method": proof.split()[0],
            }

        results.append(result_entry)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":             TOOL_NAME,
                        "version":          TOOL_VERSION,
                        "informationUri":   TOOL_URL,
                        "rules":            list(rules_seen.values()),
                        "semanticVersion":  TOOL_VERSION,
                        "organization":     "Zparty Security",
                        "shortDescription": {"text": "Automated Web Penetration Testing Framework"},
                        "properties": {
                            "tags": ["security", "dast", "web-application"],
                        },
                    }
                },
                "results":   results,
                "artifacts": [{"location": {"uri": url}} for url in
                              list({f.get("affected_url", "") for f in findings}) if url],
            }
        ],
    }

    try:
        sarif_path.write_text(
            json.dumps(sarif_doc, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"SARIF report: {sarif_path}")
        return str(sarif_path)
    except Exception as e:
        logger.error(f"SARIF generation failed: {e}")
        return None


def _sanitize_id(title: str) -> str:
    """Convert a finding title to a valid SARIF rule ID."""
    import re
    return re.sub(r"[^a-zA-Z0-9._/-]", "_", title)[:128]
