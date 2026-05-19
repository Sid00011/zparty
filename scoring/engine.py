import logging
from pathlib import Path
import yaml
from core.finding import Finding

logger = logging.getLogger(__name__)

DEFAULT_PENALTIES = {"Critical": 40, "High": 20, "Medium": 8, "Low": 3, "Info": 0}
DEFAULT_GRADES = [("S", 90), ("A", 75), ("B", 60), ("C", 45), ("D", 30), ("E", 0)]


def _load_weights(cfg: dict) -> dict:
    # Use path relative to this file so it works regardless of cwd
    weights_path = Path(__file__).parent / "weights.yaml"
    if not weights_path.exists():
        return {}
    try:
        with open(weights_path, encoding="utf-8-sig") as f:
            w = yaml.safe_load(f)
        return w or {}
    except Exception as e:
        logger.warning(f"Could not load weights.yaml ({e}) — using defaults")
        return {}


def score_findings(findings: list[Finding], cfg: dict) -> dict:
    weights = _load_weights(cfg)
    penalties = weights.get("severity_penalties", DEFAULT_PENALTIES)
    cap_mult = weights.get("cap_multiplier", 2)
    grade_thresholds = sorted(
        [(g, v) for g, v in weights.get("grades", {}).items()],
        key=lambda x: x[1], reverse=True
    ) or DEFAULT_GRADES

    # Aggregate penalties by (severity, title) groups to cap per finding type
    from collections import defaultdict
    by_type: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_type[f"{f.severity}:{f.title}"].append(f)

    total_deduction = 0
    breakdown = []

    for key, group in by_type.items():
        severity = group[0].severity
        base_penalty = penalties.get(severity, 0)
        count = len(group)
        deduction = min(count * base_penalty, cap_mult * base_penalty)
        total_deduction += deduction
        rep = group[0]
        breakdown.append({
            "key": key,
            "count": count,
            "base_penalty": base_penalty,
            "deduction": deduction,
            "cvss_score": rep.cvss_score,
            "cvss_vector": rep.cvss_vector,
            "cwe": rep.cwe,
        })

    raw_score = max(0, 100 - total_deduction)

    # Grade
    grade = "E"
    for g, threshold in grade_thresholds:
        if raw_score >= threshold:
            grade = g
            break

    # Severity counts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    result = {
        "score": raw_score,
        "grade": grade,
        "total_deduction": total_deduction,
        "severity_counts": sev_counts,
        "breakdown": breakdown,
        "total_findings": len(findings),
        "grade_description": _grade_desc(grade),
    }
    logger.info(f"Score: {raw_score}/100 Grade: {grade} | {sev_counts}")
    return result


def _grade_desc(grade: str) -> str:
    return {
        "S": "Excellent — no exploitable vulnerabilities detected.",
        "A": "Good — only informational or low-severity findings.",
        "B": "Acceptable — some medium/high findings require attention.",
        "C": "Concerning — multiple high-severity findings present.",
        "D": "Poor — critical vulnerabilities detected.",
        "E": "Critical — multiple critical vulnerabilities. Immediate action required.",
    }.get(grade, "")
