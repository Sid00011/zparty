"""
reports/poc_report.py — Proof-of-Concept Exploitation Report Generator

Generates a standalone HTML report showing only confirmed exploits,
with embedded Playwright screenshots, reproduction steps, and impact.
"""
import json
import time
from pathlib import Path
from jinja2 import Template

POC_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Zparty PoC Report — {{ target }}</title>
<style>
  :root { --red:#dc2626;--orange:#ea580c;--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--green:#16a34a; }
  * { box-sizing:border-box;margin:0;padding:0; }
  body { font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px; }
  .header { background:#7f1d1d;padding:32px 48px;border-bottom:4px solid var(--red); }
  .header h1 { font-size:2rem;font-weight:900;color:#fff; }
  .header p { color:#fca5a5;margin-top:8px; }
  .stats { display:flex;gap:24px;padding:24px 48px;background:var(--surface);border-bottom:1px solid var(--border); }
  .stat { text-align:center; }
  .stat .n { font-size:2rem;font-weight:900;color:var(--red); }
  .stat .l { font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.05em; }
  .container { max-width:1100px;margin:0 auto;padding:40px 48px; }
  .poc-card { background:var(--surface);border:2px solid var(--red);border-radius:12px;padding:28px;margin-bottom:32px; }
  .poc-card.success { border-color:var(--red); }
  .poc-card.partial { border-color:var(--orange); }
  .poc-header { display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap; }
  .badge-crit { background:var(--red);color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700; }
  .badge-confirmed { background:var(--green);color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700; }
  .badge-partial { background:var(--orange);color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700; }
  .poc-title { font-size:1.2rem;font-weight:700; }
  .section-label { font-size:11px;font-weight:700;text-transform:uppercase;color:var(--muted);letter-spacing:.06em;margin:16px 0 6px; }
  .url { font-family:monospace;font-size:12px;color:#7dd3fc;word-break:break-all; }
  .output-box { background:#0a0a1a;border:1px solid var(--border);border-radius:6px;padding:14px;font-family:monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;color:#a5f3fc;margin:8px 0; }
  .steps-list { list-style:none;counter-reset:steps; }
  .steps-list li { counter-increment:steps;padding:6px 0 6px 32px;position:relative;border-bottom:1px solid var(--border);font-size:13px; }
  .steps-list li:before { content:counter(steps);position:absolute;left:0;top:6px;background:var(--red);color:#fff;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700; }
  .impact-box { background:rgba(220,38,38,.1);border-left:4px solid var(--red);padding:12px 16px;border-radius:0 6px 6px 0;margin:12px 0; }
  .screenshot-wrap { margin-top:20px;border-radius:8px;overflow:hidden;border:1px solid var(--border); }
  .screenshot-label { background:var(--green);color:#fff;padding:8px 16px;font-size:12px;font-weight:700;letter-spacing:.04em; }
  .screenshot-wrap img { display:block;width:100%;max-width:100%;height:auto; }
  .no-screenshot { background:var(--bg);padding:24px;text-align:center;color:var(--muted);font-size:13px; }
  .cvss { font-family:monospace;font-size:13px;font-weight:700;color:var(--red); }
  .summary-box { background:rgba(220,38,38,.08);border:1px solid var(--red);border-radius:8px;padding:20px;margin-bottom:32px; }
  .summary-box h2 { color:var(--red);margin-bottom:12px; }
  @media print { body{background:#fff;color:#000} .poc-card{border-color:#ccc} .output-box{background:#f1f5f9;color:#0f172a} }
</style>
</head>
<body>
<div class="header">
  <h1>&#9888; PROOF-OF-CONCEPT EXPLOITATION REPORT</h1>
  <p>Target: <strong>{{ target }}</strong> &nbsp;|&nbsp; Generated: {{ date }} &nbsp;|&nbsp; Zparty AI Exploit Engine</p>
</div>

<div class="stats">
  <div class="stat"><div class="n">{{ results|length }}</div><div class="l">Exploits Attempted</div></div>
  <div class="stat"><div class="n" style="color:#dc2626">{{ confirmed }}</div><div class="l">Confirmed PoC</div></div>
  <div class="stat"><div class="n" style="color:#ea580c">{{ partial }}</div><div class="l">Partial</div></div>
  <div class="stat"><div class="n" style="color:#7dd3fc">{{ max_cvss }}</div><div class="l">Max CVSS</div></div>
</div>

<div class="container">

  {% if ai_chains %}
  <div class="summary-box">
    <h2>AI Exploit Chain Analysis</h2>
    {% for chain in ai_chains %}
    <div style="margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid rgba(220,38,38,.3)">
      <strong>{{ chain.title }}</strong> &nbsp;
      <span class="badge-crit">{{ chain.severity }}</span><br>
      <p style="margin-top:6px;color:var(--muted)">{{ chain.description[:200] }}</p>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  {% for poc in results %}
  <div class="poc-card {{ 'success' if poc.success else 'partial' }}">
    <div class="poc-header">
      <span class="badge-crit">{{ poc.severity }}</span>
      {% if poc.success %}
      <span class="badge-confirmed">&#10003; EXPLOITATION CONFIRMED</span>
      {% else %}
      <span class="badge-partial">&#9888; PARTIAL</span>
      {% endif %}
      {% if poc.cvss_score %}
      <span class="cvss">CVSS {{ "%.1f"|format(poc.cvss_score) }}</span>
      {% endif %}
      <span class="poc-title">{{ poc.title }}</span>
    </div>

    <div class="section-label">Based on finding</div>
    <p style="color:var(--muted);font-size:13px">{{ poc.finding_title }}</p>

    <div class="section-label">Target URL</div>
    <div class="url">{{ poc.affected_url }}</div>

    <div class="section-label">Technique</div>
    <p style="font-size:13px">{{ poc.technique }}</p>

    <div class="section-label">Extracted Output / Evidence</div>
    <div class="output-box">{{ poc.output }}</div>

    <div class="section-label">Reproduction Steps</div>
    <ol class="steps-list">
      {% for step in poc.steps %}
      <li>{{ step }}</li>
      {% endfor %}
    </ol>

    <div class="section-label">Impact</div>
    <div class="impact-box">{{ poc.impact }}</div>

    {% if poc.screenshot %}
    <div class="screenshot-wrap">
      <div class="screenshot-label">&#128247; PLAYWRIGHT PROOF-OF-EXPLOIT SCREENSHOT</div>
      <img src="data:image/png;base64,{{ poc.screenshot }}" alt="PoC screenshot" loading="lazy">
    </div>
    {% else %}
    <div class="screenshot-wrap">
      <div class="no-screenshot">Screenshot not captured — verify manually using the reproduction steps above</div>
    </div>
    {% endif %}
  </div>
  {% endfor %}

  {% if not results %}
  <p style="color:var(--muted);text-align:center;padding:48px">No exploits were attempted — run a scan first with: python main.py scan &lt;target&gt;</p>
  {% endif %}

</div>
</body>
</html>"""


def generate_poc_report(
    target: str,
    results: list,
    ai_chains: list,
    session: Path,
) -> Path:
    confirmed = sum(1 for r in results if r.success)
    partial   = sum(1 for r in results if not r.success)
    max_cvss  = max((r.cvss_score for r in results), default=0.0)

    tmpl = Template(POC_TEMPLATE)
    html = tmpl.render(
        target    = target,
        date      = time.strftime("%Y-%m-%d %H:%M:%S"),
        results   = results,
        ai_chains = ai_chains,
        confirmed = confirmed,
        partial   = partial,
        max_cvss  = f"{max_cvss:.1f}",
    )

    report_dir = Path(session) / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    out = report_dir / "poc_report.html"
    out.write_text(html, encoding="utf-8")

    # Also save JSON
    json_out = report_dir / "poc_report.json"
    json_out.write_text(
        json.dumps(
            {
                "target": target,
                "date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "confirmed": confirmed,
                "partial": partial,
                "exploits": [r.to_dict() for r in results],
                "ai_chains": ai_chains,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return out
