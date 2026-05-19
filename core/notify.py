"""
core/notify.py — Scan completion notifications

Supported channels (configured in config.yaml under `notify:`):
  slack:    webhook POST to Slack incoming webhook URL
  email:    SMTP with TLS (Gmail, Office365, Sendgrid, etc.)
  webhook:  generic HTTP POST — any URL, any payload template
  jira:     creates a Jira issue for each Critical/High finding

All channels are optional and fire in parallel after scan completes.
If a channel fails it logs a warning and never raises — notifications
must not break the scan.
"""

import asyncio
import json
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Info":     "🔵",
}


class NotificationManager:
    def __init__(self, cfg: dict):
        self._cfg = cfg.get("notify", {}) or {}

    async def send_all(self, result: dict, findings: list[dict]) -> None:
        """Fire all configured notification channels in parallel."""
        if not self._cfg:
            return

        tasks = []
        if self._cfg.get("slack", {}).get("webhook_url"):
            tasks.append(self._send_slack(result, findings))
        if self._cfg.get("email", {}).get("to"):
            tasks.append(self._send_email(result, findings))
        if self._cfg.get("webhook", {}).get("url"):
            tasks.append(self._send_webhook(result, findings))
        if self._cfg.get("jira", {}).get("url"):
            tasks.append(self._send_jira(result, findings))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── Slack ──────────────────────────────────────────────────────────────────

    async def _send_slack(self, result: dict, findings: list[dict]) -> None:
        cfg = self._cfg.get("slack", {})
        webhook_url = cfg.get("webhook_url", "")
        if not webhook_url:
            return

        grade = result.get("grade", "?")
        score = result.get("score")
        score_str = f"{score}/100" if score is not None else "N/A"
        target = result.get("target_url", "unknown")
        sev = result.get("severity_counts", {})

        # Top 5 critical/high findings
        critical_findings = [
            f for f in findings
            if f.get("severity") in ("Critical", "High")
        ][:5]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"⚡ Zparty Scan Complete — {target}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Grade:* `{grade}`"},
                    {"type": "mrkdwn", "text": f"*Score:* `{score_str}`"},
                    {"type": "mrkdwn", "text": f"*Duration:* {result.get('duration', 0)}s"},
                    {"type": "mrkdwn", "text": f"*Total Findings:* {result.get('findings_count', 0)}"},
                    {"type": "mrkdwn",
                     "text": f"*🔴 Critical:* {sev.get('Critical', 0)}  *🟠 High:* {sev.get('High', 0)}"},
                    {"type": "mrkdwn",
                     "text": f"*🟡 Medium:* {sev.get('Medium', 0)}  *🟢 Low:* {sev.get('Low', 0)}"},
                ],
            },
        ]

        if critical_findings:
            top_text = "\n".join(
                f"{SEVERITY_EMOJI.get(f['severity'], '•')} *{f['title']}*"
                for f in critical_findings
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"*Top Findings:*\n{top_text}"},
            })

        report_paths = result.get("report_paths", {})
        if report_paths.get("html"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"📄 Report: `{report_paths['html']}`"},
            })

        payload = {"blocks": blocks}

        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                r = await client.post(webhook_url, json=payload)
            if r.status_code != 200:
                logger.warning(f"Slack notification returned {r.status_code}: {r.text[:200]}")
            else:
                logger.info("Slack notification sent")
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")

    # ── Email ──────────────────────────────────────────────────────────────────

    async def _send_email(self, result: dict, findings: list[dict]) -> None:
        cfg = self._cfg.get("email", {})
        to_addr   = cfg.get("to", "")
        from_addr = cfg.get("from", "zparty@localhost")
        smtp_host = cfg.get("smtp_host", "localhost")
        smtp_port = cfg.get("smtp_port", 587)
        username  = cfg.get("username", "")
        password  = cfg.get("password", "")

        if not to_addr:
            return

        target = result.get("target_url", "unknown")
        grade  = result.get("grade", "?")
        score  = result.get("score")
        sev    = result.get("severity_counts", {})

        subject = f"[Zparty] Scan Complete — {target} | Grade {grade}"

        html_body = f"""
<html><body style="font-family:sans-serif;max-width:600px">
<h2>⚡ Zparty Security Scan Report</h2>
<table border="0" cellpadding="8" style="width:100%;border-collapse:collapse">
  <tr><td><b>Target</b></td><td>{target}</td></tr>
  <tr><td><b>Grade</b></td><td><b style="font-size:1.4em">{grade}</b></td></tr>
  <tr><td><b>Score</b></td><td>{score}/100 if score else N/A</td></tr>
  <tr><td><b>Duration</b></td><td>{result.get('duration', 0)}s</td></tr>
  <tr><td><b>Critical</b></td><td style="color:#dc2626">{sev.get('Critical', 0)}</td></tr>
  <tr><td><b>High</b></td><td style="color:#ea580c">{sev.get('High', 0)}</td></tr>
  <tr><td><b>Medium</b></td><td style="color:#d97706">{sev.get('Medium', 0)}</td></tr>
  <tr><td><b>Low</b></td><td style="color:#65a30d">{sev.get('Low', 0)}</td></tr>
</table>
<h3>Top Findings</h3>
<ul>
{"".join(f'<li><b>[{f.get("severity")}]</b> {f.get("title")} — {f.get("affected_url", "")}</li>' for f in findings[:10])}
</ul>
<p style="color:#6b7280;font-size:11px">Generated by Zparty — Automated Web Penetration Testing Framework</p>
</body></html>
"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        msg.attach(MIMEText(html_body, "html"))

        try:
            await asyncio.to_thread(
                self._smtp_send, smtp_host, smtp_port, username, password, from_addr, to_addr, msg
            )
            logger.info(f"Email notification sent to {to_addr}")
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")

    @staticmethod
    def _smtp_send(host, port, user, pw, from_addr, to_addr, msg):
        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            if s.has_extn("STARTTLS"):
                s.starttls(context=ctx)
                s.ehlo()
            if user and pw:
                s.login(user, pw)
            s.sendmail(from_addr, [to_addr], msg.as_string())

    # ── Generic Webhook ────────────────────────────────────────────────────────

    async def _send_webhook(self, result: dict, findings: list[dict]) -> None:
        cfg = self._cfg.get("webhook", {})
        url    = cfg.get("url", "")
        method = cfg.get("method", "POST").upper()
        extra_headers = cfg.get("headers", {})
        if not url:
            return

        payload = {
            "tool":          "zparty",
            "target":        result.get("target_url", ""),
            "scan_date":     result.get("scan_date", ""),
            "duration":      result.get("duration", 0),
            "score":         result.get("score"),
            "grade":         result.get("grade", "?"),
            "findings_count": result.get("findings_count", 0),
            "severity_counts": result.get("severity_counts", {}),
            "critical_findings": [
                {"title": f.get("title"), "severity": f.get("severity"),
                 "url": f.get("affected_url"), "cwe": f.get("cwe")}
                for f in findings
                if f.get("severity") in ("Critical", "High")
            ],
            "report_paths":  result.get("report_paths", {}),
        }

        try:
            headers = {"Content-Type": "application/json", **extra_headers}
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                if method == "POST":
                    r = await client.post(url, json=payload, headers=headers)
                else:
                    r = await client.get(url, params={"data": json.dumps(payload)})
            logger.info(f"Webhook notification sent → HTTP {r.status_code}")
        except Exception as e:
            logger.warning(f"Webhook notification failed: {e}")

    # ── Jira ───────────────────────────────────────────────────────────────────

    async def _send_jira(self, result: dict, findings: list[dict]) -> None:
        cfg = self._cfg.get("jira", {})
        jira_url  = cfg.get("url", "").rstrip("/")
        project   = cfg.get("project_key", "SEC")
        email     = cfg.get("email", "")
        api_token = cfg.get("api_token", "")

        if not jira_url or not email or not api_token:
            return

        import base64
        auth = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }

        target = result.get("target_url", "unknown")

        # Create one Jira issue per Critical/High finding
        crit_findings = [f for f in findings if f.get("severity") in ("Critical", "High")][:10]
        if not crit_findings:
            return

        severity_priority = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}

        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            for f in crit_findings:
                issue = {
                    "fields": {
                        "project":     {"key": project},
                        "summary":     f"[Zparty] {f.get('title')} — {target}",
                        "description": {
                            "type": "doc", "version": 1,
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": (
                                    f"Severity: {f.get('severity')}\n"
                                    f"URL: {f.get('affected_url')}\n"
                                    f"CVSS: {f.get('cvss_score')} — {f.get('cvss_vector')}\n"
                                    f"CWE: {f.get('cwe')}\n\n"
                                    f"Description: {f.get('description')}\n\n"
                                    f"Remediation: {f.get('remediation')}\n\n"
                                    f"Proof:\n{f.get('proof', '')[:1000]}"
                                )}],
                            }],
                        },
                        "issuetype": {"name": "Bug"},
                        "priority":  {"name": severity_priority.get(f.get("severity"), "Medium")},
                        "labels":    ["security", "zparty", f.get("severity", "").lower()],
                    }
                }
                try:
                    r = await client.post(
                        f"{jira_url}/rest/api/3/issue",
                        json=issue, headers=headers,
                    )
                    if r.status_code in (200, 201):
                        data = r.json()
                        logger.info(f"Jira issue created: {data.get('key')} — {f.get('title')}")
                    else:
                        logger.warning(f"Jira issue creation failed: {r.status_code} {r.text[:200]}")
                except Exception as e:
                    logger.warning(f"Jira issue failed: {e}")
