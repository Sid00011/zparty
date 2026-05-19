"""
core/ai_agent.py — Autonomous AI Agent Loop

The agent uses Playwright to drive a real browser and Ollama to decide each
next action. It iterates: observe (screenshot + DOM) → think (AI) → act
(click / fill / submit) → repeat, looking for logic flaws, IDOR, and
privilege escalation that static scanning cannot reach.

Architecture:
  - Observe: capture DOM snapshot + screenshot
  - Think:   send observation to Ollama, get next action JSON
  - Act:     execute action in browser
  - Repeat:  up to MAX_STEPS iterations per target
"""
import asyncio
import logging
import json as _json
import re
import time
from pathlib import Path
from core.finding import Finding

logger = logging.getLogger(__name__)

MAX_STEPS        = 12    # max actions per agent run
MAX_TARGETS      = 5     # max pages the agent explores
THINK_TIMEOUT    = 30    # seconds for Ollama to respond
SCREENSHOT_DIR   = "results/agent_screenshots"


# ── Ollama action schema ──────────────────────────────────────────────────────
ACTION_SCHEMA = """
You are a web security agent. Given the page state, decide the NEXT single action.
Respond ONLY with a JSON object (no prose) matching one of:

{"action":"click",    "selector":"CSS_SELECTOR"}
{"action":"fill",     "selector":"CSS_SELECTOR", "value":"TEXT"}
{"action":"navigate", "url":"FULL_URL"}
{"action":"submit",   "selector":"CSS_FORM_SELECTOR"}
{"action":"done",     "reason":"WHY_DONE"}

Goals (in order):
1. Find hidden admin/privileged pages by navigating to /admin, /dashboard, /settings
2. Try accessing other users' resources by incrementing IDs in URLs
3. Look for forms that accept price/quantity/plan values and submit unexpected values
4. Detect if the response reveals sensitive data or grants unexpected access

Be concise. Only one action per response.
"""


class AIAgent:
    """
    Autonomous browser-driving agent.
    Requires: Ollama running + Playwright installed.
    """

    def __init__(self, cfg: dict, session_dir: Path | None = None):
        self.cfg         = cfg
        self.ai_host     = cfg.get("ai", {}).get("host", "http://localhost:11434")
        self.model       = cfg.get("ai", {}).get("model", "llama3.2:3b")
        self.session_dir = session_dir or Path(SCREENSHOT_DIR)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._playwright = None
        self._browser    = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> bool:
        try:
            from playwright.async_api import async_playwright
            self._pw      = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            logger.info("AIAgent: Playwright browser started")
            return True
        except Exception as e:
            logger.warning(f"AIAgent: Playwright unavailable — {e}")
            return False

    async def stop(self):
        try:
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self, ctx: dict) -> list[Finding]:
        findings: list[Finding] = []
        target    = ctx.get("target_url", "")
        endpoints = ctx.get("endpoints", [])

        if not target:
            return findings

        ready = await self.start()
        if not ready:
            return findings

        # Select pages to explore: target + interesting endpoints
        pages_to_explore = [target]
        for ep in endpoints[:MAX_TARGETS - 1]:
            if any(k in ep.lower() for k in [
                "admin", "dashboard", "profile", "account", "settings",
                "order", "checkout", "payment", "user", "manage",
            ]):
                pages_to_explore.append(ep)

        pages_to_explore = pages_to_explore[:MAX_TARGETS]
        logger.info(f"AIAgent: exploring {len(pages_to_explore)} page(s)")

        for start_url in pages_to_explore:
            try:
                fs = await self._explore(start_url, ctx)
                findings.extend(fs)
            except Exception as e:
                logger.debug(f"AIAgent explore {start_url}: {e}")

        await self.stop()
        logger.info(f"AIAgent completed — {len(findings)} finding(s)")
        return findings

    # ── Agent loop ────────────────────────────────────────────────────────────

    async def _explore(self, start_url: str, ctx: dict) -> list[Finding]:
        findings = []
        page     = await self._browser.new_page()
        history: list[dict] = []  # conversation with AI

        try:
            await page.goto(start_url, timeout=15000, wait_until="domcontentloaded")

            for step in range(MAX_STEPS):
                # ── Observe ───────────────────────────────────────────────────
                state  = await self._observe(page, step)
                if not state:
                    break

                # ── Think ─────────────────────────────────────────────────────
                action = await self._think(state, history)
                if not action:
                    break

                logger.debug(f"AIAgent step {step}: {action}")
                history.append({"step": step, "action": action, "url": page.url})

                # ── Act ───────────────────────────────────────────────────────
                if action.get("action") == "done":
                    break

                finding = await self._act(page, action, ctx)
                if finding:
                    findings.append(finding)

                await asyncio.sleep(0.5)

        except Exception as e:
            logger.debug(f"AIAgent loop: {e}")
        finally:
            await page.close()

        return findings

    async def _observe(self, page, step: int) -> dict | None:
        """Capture page state: URL, title, visible text, forms."""
        try:
            url   = page.url
            title = await page.title()

            # Extract visible text (truncated)
            body_text = await page.evaluate(
                "() => document.body ? document.body.innerText.slice(0, 1500) : ''"
            )

            # Extract form structures
            forms = await page.evaluate("""
                () => Array.from(document.forms).slice(0, 5).map(f => ({
                    action: f.action,
                    method: f.method,
                    fields: Array.from(f.elements).slice(0, 10).map(e => ({
                        name: e.name, type: e.type, value: e.value
                    }))
                }))
            """)

            # Screenshot
            screenshot_path = self.session_dir / f"step_{step:02d}.png"
            await page.screenshot(path=str(screenshot_path), full_page=False)

            return {
                "url":   url,
                "title": title,
                "text":  body_text,
                "forms": forms,
                "step":  step,
            }
        except Exception as e:
            logger.debug(f"AIAgent observe: {e}")
            return None

    async def _think(self, state: dict, history: list[dict]) -> dict | None:
        """Ask Ollama what to do next, returns action dict."""
        prompt = (
            f"Current URL: {state['url']}\n"
            f"Page title: {state['title']}\n"
            f"Visible text (first 800 chars):\n{state['text'][:800]}\n"
            f"Forms: {_json.dumps(state['forms'], default=str)[:400]}\n"
            f"Steps taken: {len(history)}\n\n"
            f"{ACTION_SCHEMA}"
        )

        try:
            import httpx
            async with httpx.AsyncClient(timeout=THINK_TIMEOUT) as c:
                r = await c.post(
                    f"{self.ai_host}/api/chat",
                    json={
                        "model":    self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream":   False,
                        "options":  {"num_ctx": 1024, "temperature": 0.1},
                    },
                )
            raw = r.json().get("message", {}).get("content", "")
            # Extract JSON from response
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if match:
                return _json.loads(match.group())
        except Exception as e:
            logger.debug(f"AIAgent think: {e}")
        return None

    async def _act(self, page, action: dict, ctx: dict) -> Finding | None:
        """Execute one action in the browser. Returns a Finding if something suspicious found."""
        act = action.get("action", "")
        url_before = page.url

        try:
            if act == "click":
                sel = action.get("selector", "")
                if sel:
                    await page.click(sel, timeout=5000)
                    await page.wait_for_load_state("domcontentloaded", timeout=8000)

            elif act == "fill":
                sel = action.get("selector", "")
                val = action.get("value", "")
                if sel and val:
                    await page.fill(sel, val, timeout=5000)

            elif act == "navigate":
                nav_url = action.get("url", "")
                if nav_url:
                    await page.goto(nav_url, timeout=12000, wait_until="domcontentloaded")

            elif act == "submit":
                sel = action.get("selector", "form")
                await page.evaluate(
                    f"() => document.querySelector('{sel}') && "
                    f"document.querySelector('{sel}').submit()"
                )
                await page.wait_for_load_state("domcontentloaded", timeout=8000)

            # ── Evaluate response for findings ────────────────────────────────
            url_after = page.url
            body      = await page.evaluate(
                "() => document.body ? document.body.innerText.slice(0, 2000) : ''"
            )
            return await self._evaluate_response(url_before, url_after, body, action, ctx)

        except Exception as e:
            logger.debug(f"AIAgent act ({act}): {e}")
        return None

    async def _evaluate_response(
        self, url_before: str, url_after: str, body: str, action: dict, ctx: dict
    ) -> Finding | None:
        """Heuristically detect interesting responses after an action."""
        body_l = body.lower()
        target = ctx.get("target_url", "")

        # Admin panel accessed
        if any(k in url_after.lower() for k in ["admin", "dashboard", "manage"]):
            if any(k in body_l for k in ["user", "settings", "configuration", "management"]):
                return Finding(
                    title="AI Agent: Admin/Privileged Page Accessible",
                    severity="Critical",
                    description=(
                        f"The AI agent navigated to {url_after} and found what appears "
                        f"to be an administrative or privileged interface. "
                        f"This endpoint may not require proper authentication or authorization."
                    ),
                    affected_url=url_after,
                    proof=(
                        f"Action: {_json.dumps(action)}\n"
                        f"Navigated from: {url_before}\n"
                        f"To: {url_after}\n"
                        f"Response snippet: {body[:400]}"
                    ),
                    remediation=(
                        "Ensure all privileged endpoints enforce authentication "
                        "and role-based access control. Verify session tokens on every request."
                    ),
                    impact=5, likelihood=3, module="AIAgent",
                    cvss_score=9.1, cwe="CWE-285",
                )

        # Sensitive data exposed
        SENSITIVE = [
            "password", "secret", "api_key", "token", "ssn",
            "credit_card", "private_key", "aws_secret",
        ]
        for keyword in SENSITIVE:
            # Look for keyword appearing near a value (e.g. "password: abc123")
            pattern = re.search(
                rf'{keyword}[\s:="\']{{1,5}}([A-Za-z0-9+/=_\-]{{8,}})', body_l
            )
            if pattern:
                return Finding(
                    title=f"AI Agent: Sensitive Data '{keyword}' Exposed in Response",
                    severity="High",
                    description=(
                        f"The AI agent triggered an action that caused '{keyword}' "
                        f"to appear in the response at {url_after}. "
                        f"Sensitive data should never be returned in page content."
                    ),
                    affected_url=url_after,
                    proof=(
                        f"Action: {_json.dumps(action)}\n"
                        f"URL: {url_after}\n"
                        f"Found '{keyword}' in response: {body[max(0, body_l.find(keyword)-50):body_l.find(keyword)+100]}"
                    ),
                    remediation="Remove sensitive fields from API responses. Apply field-level access control.",
                    impact=4, likelihood=3, module="AIAgent",
                    cvss_score=7.5, cwe="CWE-200",
                )

        # IDOR via navigation: URL changed to a different user's resource
        if url_after != url_before and url_after != target:
            # If URL contains numeric ID different from what we navigated from
            ids_before = set(re.findall(r'/(\d{1,10})(?:/|$|\?)', url_before))
            ids_after  = set(re.findall(r'/(\d{1,10})(?:/|$|\?)', url_after))
            new_ids = ids_after - ids_before
            if new_ids and len(body) > 100:
                # Not an error page
                if not any(k in body_l for k in ["not found", "404", "error", "forbidden", "denied"]):
                    return Finding(
                        title=f"AI Agent: Potential IDOR via Navigation (ID={list(new_ids)[0]})",
                        severity="Medium",
                        description=(
                            f"The AI agent navigated to a URL containing ID {list(new_ids)[0]} "
                            f"({url_after}) and received a non-error response. "
                            f"Verify whether this ID belongs to the current user."
                        ),
                        affected_url=url_after,
                        proof=f"Navigation: {url_before} → {url_after}\nResponse: {body[:300]}",
                        remediation="Validate resource ownership on every request.",
                        impact=3, likelihood=2, module="AIAgent",
                        cvss_score=6.5, cwe="CWE-639",
                    )

        return None
