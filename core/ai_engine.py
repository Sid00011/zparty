"""
core/ai_engine.py — Local AI attack planning via Ollama

100% offline. No API keys. No external services. Nothing leaves your machine.

Uses Ollama (https://ollama.com) running locally on port 11434.
Ollama runs open-source models like Llama 3.1, Mistral, Qwen2.5, DeepSeek.

Install Ollama:
  Windows/macOS: https://ollama.com/download
  Linux:         curl -fsSL https://ollama.com/install.sh | sh

Pull a model (one-time, then fully offline):
  ollama pull llama3.1          # 4.7 GB — best balance
  ollama pull mistral           # 4.1 GB — fast
  ollama pull qwen2.5-coder     # 4.7 GB — great for technical/security tasks
  ollama pull deepseek-r1:8b    # 4.9 GB — strong reasoning

Then enable in config.yaml:
  ai:
    enabled: true
    model: "llama3.1"
    host: "http://localhost:11434"

Everything stays on your machine. The target never knows AI is involved.
The model never sees your real IP (Tor is still active). Zero telemetry.
"""
import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_OLLAMA_TIMEOUT = httpx.Timeout(connect=5.0, read=90.0, write=10.0, pool=5.0)

# Recommended models ranked by quality for pentesting tasks
RECOMMENDED_MODELS = [
    "llama3.1",
    "qwen2.5-coder",
    "mistral",
    "deepseek-r1:8b",
    "llama3.2",
    "phi4",
]


class AIEngine:
    """
    Local AI reasoning engine using Ollama.

    Three capabilities:
      1. analyze_target()  — read recon, build prioritised attack plan
      2. analyze_chain()   — after scan, identify multi-step exploit paths
      3. triage_findings() — re-score by real exploitability

    All calls are async and use httpx to talk to Ollama's REST API.
    Falls back silently to no-op if Ollama is not running or model missing.
    """

    def __init__(self, cfg: dict):
        ai_cfg       = cfg.get("ai", {})
        self.enabled = ai_cfg.get("enabled", False)
        self.model   = ai_cfg.get("model", "llama3.1")
        self.host    = ai_cfg.get("host", "http://localhost:11434").rstrip("/")
        self._ready  = False

    @property
    def active(self) -> bool:
        return self._ready

    async def stop(self) -> None:
        """
        Unload the model from Ollama memory and kill the process.
        Frees ~2GB RAM on a 7.6GB system before exploitation phase starts.
        """
        self._ready = False
        try:
            # Tell Ollama to unload the model
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as c:
                await c.post(
                    f"{self.host}/api/generate",
                    json={"model": self.model, "keep_alive": 0},
                )
        except Exception:
            pass
        try:
            import subprocess
            subprocess.run(
                ["taskkill", "/F", "/IM", "ollama.exe"],
                capture_output=True,
            )
            logger.info("AI Engine: Ollama stopped — RAM freed for exploitation phase")
        except Exception:
            pass

    # ── Startup ───────────────────────────────────────────────────────────────

    async def start(self) -> bool:
        """
        Check Ollama is running and the configured model is available.
        Tries to auto-start Ollama if installed but not running.
        Returns True if ready.
        """
        if not self.enabled:
            return False

        # Check if Ollama API is reachable
        if not await self._ping():
            # Try starting Ollama in the background
            logger.info("Ollama not responding — attempting to start it ...")
            await self._try_start_ollama()
            await asyncio.sleep(3)
            if not await self._ping():
                logger.warning(
                    "Ollama not running. Install from https://ollama.com/download "
                    "then run: ollama pull " + self.model
                )
                return False

        # Check the model exists
        if not await self._model_available():
            logger.warning(
                f"Model '{self.model}' not found in Ollama. "
                f"Run: ollama pull {self.model}"
            )
            # Try to find any available model as fallback
            fallback = await self._find_any_model()
            if fallback:
                logger.info(f"Using fallback model: {fallback}")
                self.model = fallback
            else:
                logger.warning("No models found in Ollama. Run: ollama pull llama3.1")
                return False

        self._ready = True
        logger.info(f"AI Engine: Ollama ready — model={self.model} (100% local, zero telemetry)")
        return True

    async def _ping(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as c:
                r = await c.get(f"{self.host}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def _model_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as c:
                r = await c.get(f"{self.host}/api/tags")
                models = [m["name"].split(":")[0] for m in r.json().get("models", [])]
                return self.model.split(":")[0] in models
        except Exception:
            return False

    async def _find_any_model(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as c:
                r = await c.get(f"{self.host}/api/tags")
                models = r.json().get("models", [])
                if models:
                    return models[0]["name"]
        except Exception:
            pass
        return None

    async def _try_start_ollama(self) -> None:
        try:
            import shutil
            if shutil.which("ollama"):
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except Exception:
            pass

    # ── Core inference ────────────────────────────────────────────────────────

    async def _ask(self, prompt: str, max_words: int = 400) -> str:
        """
        Send a prompt to Ollama, return the text response.
        Uses /api/chat endpoint (supports system message + conversation).
        """
        system = (
            "You are an expert penetration tester with 15 years of experience. "
            "You think like an attacker. Be concise, technical, and accurate. "
            "Always return valid JSON when asked. No explanations outside JSON."
        )
        payload = {
            "model":  self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt},
            ],
            "options": {
                "temperature":  0.2,
                "num_predict":  min(max_words * 2, 800),
                "num_ctx":      3072,   # 1024 was too small — prompt alone eats 600+ tokens, leaving no room for response
                "num_batch":    64,
                "num_thread":   2,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as c:
                r = await c.post(f"{self.host}/api/chat", json=payload)
                r.raise_for_status()
                data = r.json()
                return data.get("message", {}).get("content", "").strip()
        except Exception as e:
            logger.debug(f"Ollama inference error: {type(e).__name__}: {e}")
            return ""

    def _parse_json(self, text: str) -> dict | list | None:
        """Extract JSON from model response — handles markdown code blocks."""
        text = text.strip()
        # Strip markdown code fences
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                part = part.strip().lstrip("json").strip()
                try:
                    return json.loads(part)
                except Exception:
                    pass
        # Try raw
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try finding first { or [
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end   = text.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except Exception:
                    pass
        return None

    # ── Public API ────────────────────────────────────────────────────────────

    async def analyze_target(self, ctx: dict) -> dict:
        """
        After recon, generate a prioritized attack plan.
        Returns dict: {priority_modules, high_value_params, exploit_chain_hypothesis, notes}
        """
        if not self._ready:
            return {}

        recon    = ctx.get("recon", {})
        tech     = recon.get("TechFingerprint", {})
        ports    = ctx.get("scan", {}).get("open_ports", {})
        subs     = len(ctx.get("subdomains", []))
        eps      = ctx.get("endpoints", [])[:15]
        target   = ctx.get("target_url", "")

        prompt = f"""Analyze this target for penetration testing and return a JSON attack plan.

TARGET: {target}
TECH STACK: {json.dumps(tech, default=str)[:800]}
OPEN PORTS: {list(ports.keys())}
SUBDOMAINS FOUND: {subs}
SAMPLE ENDPOINTS: {eps}

Return ONLY this JSON (no other text):
{{
  "priority_modules": ["list of 3-5 module names to focus on, e.g. sqli, xss, lfi, default_creds, ssrf_chain, command_injection, ssti_rce, file_upload, mass_assignment"],
  "high_value_params": ["parameter names most likely to be injectable based on tech stack"],
  "tech_specific_risks": ["2-3 specific risks based on the detected tech"],
  "exploit_chain_hypothesis": "one sentence: most likely full exploit chain for this target",
  "notes": "any important observation about this target"
}}"""

        response = await self._ask(prompt, max_words=300)
        result   = self._parse_json(response)
        if isinstance(result, dict):
            logger.info(f"AI attack plan: {result.get('exploit_chain_hypothesis', 'N/A')}")
            return result
        logger.debug(f"AI analyze_target: could not parse response: {response[:200]}")
        return {}

    async def generate_payloads(
        self, vuln_type: str, tech_stack: str, endpoint: str
    ) -> list[str]:
        """
        Generate targeted payloads for the specific tech stack and vuln type.
        Returns list of payload strings.
        """
        if not self._ready:
            return []

        prompt = f"""Generate 5 {vuln_type} attack payloads specifically for:
Tech: {tech_stack}
Endpoint: {endpoint}

Return ONLY a JSON array of strings, no explanation:
["payload1", "payload2", "payload3", "payload4", "payload5"]"""

        response = await self._ask(prompt, max_words=150)
        result   = self._parse_json(response)
        if isinstance(result, list):
            return [str(p) for p in result[:5] if p]
        return []

    async def analyze_chain(self, findings: list[dict]) -> list[dict]:
        """
        Given all findings, identify multi-step exploit chains.
        Returns list of new synthetic chain finding dicts.
        """
        if not self._ready or not findings:
            return []

        # Only include significant findings
        significant = [
            {"title": f["title"], "severity": f["severity"],
             "module": f.get("module", ""), "url": f.get("affected_url", "")}
            for f in findings
            if f.get("severity") in ("Critical", "High", "Medium")
        ][:15]

        if len(significant) < 2:
            return []

        prompt = f"""Given these security findings, identify realistic exploit chains —
sequences of vulnerabilities that together create higher-impact attacks.

FINDINGS:
{json.dumps(significant, indent=2)}

Return ONLY a JSON array (max 2 chains, or empty [] if no chains exist):
[
  {{
    "title": "Chain: [name the chain]",
    "severity": "Critical",
    "description": "how to chain these vulnerabilities step by step",
    "steps": ["step 1", "step 2", "step 3"],
    "impact": "what the attacker achieves at the end",
    "findings_used": ["title of finding 1", "title of finding 2"]
  }}
]"""

        response = await self._ask(prompt, max_words=500)
        result   = self._parse_json(response)

        if not isinstance(result, list):
            return []

        chain_findings = []
        for chain in result[:2]:
            if not isinstance(chain, dict):
                continue
            steps = chain.get("steps", [])
            steps_text = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps))
            chain_findings.append({
                "title":       chain.get("title", "Exploit Chain"),
                "severity":    chain.get("severity", "High"),
                "description": chain.get("description", ""),
                "affected_url": "Multiple endpoints",
                "proof": (
                    f"AI-identified exploit chain:\n{steps_text}\n\n"
                    f"Impact: {chain.get('impact', '')}\n"
                    f"Based on: {', '.join(chain.get('findings_used', []))}"
                ),
                "remediation": "Fix each vulnerability in the chain, starting with the entry point.",
                "impact":      5,
                "likelihood":  4,
                "module":      "AIEngine",
                "references":  [],
                "cvss_score":  9.0 if chain.get("severity") == "Critical" else 7.5,
                "screenshot":  "",
                "verified":    False,
                "risk_score":  20,
            })

        if chain_findings:
            logger.info(f"AI identified {len(chain_findings)} exploit chain(s)")
        return chain_findings

    async def triage_findings(self, findings: list[dict]) -> list[dict]:
        """
        Re-evaluate finding severities based on real exploitability context.
        Updates severities in-place and returns the modified list.
        """
        if not self._ready or len(findings) < 3:
            return findings

        summary = [
            {"title": f["title"], "severity": f["severity"],
             "module": f.get("module", ""), "verified": f.get("verified", False)}
            for f in findings
        ][:12]

        prompt = f"""Review these penetration test findings and identify severity corrections.

FINDINGS:
{json.dumps(summary, indent=2)}

Return ONLY a JSON array of corrections (only include findings that need changes):
[
  {{
    "title": "exact finding title",
    "new_severity": "Critical|High|Medium|Low",
    "reason": "one sentence explanation"
  }}
]

Return [] if all severities are correct."""

        response = await self._ask(prompt, max_words=300)
        result   = self._parse_json(response)

        if not isinstance(result, list):
            return findings

        corrections = {c["title"]: c for c in result if isinstance(c, dict) and "title" in c}
        for f in findings:
            correction = corrections.get(f.get("title", ""))
            if correction and "new_severity" in correction:
                old = f.get("severity")
                new = correction["new_severity"]
                if new in ("Critical", "High", "Medium", "Low", "Info") and new != old:
                    f["severity"] = new
                    f["proof"] = f.get("proof", "") + f"\n\nAI triage: {correction.get('reason', '')}"

        return findings
