# Contributing

Contributions are welcome — bug fixes, new modules, improved payloads, better evasion, documentation.

## Getting started

```bash
git clone https://github.com/Sid00011/zparty.git
cd zparty
pip install -r requirements.txt
playwright install chromium
```

## Adding a vulnerability module

Each module is a self-contained async class in `modules/vulns/`:

```python
from core.finding import Finding

class MyModule:
    async def run(self, ctx: dict) -> list[Finding]:
        url     = ctx["target_url"]
        limiter = ctx["limiter"]
        # ... your logic
        return [Finding(
            title="Vulnerability Name",
            severity="High",          # Critical | High | Medium | Low | Info
            description="What it is and why it matters.",
            affected_url=url,
            proof="Evidence string shown in the report",
            remediation="How to fix it.",
            impact=4,                 # 1–5
            likelihood=3,             # 1–5
            module="MyModule",
        )]
```

Then register it in `core/pipeline.py` under `vuln_map` and add a toggle in `config.yaml` under `modules.vulns`.

## Guidelines

- **Authorized testing only** — payloads must not be destructive (no `DROP TABLE`, no `rm -rf`, no denial-of-service)
- Each module must handle its own exceptions and return `[]` on failure — never raise
- Use `ctx["limiter"]` for all HTTP requests — do not bypass the rate limiter
- Keep modules async throughout — no blocking calls (`requests`, `time.sleep`) without `asyncio.to_thread` / `asyncio.sleep`
- Test against intentionally vulnerable targets: DVWA, WebGoat, HackTheBox, TryHackMe

## Reporting bugs

Open a GitHub issue with:
- What you ran (target type, config, module)
- What you expected vs what happened
- Relevant log output (redact any real target URLs)

## Pull requests

- One feature or fix per PR
- Include a brief description of what changed and why
- If adding a module, test it on at least one intentionally vulnerable target
