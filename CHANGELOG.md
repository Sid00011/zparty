# Changelog

## [1.0.0] — 2026-05-19

First public release.

### Added
- Full 5-phase scan pipeline: validation → recon → active scan → vulns → report
- 30 concurrent vulnerability modules covering OWASP Top 10 and beyond
- Live browser UI with WebSocket log streaming (FastAPI)
- AI exploit engine: local LLM via Ollama, zero data sent externally
- Playwright-based PoC screenshot capture for confirmed exploits
- CVSS 3.1 scoring with letter grade (S → E)
- OWASP Top 10 2021 and PCI-DSS 4.0 compliance mapping
- SARIF report output (compatible with GitHub Code Scanning)
- Tor integration: new exit node per module, automatic circuit rotation via NEWNYM
- User-agent rotation and request jitter for evasion
- OOB (out-of-band) listener for blind injection detection
- Scope enforcement: out-of-scope domains, excluded paths, include-only lists
- Authentication support: cookie, Bearer token, Basic, API key, form login
- Notifications: Slack, email, Jira, custom webhook
- Docker support

---

## [0.5.0] — 2026-04

### Added
- AI attack planning after recon phase: AI reads tech stack and generates prioritised attack hypothesis
- AI exploit chain detection: identifies multi-step vulnerability paths across findings
- Ollama model fallback: auto-selects any available local model if configured model is missing
- Playwright exploit verifier: automated browser-based confirmation for XSS, SQLi, SSTI, default creds

### Changed
- Tor now activates only at Phase 3 (attack modules) — recon and scanning run direct for speed
- Phase 3 hard limit introduced (300s) so scans never stall indefinitely
- Per-module timeouts enforced: 60s for vuln modules, 180s for Nuclei

### Fixed
- stem SocketClosed log spam during Tor circuit rotation no longer floods the UI terminal
- DirBruteforce capped at 2000 entries to prevent 220K asyncio task creation stalling the event loop
- Tor rotation serialization: single pre-phase rotation instead of 30 sequential locks

---

## [0.3.0] — 2026-03

### Added
- IDOR Chain module: cross-endpoint object ID correlation
- OAuth / OIDC tester: state parameter, redirect_uri bypass, PKCE downgrade
- Race Conditions (AI-targeted): focuses timing attacks on financial and coupon endpoints
- Business Logic module: price manipulation, quota bypass, plan escalation
- Mass Assignment module: hidden field injection on REST APIs
- CVSS 3.1 vector lookup for all finding types
- Deduplication engine: exact and near-duplicate finding suppression

### Changed
- Rate limiter redesigned: semaphore-based, non-serialising — eliminated the global lock that capped throughput at 5 req/s
- Scan phase modules now run with individual timeouts instead of a shared budget

---

## [0.2.0] — 2026-02

### Added
- Browser UI: FastAPI + WebSocket live scan streaming
- Scan history and result browser in the UI
- SSRF Chain module with cloud metadata credential extraction
- SSTI → RCE escalation module with engine-specific sandbox escape chains
- LFI module with PHP filter bypass (`php://filter/convert.base64-encode`)
- Default credentials module (200+ pairs)
- Nuclei integration with automatic binary download
- nmap integration with socket-based fallback
- WAF detection module

### Changed
- Modules refactored to a self-contained async class interface (`run(ctx) -> list[Finding]`)
- Endpoint seeding: vuln modules always have a baseline set of parameterised URLs even when crawler finds nothing

---

## [0.1.0] — 2026-01

### Added
- Initial pipeline: WHOIS, DNS, subdomain enumeration, tech fingerprint, SSL analysis
- Core vulnerability modules: SQLi, XSS, SSTI, SSRF, XXE, JWT, CORS, open redirect, path traversal, HTTP smuggling
- Finding dataclass with severity, CVSS impact/likelihood, proof, remediation
- HTML report generation with Jinja2
- `config.yaml`-driven configuration
- CLI entrypoint with Typer + Rich
