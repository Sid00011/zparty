# Zparty

**Automated web penetration testing framework with local AI, built in Python.**

Zparty runs a full black-box security audit in one command — recon, scanning, 30+ vulnerability modules, CVSS scoring, compliance mapping, and an AI-directed exploit engine — all from a browser UI with live streaming output.

No API keys. No cloud. Everything runs on your machine.

![Zparty UI](assets/screenshot.png)

---

## What it does

A target URL goes in. A scored security report comes out.

Zparty runs five phases automatically:

```
Phase 0  →  Validation        DNS, reachability, scope enforcement
Phase 1  →  Recon             WHOIS, DNS, subdomains, tech stack, SSL, JS secrets, Wayback
Phase 2  →  Active Scan       Ports, directories, crawl, headers, WAF detection
Phase 3  →  Vulnerabilities   30+ concurrent modules (see list below)
Phase 4  →  Scoring           CVSS 3.1, OWASP Top 10, PCI-DSS 4.0 compliance mapping
Phase 5  →  Report            HTML + SARIF reports, Playwright PoC screenshots
```

After the scan, the **AI Agent** loads the findings into a local LLM (Ollama), identifies exploit chains, selects the highest-impact targets, and attempts live exploitation with automated PoC screenshots.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Browser UI (FastAPI)                │
│         Live log stream via WebSocket               │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│                  Pipeline (asyncio)                  │
│                                                      │
│  Phase 1: Recon modules (sequential, 60s timeout)   │
│  Phase 2: Scan modules  (sequential, 60s timeout)   │
│  Phase 3: Vuln modules  (concurrent, 300s hard cap) │
│                                                      │
│  Rate limiter  │  Scope filter  │  Tor proxy         │
└──────┬─────────┴────────────────┴────────────────────┘
       │
┌──────▼──────────────────────────────────────────────┐
│              30+ Vulnerability Modules               │
│  Each module: async, timeout-guarded, self-contained │
└──────┬──────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────┐
│           Scoring + Compliance + Reports             │
│   CVSS 3.1 · OWASP Top 10 · PCI-DSS 4.0 · SARIF    │
└──────┬──────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────┐
│              AI Exploit Engine (local)               │
│   Ollama LLM → chain analysis → Playwright PoC      │
└─────────────────────────────────────────────────────┘
```

---

## Vulnerability modules

### Recon (Phase 1)
| Module | What it finds |
|---|---|
| WHOIS | Registrar, owner, expiry, ASN |
| DNS Enumeration | A, AAAA, MX, TXT, NS, CNAME, SOA records |
| Subdomain Enumeration | crt.sh + DNS brute-force (top 5000) |
| Tech Fingerprint | Server, framework, CMS, language from headers/HTML/JS |
| SSL Analysis | Cipher strength, certificate validity, HSTS enforcement |
| JS Analysis | API keys, secrets, internal URLs leaked in JavaScript files |
| Wayback Miner | Historical endpoints from the Wayback Machine |
| Error Analysis | Stack traces, debug pages, version disclosure |

### Scan (Phase 2)
| Module | What it finds |
|---|---|
| Port Scanner | Open ports with service fingerprinting (nmap / socket fallback) |
| Dir Bruteforce | Exposed admin panels, `.env`, `.git`, backup files, sensitive paths |
| Crawler | Endpoint and parameter discovery |
| Header Analysis | Missing CSP, HSTS, X-Frame-Options, cookie flags |
| WAF Detection | Firewall presence and bypass surface |

### Vulnerabilities (Phase 3 — concurrent)
| Module | Technique |
|---|---|
| SQL Injection | Error-based, boolean-blind, time-blind, UNION extraction |
| XSS | Reflected, stored, DOM — 50+ context-aware payloads |
| SSTI | Jinja2, Twig, Freemarker, Velocity, Pebble detection |
| SSTI → RCE | Template sandbox escapes → `os.popen()` chain |
| Command Injection | Shell metacharacter injection with OOB confirmation |
| LFI | Path traversal, PHP filter bypass, log poisoning paths |
| SSRF | Internal network probe + cloud metadata (169.254.169.254) |
| SSRF Chain | Multi-hop SSRF with AWS/GCP/Azure credential extraction |
| XXE | External entity injection with OOB exfiltration |
| JWT Attacks | `alg:none`, weak secret brute-force, kid injection |
| CORS | Misconfigured `Access-Control-Allow-Origin` |
| Open Redirect | Parameter-based redirect to attacker-controlled URL |
| Path Traversal | Directory traversal + file read confirmation |
| NoSQL Injection | MongoDB operator injection (`$gt`, `$regex`, `$where`) |
| Deserialization | Java, Python pickle, PHP object injection patterns |
| HTTP Smuggling | CL.TE / TE.CL request smuggling probes |
| HTTP Methods | TRACE, PUT, DELETE, CONNECT method enumeration |
| Race Conditions | Concurrent request timing attacks on sensitive endpoints |
| Race Conditions (AI) | AI-targeted race window detection on financial/coupon endpoints |
| IDOR | Parameter ID enumeration with cross-user response diffing |
| IDOR Chain | Cross-endpoint ID correlation (object A's ID → object B's data) |
| Subdomain Takeover | Dangling CNAME detection for major cloud services |
| GraphQL | Introspection, batching, field suggestion, DoS probes |
| OAuth / OIDC | State parameter, redirect_uri, PKCE, token leakage |
| Mass Assignment | Hidden parameter injection on REST endpoints |
| File Upload | Extension bypass, MIME confusion, webshell delivery |
| Default Credentials | 200+ credential pairs against admin panels |
| Business Logic | Price manipulation, quota bypass, plan escalation |
| CVE Checks | Version-based CVE matching from tech fingerprint |
| Nuclei | Community template engine (1000+ templates) |

---

## AI Exploit Engine

After the scan, an optional AI agent loads findings into a **local LLM via Ollama** — zero data leaves the machine:

1. **Chain analysis** — identifies multi-step exploit paths across findings (e.g. SSRF → cloud metadata → credentials → account takeover)
2. **Target selection** — ranks findings by exploitability and selects the highest-impact ones
3. **Live exploitation** — runs focused exploit routines per finding type:
   - SQLi: UNION-based table/column/data extraction
   - XSS: cookie theft with Playwright browser automation
   - SSTI: sandbox escape → `os.popen()` RCE chain
   - LFI: `/etc/passwd`, `config.php`, PHP filter bypass
   - Default creds: automated login with screenshot proof
4. **Playwright PoC** — captures browser screenshots of confirmed exploits as evidence

Supported local models: `llama3.1`, `qwen2.5-coder`, `mistral`, `deepseek-r1:8b`, `llama3.2`

---

## Evasion & anonymity

- **User-agent rotation** — random real browser UA per request, no tool fingerprint in headers
- **Jitter** — 0–300ms randomized delay between requests (human pacing)
- **Tor integration** — Phase 3 attack traffic routes through Tor SOCKS5, new exit node per module via NEWNYM
- **Proxy support** — HTTP/HTTPS/SOCKS5 proxies, round-robin rotation across a list
- **Scope enforcement** — configurable out-of-scope domains, excluded paths, include-only lists

---

## Output

Every scan produces a timestamped results folder:

```
results/scan_2026-05-19_00-33-18/
├── report/
│   ├── report.html          # Full HTML report with CVSS scores
│   ├── poc_report.html      # AI exploit PoC report with screenshots
│   └── report.sarif         # SARIF format (GitHub Code Scanning compatible)
├── findings.json            # Raw findings (machine-readable)
├── scan_data.json           # Full scan context (recon, endpoints, config)
└── checkpoints/             # Phase-by-phase incremental saves
```

**Scoring:** starts at 100, deducts per finding (Critical −40, High −20, Medium −8, Low −3). Letter grade S → E.

**Compliance:** each finding is mapped to OWASP Top 10 2021 and PCI-DSS 4.0 controls.

**Notifications:** Slack webhook, email, Jira ticket creation, custom webhook — all configurable in `config.yaml`.

---

## Browser UI

```bash
python ui_launch.py
# opens http://localhost:8000
```

- **Full Scan** — runs all phases with live log streaming over WebSocket
- **AI Agent** — loads findings from a previous scan and runs the exploit engine
- Real-time phase progress, per-module status, filterable log terminal
- Scan history and result browser

---

## Installation

**Requirements:** Python 3.11+

```bash
git clone https://github.com/Sid00011/zparty.git
cd zparty
pip install -r requirements.txt
playwright install chromium
```

**Optional — Nuclei integration:**
```bash
python install_tools.py   # downloads nuclei binary automatically
```

**Optional — AI features:**
```bash
# Install Ollama: https://ollama.com/download
ollama pull llama3.1      # 4.7 GB — best reasoning
ollama pull llama3.2      # 2.0 GB — fastest, lowest RAM
```

**Optional — Tor anonymity:**
```bash
# Linux / macOS
sudo apt install tor
# Windows — downloaded automatically on first scan
```

---

## Usage

**1. Set your target in `config.yaml`:**

```yaml
target:
  url: "https://your-target.com"
```

**2. Launch:**

```bash
# Browser UI
python ui_launch.py

# CLI
python main.py scan --target https://your-target.com

# AI exploit engine on existing scan
python main.py analyze --session results/scan_2026-05-19_00-33-18/
```

---

## Configuration

`config.yaml` controls every aspect of the scan:

```yaml
rate_limit:
  requests_per_second: 10
  max_concurrent_threads: 15

modules:
  vulns:
    sqli: true
    xss: true
    nuclei: true
    # enable/disable any module individually

tor:
  enabled: true
  rotate_between_modules: true   # new exit node per module = new IP per module

ai:
  enabled: true
  model: "llama3.1"

auth:
  type: bearer          # none | cookie | bearer | basic | apikey | form
  bearer: "your-token"

notify:
  slack:
    webhook_url: "https://hooks.slack.com/..."
  jira:
    url: "https://yourcompany.atlassian.net"
    project_key: "SEC"
```

---

## Tech stack

| Component | Technology |
|---|---|
| Language | Python 3.11 |
| Async runtime | asyncio |
| HTTP client | httpx (HTTP/1.1, HTTP/2, SOCKS5) |
| Web UI | FastAPI + WebSocket |
| Browser automation | Playwright (Chromium) |
| AI engine | Ollama (local LLM, fully offline) |
| Port scanning | nmap + socket fallback |
| Tor control | stem |
| Reports | Jinja2 (HTML) + SARIF |
| CLI | Typer + Rich |

---

## Project structure

```
zparty/
├── core/                   # Pipeline, rate limiter, auth, scope, Tor, AI engine, CVSS
├── modules/
│   ├── recon/              # 8 passive recon modules
│   ├── scan/               # 5 active scan modules
│   └── vulns/              # 30 vulnerability modules
├── scoring/                # CVSS 3.1 scoring + grading engine
├── reports/                # HTML, SARIF, and PoC report generators
├── ui/                     # FastAPI server + WebSocket live streaming
├── config.yaml             # All scan settings (annotated)
├── requirements.txt
└── main.py                 # CLI entrypoint
```

---

## Legal

**For authorized security testing only.**

Only use Zparty against systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions. The author assumes no liability for misuse.

Intended use cases:
- Penetration testers with a signed scope agreement
- Security researchers testing their own infrastructure
- CTF competitions (HackTheBox, TryHackMe, PicoCTF)
- Students in lab environments (DVWA, WebGoat, VulnHub, Metasploitable)

---

*Built as an independent security research project.*
