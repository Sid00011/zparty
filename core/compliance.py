"""
core/compliance.py — OWASP Top 10 2021 and PCI-DSS 4.0 compliance mapping

Maps Zparty finding titles/modules to compliance controls so the report
can show which standard requirements are passing or failing.
"""

# OWASP Top 10 2021 mapping: {A0X_ID: {title, description, modules/title_keywords}}
OWASP_2021 = {
    "A01": {
        "title": "Broken Access Control",
        "description": "Restrictions on authenticated users are not properly enforced.",
        "keywords": ["idor", "unauthorized", "access control", "privilege", "directory listing",
                     "exposed path", "admin panel", "exposed admin"],
        "modules": ["Idor", "CveChecks"],
    },
    "A02": {
        "title": "Cryptographic Failures",
        "description": "Data exposed due to weak/missing cryptography.",
        "keywords": ["ssl", "tls", "hsts", "insecure cookie", "http", "cleartext",
                     "certificate", "weak cipher", "missing.*hsts"],
        "modules": ["SslAnalysis", "HeaderAnalysis"],
    },
    "A03": {
        "title": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized.",
        "keywords": ["sql injection", "xss", "ssti", "xxe", "nosql injection",
                     "command injection", "ldap injection", "path traversal"],
        "modules": ["SqlInjection", "Xss", "Ssti", "Xxe", "NoSqlInjection",
                    "PathTraversal", "CveChecks"],
    },
    "A04": {
        "title": "Insecure Design",
        "description": "Missing or ineffective control design.",
        "keywords": ["race condition", "csrf", "business logic", "rate limit",
                     "mass assignment"],
        "modules": ["RaceConditions"],
    },
    "A05": {
        "title": "Security Misconfiguration",
        "description": "Insecure default configurations, open cloud storage, verbose errors.",
        "keywords": ["misconfiguration", "exposed", "server-status", "debug mode",
                     "default credentials", "directory listing", "swagger", "actuator",
                     "cors", "http method", "phpinfo", "adminer", "phpmyadmin",
                     "jenkins", "grafana", "kibana"],
        "modules": ["HeaderAnalysis", "DirBruteforce", "CorsCheck", "HttpMethods",
                    "CveChecks", "WafDetection"],
    },
    "A06": {
        "title": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "keywords": ["cve-", "log4shell", "spring4shell", "shellshock", "struts",
                     "confluence", "outdated", "vulnerable version"],
        "modules": ["CveChecks"],
    },
    "A07": {
        "title": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication, session management.",
        "keywords": ["jwt", "authentication bypass", "weak password", "brute force",
                     "session fixation", "default credentials", "auth bypass"],
        "modules": ["JwtAttacks", "SqlInjection", "NoSqlInjection"],
    },
    "A08": {
        "title": "Software and Data Integrity Failures",
        "description": "Code and infrastructure not protected against integrity violations.",
        "keywords": ["deserialization", "prototype pollution", "supply chain",
                     "integrity", "update mechanism"],
        "modules": ["Deserialization"],
    },
    "A09": {
        "title": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging and monitoring.",
        "keywords": ["logging", "monitoring", "error disclosure", "stack trace",
                     "verbose error", "debug"],
        "modules": ["ErrorAnalysis"],
    },
    "A10": {
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Web app fetches a remote resource without validating user-supplied URL.",
        "keywords": ["ssrf", "server-side request forgery", "blind ssrf", "oob ssrf"],
        "modules": ["Ssrf"],
    },
}

# PCI-DSS 4.0 mapping (requirement → description + keywords)
PCI_DSS_4 = {
    "6.2.4": {
        "title": "Prevent Common Software Attacks",
        "description": "Software development practices prevent injection, XSS, SSRF.",
        "keywords": ["sql injection", "xss", "ssrf", "xxe", "ssti", "nosql injection"],
    },
    "6.3.2": {
        "title": "Inventory of Bespoke Software",
        "description": "Maintain inventory of bespoke and third-party components.",
        "keywords": ["cve-", "outdated", "vulnerable version", "component"],
    },
    "6.4.1": {
        "title": "Web-Facing Applications Protected",
        "description": "Public-facing web apps reviewed for vulnerabilities.",
        "keywords": ["exposed", "admin", "sensitive file", "information disclosure"],
    },
    "4.2.1": {
        "title": "Strong Cryptography in Transit",
        "description": "Strong cryptography used for data in transit.",
        "keywords": ["ssl", "tls", "hsts", "insecure", "cleartext", "http"],
    },
    "8.3.9": {
        "title": "Multi-Factor Authentication",
        "description": "MFA enforced for admin access.",
        "keywords": ["authentication bypass", "default credentials", "admin panel"],
    },
}


def map_findings_to_compliance(findings: list[dict]) -> dict:
    """
    Given a list of finding dicts, return compliance status for OWASP Top 10 and PCI-DSS.
    Returns:
      {
        "owasp_top10": {
          "A01": {"title": ..., "status": "FAIL", "findings": [...]},
          ...
        },
        "pci_dss": {
          "6.2.4": {"title": ..., "status": "PASS", "findings": []},
          ...
        },
        "owasp_pass_count": 7,
        "owasp_fail_count": 3,
        "pci_pass_count": 4,
        "pci_fail_count": 1,
      }
    """
    owasp_result: dict[str, dict] = {}
    pci_result:   dict[str, dict] = {}

    # ── OWASP Top 10 ──────────────────────────────────────────────────────────
    for code, ctrl in OWASP_2021.items():
        matched = []
        for f in findings:
            title_low  = f.get("title", "").lower()
            module     = f.get("module", "")
            if module in ctrl["modules"]:
                matched.append(f)
            elif any(kw in title_low for kw in ctrl["keywords"]):
                matched.append(f)
        # Deduplicate
        seen_titles: set[str] = set()
        deduped = []
        for f in matched:
            if f.get("title") not in seen_titles:
                seen_titles.add(f.get("title", ""))
                deduped.append(f)

        severities = [f.get("severity") for f in deduped]
        if any(s in ("Critical", "High") for s in severities):
            status = "FAIL"
        elif any(s == "Medium" for s in severities):
            status = "WARN"
        else:
            status = "PASS"

        owasp_result[code] = {
            "title":       ctrl["title"],
            "description": ctrl["description"],
            "status":      status,
            "findings":    deduped[:10],  # cap to avoid huge payload
        }

    # ── PCI-DSS ───────────────────────────────────────────────────────────────
    for req, ctrl in PCI_DSS_4.items():
        matched = []
        for f in findings:
            title_low = f.get("title", "").lower()
            if any(kw in title_low for kw in ctrl["keywords"]):
                matched.append(f)
        severities = [f.get("severity") for f in matched]
        if any(s in ("Critical", "High") for s in severities):
            status = "FAIL"
        elif matched:
            status = "WARN"
        else:
            status = "PASS"
        pci_result[req] = {
            "title":    ctrl["title"],
            "description": ctrl["description"],
            "status":   status,
            "findings": matched[:5],
        }

    owasp_fail  = sum(1 for v in owasp_result.values() if v["status"] == "FAIL")
    owasp_warn  = sum(1 for v in owasp_result.values() if v["status"] == "WARN")
    owasp_pass  = sum(1 for v in owasp_result.values() if v["status"] == "PASS")
    pci_fail    = sum(1 for v in pci_result.values()   if v["status"] == "FAIL")
    pci_pass    = sum(1 for v in pci_result.values()   if v["status"] == "PASS")

    return {
        "owasp_top10":       owasp_result,
        "pci_dss":           pci_result,
        "owasp_fail_count":  owasp_fail,
        "owasp_warn_count":  owasp_warn,
        "owasp_pass_count":  owasp_pass,
        "pci_fail_count":    pci_fail,
        "pci_pass_count":    pci_pass,
    }
