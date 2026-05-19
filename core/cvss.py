"""core/cvss.py — CVSS 3.1 vectors for common finding types"""

import re

# Map of finding title keywords → (vector, score, CWE)
CVSS_MAP = {
    # SQLi
    "sql injection.*auth": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-89"),
    "sql injection.*error": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-89"),
    "sql injection.*time": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "CWE-89"),
    # XSS
    "reflected xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-79"),
    "xss in form": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-79"),
    "stored xss": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "CWE-79"),
    "dom xss": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7, "CWE-79"),
    # SSRF
    "ssrf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CWE-918"),
    # XXE
    "xxe": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-611"),
    # SSTI
    "ssti": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CWE-94"),
    # Path traversal
    "path traversal": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "CWE-22"),
    # CORS
    "cors.*wildcard": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "CWE-942"),
    "cors.*arbitrary": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 8.3, "CWE-942"),
    # JWT
    "jwt.*none": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-347"),
    "jwt.*weak": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-798"),
    # Open redirect
    "open redirect": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-601"),
    # IDOR
    "idor": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "CWE-639"),
    # Sensitive files
    "sensitive file.*git": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "CWE-312"),
    "sensitive file.*env": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "CWE-312"),
    "sensitive file": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N", 5.3, "CWE-312"),
    # Headers
    "missing.*csp": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7, "CWE-1021"),
    "missing.*x-frame": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7, "CWE-1021"),
    "missing.*hsts": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 3.7, "CWE-311"),
    "insecure cookie": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, "CWE-614"),
    # Deserialization
    "deserialization": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-502"),
    # Prototype pollution
    "prototype pollution": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-1321"),
    # Race condition
    "race condition": ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.5, "CWE-362"),
    # HTTP methods
    "http.*put": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5, "CWE-16"),
    "http.*delete": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1, "CWE-16"),
    # Default
    "exposed path": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "CWE-200"),
    "open port": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "CWE-200"),
}


def lookup(title: str, severity: str) -> tuple[str, float, str]:
    """Return (cvss_vector, cvss_score, cwe) for a finding title."""
    title_lower = title.lower()
    for pattern, (vector, score, cwe) in CVSS_MAP.items():
        if re.search(pattern, title_lower):
            return vector, score, cwe
    # Fallback by severity
    fallbacks = {
        "Critical": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CWE-200"),
        "High": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "CWE-200"),
        "Medium": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "CWE-200"),
        "Low": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.1, "CWE-200"),
        "Info": ("", 0.0, ""),
    }
    return fallbacks.get(severity, ("", 0.0, ""))
