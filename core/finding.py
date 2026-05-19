from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    title: str
    severity: str                   # Critical / High / Medium / Low / Info
    description: str
    affected_url: str
    proof: str                      # raw request + response snippet
    remediation: str
    impact: int = 3                 # 1-5
    likelihood: int = 3             # 1-5
    module: str = ""
    references: list[str] = field(default_factory=list)
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    screenshot: str = ""    # base64-encoded PNG — Playwright proof-of-exploit
    verified: bool = False  # True when Playwright confirmed execution in browser

    @property
    def risk_score(self) -> int:
        return self.impact * self.likelihood

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_score"] = self.risk_score
        return d
