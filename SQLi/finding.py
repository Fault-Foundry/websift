from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class VulnType(str, Enum):
    SQLI = "sqli"
    IDOR = "idor"
    XSS = "xss"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    vuln_type: VulnType
    url: str
    parameter: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str = ""
    remediation: str = ""
    extra: dict = field(default_factory=dict)
    found_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))