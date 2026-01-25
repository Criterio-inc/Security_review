"""
Datamodeller för säkerhetsgranskningsresultat.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from pathlib import Path


class Severity(Enum):
    """Allvarlighetsgrad för säkerhetsfynd."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> float:
        """Returnera numeriskt värde för allvarlighetsgrad."""
        scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.0,
        }
        return scores[self]

    @property
    def color(self) -> str:
        """Returnera färg för terminal-output."""
        colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        return colors[self]


class ComplianceStatus(Enum):
    """Status för compliance-kontroll."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class FindingCategory(Enum):
    """Kategori för säkerhetsfynd."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"
    CRYPTOGRAPHY = "cryptography"
    CONFIGURATION = "configuration"
    DATA_EXPOSURE = "data_exposure"
    VULNERABLE_COMPONENT = "vulnerable_component"
    SECRET_EXPOSURE = "secret_exposure"
    LOGGING = "logging"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    PRIVACY = "privacy"
    OTHER = "other"


@dataclass
class CodeLocation:
    """Plats i källkod där ett fynd upptäcktes."""
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    code_snippet: Optional[str] = None

    def __str__(self) -> str:
        location = f"{self.file_path}:{self.line_start}"
        if self.line_end and self.line_end != self.line_start:
            location += f"-{self.line_end}"
        return location


@dataclass
class Finding:
    """Ett säkerhetsfynd från en granskning."""
    id: str
    title: str
    description: str
    severity: Severity
    category: FindingCategory
    location: Optional[CodeLocation] = None
    url: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)
    false_positive: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Konvertera till dictionary för JSON-serialisering."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "location": str(self.location) if self.location else None,
            "url": self.url,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "references": self.references,
            "compliance_frameworks": self.compliance_frameworks,
            "false_positive": self.false_positive,
            "metadata": self.metadata,
        }


@dataclass
class ComplianceCheck:
    """Resultat av en compliance-kontroll."""
    framework: str
    requirement_id: str
    requirement_name: str
    status: ComplianceStatus
    findings: list[Finding] = field(default_factory=list)
    notes: Optional[str] = None

    @property
    def is_passing(self) -> bool:
        """Kontrollera om kontrollen är godkänd."""
        return self.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.NOT_APPLICABLE)


@dataclass
class ScanResult:
    """Resultat från en säkerhetsskanning."""
    scan_id: str
    scan_type: str
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: list[Finding] = field(default_factory=list)
    compliance_checks: list[ComplianceCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Beräkna skanningens längd i sekunder."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def critical_count(self) -> int:
        """Antal kritiska fynd."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Antal höga fynd."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Antal medium fynd."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Antal låga fynd."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Antal informationsfynd."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        """Totalt antal fynd."""
        return len(self.findings)

    @property
    def risk_score(self) -> float:
        """Beräkna total risknivå (0-100)."""
        if not self.findings:
            return 0.0
        total_score = sum(f.severity.score for f in self.findings)
        max_possible = len(self.findings) * 10
        return min(100.0, (total_score / max_possible) * 100)

    @property
    def compliance_summary(self) -> dict[str, dict]:
        """Sammanfattning av compliance-status per ramverk."""
        summary: dict[str, dict] = {}
        for check in self.compliance_checks:
            if check.framework not in summary:
                summary[check.framework] = {
                    "total": 0,
                    "compliant": 0,
                    "non_compliant": 0,
                    "partial": 0,
                }
            summary[check.framework]["total"] += 1
            if check.status == ComplianceStatus.COMPLIANT:
                summary[check.framework]["compliant"] += 1
            elif check.status == ComplianceStatus.NON_COMPLIANT:
                summary[check.framework]["non_compliant"] += 1
            elif check.status == ComplianceStatus.PARTIAL:
                summary[check.framework]["partial"] += 1
        return summary

    def to_dict(self) -> dict:
        """Konvertera till dictionary för JSON-serialisering."""
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "risk_score": self.risk_score,
            },
            "findings": [f.to_dict() for f in self.findings],
            "compliance_summary": self.compliance_summary,
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass
class ScanConfig:
    """Konfiguration för en säkerhetsskanning."""
    target_path: Optional[Path] = None
    target_url: Optional[str] = None
    scan_types: list[str] = field(default_factory=lambda: ["all"])
    exclude_patterns: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)
    compliance_frameworks: list[str] = field(
        default_factory=lambda: ["gdpr", "nis2", "owasp_top10"]
    )
    severity_threshold: Severity = Severity.LOW
    max_depth: int = 10
    timeout_seconds: int = 3600
    parallel_workers: int = 4
    output_format: str = "json"
    output_path: Optional[Path] = None
    verbose: bool = False
