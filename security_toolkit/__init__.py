"""
Security Toolkit - Säkerhetsgranskningsverktygslåda
===================================================

En omfattande verktygslåda för säkerhetsgranskning av:
- Källkod (SAST)
- Webbapplikationer (DAST)
- Beroenden och tredjepartsbibliotek
- Hemligheter och känslig data
- Compliance (GDPR, NIS2, OWASP, ISO 27001, MSB)

Kompatibel med EU- och svenska säkerhetsstandarder.
"""

__version__ = "1.0.0"
__author__ = "Security Toolkit Team"

from security_toolkit.models import (
    Finding,
    ScanResult,
    Severity,
    ComplianceStatus,
)

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "ComplianceStatus",
]
