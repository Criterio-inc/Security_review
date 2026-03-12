"""
Compliance-granskningsagent för EU- och svenska standarder.

Kontrollerar efterlevnad av:
- GDPR (General Data Protection Regulation)
- NIS2 / Cybersäkerhetslagen (SFS 2025:1506)
- OWASP Top 10 (2025)
- ISO 27001 (2022)
- MCF Riktlinjer (Myndigheten för civilt försvar, f.d. MSB)
- EU Cyber Resilience Act (2024/2847)

Uppdaterad: 2026-01
"""

import re
import uuid
from pathlib import Path
from typing import Optional

import yaml

from security_toolkit.agents.base import BaseAgent
from security_toolkit.models import (
    Finding,
    FindingCategory,
    Severity,
    ScanConfig,
    ScanResult,
    CodeLocation,
    ComplianceCheck,
    ComplianceStatus,
)


# GDPR-specifika kontroller
GDPR_CHECKS = {
    "personal_data_logging": {
        "patterns": [
            r"log\.(info|debug|warning|error)\s*\([^)]*\b(email|phone|ssn|personnummer|address|name)\b",
            r"console\.(log|debug)\s*\([^)]*\b(email|phone|ssn|personnummer|address|name)\b",
            r"print\s*\([^)]*\b(email|phone|ssn|personnummer|address|name)\b",
        ],
        "title": "Potentiell loggning av personuppgifter",
        "description": "Personuppgifter kan loggas vilket strider mot GDPR art. 5.1(c) (dataminimering).",
        "severity": Severity.HIGH,
        "requirement_id": "GDPR-5.1c",
        "requirement_name": "Dataminimering",
    },
    "data_retention": {
        "patterns": [
            r"DELETE\s+FROM.*WHERE.*created_at.*<",
            r"retention.*policy",
            r"data.*expiry",
            r"auto.*delete",
        ],
        "check_absence": True,
        "title": "Ingen synlig policy för datalagring",
        "description": "Ingen kod för automatisk radering av data hittades. GDPR art. 5.1(e) kräver begränsad lagringstid.",
        "severity": Severity.MEDIUM,
        "requirement_id": "GDPR-5.1e",
        "requirement_name": "Lagringsminimering",
    },
    "consent_mechanism": {
        "patterns": [
            r"consent",
            r"gdpr.*accept",
            r"privacy.*policy.*accept",
            r"samtycke",
        ],
        "check_absence": True,
        "files": ["*.html", "*.tsx", "*.jsx", "*.vue"],
        "title": "Samtyckehantering saknas",
        "description": "Ingen synlig samtyckehantering i UI. GDPR art. 7 kräver tydligt samtycke.",
        "severity": Severity.HIGH,
        "requirement_id": "GDPR-7",
        "requirement_name": "Villkor för samtycke",
    },
    "encryption_at_rest": {
        "patterns": [
            r"encrypt",
            r"AES",
            r"cipher",
            r"kryptera",
        ],
        "check_absence": True,
        "title": "Ingen synlig kryptering av lagrad data",
        "description": "Ingen kryptering av data i vila upptäckt. GDPR art. 32 rekommenderar kryptering.",
        "severity": Severity.MEDIUM,
        "requirement_id": "GDPR-32",
        "requirement_name": "Säkerhet vid behandling",
    },
    "data_export": {
        "patterns": [
            r"export.*user.*data",
            r"download.*data",
            r"gdpr.*export",
            r"data.*portability",
        ],
        "check_absence": True,
        "title": "Dataportabilitet kan saknas",
        "description": "Ingen synlig funktion för dataexport. GDPR art. 20 kräver rätt till dataportabilitet.",
        "severity": Severity.LOW,
        "requirement_id": "GDPR-20",
        "requirement_name": "Rätt till dataportabilitet",
    },
}

# NIS2 / Cybersäkerhetslagen (SFS 2025:1506) - kontroller
NIS2_CHECKS = {
    "incident_logging": {
        "patterns": [
            r"security.*incident",
            r"breach.*log",
            r"alert.*system",
            r"siem",
            r"incident.*report",
        ],
        "check_absence": True,
        "title": "Incidenthantering kan vara bristfällig",
        "description": "Ingen synlig incidentloggning eller SIEM-integration. Cybersäkerhetslagen/NIS2 kräver incidenthantering och rapportering till MCF.",
        "severity": Severity.MEDIUM,
        "requirement_id": "CSL-7",
        "requirement_name": "Incidenthantering",
    },
    "backup_mechanism": {
        "patterns": [
            r"backup",
            r"disaster.*recovery",
            r"snapshot",
            r"replika",
        ],
        "check_absence": True,
        "title": "Backup-mekanism kan saknas",
        "description": "Ingen synlig backup-implementation. Cybersäkerhetslagen kräver driftskontinuitet.",
        "severity": Severity.MEDIUM,
        "requirement_id": "CSL-8",
        "requirement_name": "Driftskontinuitet",
    },
    "access_control": {
        "patterns": [
            r"@login_required",
            r"@authenticated",
            r"requireAuth",
            r"isAuthenticated",
            r"auth.*middleware",
            r"passport",
            r"jwt.*verify",
        ],
        "check_absence": True,
        "title": "Åtkomstkontroll kan vara bristfällig",
        "description": "Ingen tydlig autentiseringsmekanism hittad. Cybersäkerhetslagen kräver åtkomstkontroll.",
        "severity": Severity.HIGH,
        "requirement_id": "CSL-9",
        "requirement_name": "Åtkomstkontroll",
    },
    "mfa_implementation": {
        "patterns": [
            r"two.*factor",
            r"2fa",
            r"mfa",
            r"totp",
            r"authenticator",
            r"otp",
        ],
        "check_absence": True,
        "title": "Multifaktorautentisering kan saknas",
        "description": "Ingen synlig MFA-implementation. Cybersäkerhetslagen rekommenderar starkt MFA för känsliga system.",
        "severity": Severity.MEDIUM,
        "requirement_id": "CSL-10",
        "requirement_name": "Stark autentisering",
    },
    "vulnerability_scanning": {
        "patterns": [
            r"security.*scan",
            r"vulnerability.*check",
            r"snyk",
            r"dependabot",
            r"trivy",
            r"safety",
        ],
        "files": [".github/*", "Jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml"],
        "check_absence": True,
        "title": "Automatisk sårbarhetsscanning kan saknas",
        "description": "Ingen CI/CD-integration för sårbarhetsscanning. Cybersäkerhetslagen kräver säkerhetstestning.",
        "severity": Severity.MEDIUM,
        "requirement_id": "CSL-11",
        "requirement_name": "Säkerhetstestning",
    },
    "rate_limiting": {
        "patterns": [
            r"rate.?limit",
            r"throttle",
            r"RateLimit",
            r"slowapi",
            r"flask.?limiter",
            r"express.?rate.?limit",
            r"django.?ratelimit",
            r"throttle_classes",
        ],
        "check_absence": True,
        "title": "Rate limiting kan saknas",
        "description": "Ingen synlig rate limiting-implementation. Cybersäkerhetslagen kräver skydd mot överbelastningsattacker och brute force.",
        "severity": Severity.HIGH,
        "requirement_id": "CSL-12",
        "requirement_name": "Skydd mot överbelastning",
    },
    "csrf_protection": {
        "patterns": [
            r"csrf",
            r"CSRFProtect",
            r"CsrfViewMiddleware",
            r"csurf",
            r"anti.?forgery",
            r"AntiForgeryToken",
            r"csrfmiddlewaretoken",
        ],
        "check_absence": True,
        "title": "CSRF-skydd kan saknas",
        "description": "Ingen synlig CSRF-implementation. Cybersäkerhetslagen kräver skydd mot cross-site request forgery.",
        "severity": Severity.HIGH,
        "requirement_id": "CSL-13",
        "requirement_name": "Skydd mot CSRF-attacker",
    },
    "webhook_verification": {
        "patterns": [
            r"hmac",
            r"webhook.*sign",
            r"signature.*verif",
            r"X-Hub-Signature",
            r"verify_signature",
            r"compute_hash",
        ],
        "check_absence": True,
        "title": "Webhook-signaturverifiering kan saknas",
        "description": "Ingen synlig HMAC/signaturverifiering för webhooks. Cybersäkerhetslagen kräver verifiering av inkommande data.",
        "severity": Severity.MEDIUM,
        "requirement_id": "CSL-14",
        "requirement_name": "Verifiering av extern input",
    },
    "input_validation": {
        "patterns": [
            r"validate",
            r"sanitize",
            r"Schema\s*\(",
            r"Pydantic",
            r"BaseModel",
            r"Joi\.",
            r"Zod\.",
            r"Marshmallow",
            r"WTForm",
            r"class.*Serializer",
            r"express-validator",
        ],
        "check_absence": True,
        "title": "Systematisk input-validering kan saknas",
        "description": "Ingen synlig input-validering med schema eller valideringsramverk. Cybersäkerhetslagen kräver robust inputhantering.",
        "severity": Severity.HIGH,
        "requirement_id": "CSL-15",
        "requirement_name": "Input-validering",
    },
}

# MCF-specifika kontroller (Myndigheten för civilt försvar, f.d. MSB)
MCF_CHECKS = {
    "security_documentation": {
        "patterns": [
            r"SECURITY\.md",
            r"security.*policy",
            r"säkerhetspolicy",
        ],
        "files": ["*.md", "docs/*"],
        "check_absence": True,
        "title": "Säkerhetsdokumentation kan saknas",
        "description": "Ingen SECURITY.md eller säkerhetspolicy hittad. MCF rekommenderar dokumenterat säkerhetsarbete.",
        "severity": Severity.LOW,
        "requirement_id": "MCF-1",
        "requirement_name": "Systematiskt informationssäkerhetsarbete",
    },
    "network_segmentation": {
        "patterns": [
            r"vpc",
            r"subnet",
            r"firewall.*rule",
            r"security.*group",
            r"network.*policy",
        ],
        "files": ["*.tf", "*.yaml", "*.yml", "*.json"],
        "check_absence": True,
        "title": "Nätverkssegmentering kan vara bristfällig",
        "description": "Ingen synlig nätverkssegmentering i IaC-filer. MCF rekommenderar nätverksuppdelning.",
        "severity": Severity.LOW,
        "requirement_id": "MCF-2",
        "requirement_name": "Tekniska säkerhetsåtgärder",
    },
}


class ComplianceCheckerAgent(BaseAgent):
    """
    Agent för compliance-granskning mot EU- och svenska standarder.

    Kontrollerar kod och konfiguration mot:
    - GDPR (2016/679)
    - NIS2 / Cybersäkerhetslagen (SFS 2025:1506)
    - OWASP Top 10 (2025)
    - ISO 27001 (2022)
    - MCF Riktlinjer (f.d. MSB)
    - EU Cyber Resilience Act (2024/2847)
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__(config)
        self.compliance_checks: list[ComplianceCheck] = []
        self._external_findings: list[Finding] = []

    @property
    def scan_type(self) -> str:
        return "Compliance"

    def enrich_with_findings(self, findings: list[Finding]) -> None:
        """
        Ta emot findings från andra agenter (SAST, DAST, etc.)
        för att berika compliance-rapporteringen.

        Args:
            findings: Lista med findings från andra agenter.
        """
        self._external_findings = findings

    async def scan(self, target: str) -> ScanResult:
        """
        Utför compliance-granskning.

        Args:
            target: Sökväg till katalog att granska.

        Returns:
            ScanResult med compliance-status och fynd.
        """
        result = self._create_scan_result(target)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Målsökväg existerar inte: {target}")
            return self._finalize_scan_result(result)

        self.log(f"Startar compliance-granskning av: {target}")

        # Samla all kod för analys
        code_content = await self._collect_code_content(target_path)

        # Utför compliance-kontroller baserat på konfiguration
        frameworks = self.config.compliance_frameworks

        if "gdpr" in frameworks or "all" in frameworks:
            await self._check_gdpr_compliance(code_content, target_path)

        if "nis2" in frameworks or "all" in frameworks:
            await self._check_nis2_compliance(code_content, target_path)

        if "mcf" in frameworks or "msb" in frameworks or "all" in frameworks:
            await self._check_mcf_compliance(code_content, target_path)

        # Berika NIS2-compliance med findings från andra agenter
        if self._external_findings and ("nis2" in frameworks or "all" in frameworks):
            self._enrich_nis2_from_external_findings()

        # Lägg till compliance checks till resultatet
        result.compliance_checks = self.compliance_checks.copy()
        self.compliance_checks.clear()

        return self._finalize_scan_result(result)

    async def _collect_code_content(self, target_path: Path) -> dict[str, str]:
        """Samla innehåll från alla kodfiler."""
        content_map: dict[str, str] = {}

        exclude_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "dist"}

        for file_path in target_path.rglob("*"):
            if any(excluded in file_path.parts for excluded in exclude_dirs):
                continue
            if file_path.is_file():
                try:
                    rel_path = str(file_path.relative_to(target_path))
                    content_map[rel_path] = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass

        return content_map

    async def _check_gdpr_compliance(
        self,
        code_content: dict[str, str],
        target_path: Path,
    ) -> None:
        """Kontrollera GDPR-efterlevnad."""
        self.log("Kontrollerar GDPR-efterlevnad...")

        for check_name, check_config in GDPR_CHECKS.items():
            found = False
            finding_location = None

            for rel_path, content in code_content.items():
                # Filtrera på filtyper om specificerat
                if "files" in check_config:
                    if not any(
                        self._matches_pattern(rel_path, pattern)
                        for pattern in check_config["files"]
                    ):
                        continue

                for pattern in check_config["patterns"]:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        found = True
                        line_num = content[:match.start()].count("\n") + 1
                        finding_location = CodeLocation(
                            file_path=rel_path,
                            line_start=line_num,
                        )
                        break
                if found:
                    break

            # Skapa compliance check
            check_absence = check_config.get("check_absence", False)

            if check_absence:
                # Vi vill att mönstret SKA finnas
                status = ComplianceStatus.NON_COMPLIANT if not found else ComplianceStatus.COMPLIANT
            else:
                # Vi vill INTE att mönstret ska finnas
                status = ComplianceStatus.NON_COMPLIANT if found else ComplianceStatus.COMPLIANT

            compliance_check = ComplianceCheck(
                framework="GDPR",
                requirement_id=check_config["requirement_id"],
                requirement_name=check_config["requirement_name"],
                status=status,
            )

            if status == ComplianceStatus.NON_COMPLIANT:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=check_config["title"],
                    description=check_config["description"],
                    severity=check_config["severity"],
                    category=FindingCategory.PRIVACY,
                    location=finding_location,
                    remediation=self._get_gdpr_remediation(check_name),
                    compliance_frameworks=["gdpr"],
                    metadata={"check_name": check_name},
                )
                self.add_finding(finding)
                compliance_check.findings.append(finding)

            self.compliance_checks.append(compliance_check)

    async def _check_nis2_compliance(
        self,
        code_content: dict[str, str],
        target_path: Path,
    ) -> None:
        """Kontrollera NIS2-efterlevnad."""
        self.log("Kontrollerar NIS2-efterlevnad...")

        for check_name, check_config in NIS2_CHECKS.items():
            found = False
            finding_location = None

            for rel_path, content in code_content.items():
                if "files" in check_config:
                    if not any(
                        self._matches_pattern(rel_path, pattern)
                        for pattern in check_config["files"]
                    ):
                        continue

                for pattern in check_config["patterns"]:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        found = True
                        line_num = content[:match.start()].count("\n") + 1
                        finding_location = CodeLocation(
                            file_path=rel_path,
                            line_start=line_num,
                        )
                        break
                if found:
                    break

            check_absence = check_config.get("check_absence", False)

            if check_absence:
                status = ComplianceStatus.NON_COMPLIANT if not found else ComplianceStatus.COMPLIANT
            else:
                status = ComplianceStatus.NON_COMPLIANT if found else ComplianceStatus.COMPLIANT

            compliance_check = ComplianceCheck(
                framework="NIS2",
                requirement_id=check_config["requirement_id"],
                requirement_name=check_config["requirement_name"],
                status=status,
            )

            if status == ComplianceStatus.NON_COMPLIANT:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=check_config["title"],
                    description=check_config["description"],
                    severity=check_config["severity"],
                    category=FindingCategory.CONFIGURATION,
                    location=finding_location,
                    remediation=self._get_nis2_remediation(check_name),
                    compliance_frameworks=["nis2"],
                    metadata={"check_name": check_name},
                )
                self.add_finding(finding)
                compliance_check.findings.append(finding)

            self.compliance_checks.append(compliance_check)

    async def _check_mcf_compliance(
        self,
        code_content: dict[str, str],
        target_path: Path,
    ) -> None:
        """Kontrollera MCF-riktlinjer (f.d. MSB)."""
        self.log("Kontrollerar MCF-riktlinjer...")

        for check_name, check_config in MCF_CHECKS.items():
            found = False

            for rel_path, content in code_content.items():
                if "files" in check_config:
                    if not any(
                        self._matches_pattern(rel_path, pattern)
                        for pattern in check_config["files"]
                    ):
                        continue

                for pattern in check_config["patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        found = True
                        break
                if found:
                    break

            # Kontrollera även filnamn
            for rel_path in code_content.keys():
                for pattern in check_config["patterns"]:
                    if re.search(pattern, rel_path, re.IGNORECASE):
                        found = True
                        break
                if found:
                    break

            check_absence = check_config.get("check_absence", False)

            if check_absence:
                status = ComplianceStatus.NON_COMPLIANT if not found else ComplianceStatus.COMPLIANT
            else:
                status = ComplianceStatus.NON_COMPLIANT if found else ComplianceStatus.COMPLIANT

            compliance_check = ComplianceCheck(
                framework="MCF",
                requirement_id=check_config["requirement_id"],
                requirement_name=check_config["requirement_name"],
                status=status,
            )

            if status == ComplianceStatus.NON_COMPLIANT:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=check_config["title"],
                    description=check_config["description"],
                    severity=check_config["severity"],
                    category=FindingCategory.CONFIGURATION,
                    remediation=self._get_mcf_remediation(check_name),
                    compliance_frameworks=["mcf"],
                    metadata={"check_name": check_name},
                )
                self.add_finding(finding)
                compliance_check.findings.append(finding)

            self.compliance_checks.append(compliance_check)

    # Mappning från SAST/DAST-regelnamn till NIS2-krav
    _FINDING_TO_NIS2_MAP = {
        "missing_rate_limiting": {
            "requirement_id": "CSL-12",
            "requirement_name": "Skydd mot överbelastning",
        },
        "missing_csrf_protection": {
            "requirement_id": "CSL-13",
            "requirement_name": "Skydd mot CSRF-attacker",
        },
        "missing_webhook_verification": {
            "requirement_id": "CSL-14",
            "requirement_name": "Verifiering av extern input",
        },
        "missing_input_sanitization": {
            "requirement_id": "CSL-15",
            "requirement_name": "Input-validering",
        },
    }

    def _enrich_nis2_from_external_findings(self) -> None:
        """
        Berika NIS2-compliance-resultat med findings från SAST/DAST-agenter.

        Findings som taggar sig med 'nis2' i compliance_frameworks och matchar
        kända regelnamn mappas till NIS2 ComplianceCheck-objekt.
        """
        # Samla NIS2-relevanta findings grupperade per regelnamn
        nis2_findings: dict[str, list[Finding]] = {}

        for finding in self._external_findings:
            if "nis2" not in [fw.lower() for fw in finding.compliance_frameworks]:
                continue

            rule_name = finding.metadata.get("rule", "")
            if rule_name in self._FINDING_TO_NIS2_MAP:
                nis2_findings.setdefault(rule_name, []).append(finding)

        # Skapa ComplianceCheck-objekt för varje grupp
        for rule_name, findings in nis2_findings.items():
            mapping = self._FINDING_TO_NIS2_MAP[rule_name]

            # Kontrollera om vi redan har en check för detta krav
            existing = any(
                c.requirement_id == mapping["requirement_id"]
                for c in self.compliance_checks
            )
            if existing:
                # Uppdatera befintlig check med externa findings
                for check in self.compliance_checks:
                    if check.requirement_id == mapping["requirement_id"]:
                        check.findings.extend(findings)
                        if check.status == ComplianceStatus.COMPLIANT:
                            check.status = ComplianceStatus.PARTIAL
                            check.notes = f"Kodanalys hittade {len(findings)} relaterade varningar från SAST/DAST."
                        break
            else:
                compliance_check = ComplianceCheck(
                    framework="NIS2",
                    requirement_id=mapping["requirement_id"],
                    requirement_name=mapping["requirement_name"],
                    status=ComplianceStatus.NON_COMPLIANT,
                    findings=findings,
                    notes=f"Identifierat via SAST/DAST-skanning: {len(findings)} fynd.",
                )
                self.compliance_checks.append(compliance_check)

        self.log(f"Berikade NIS2-compliance med {sum(len(f) for f in nis2_findings.values())} externa findings")

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Kontrollera om en sökväg matchar ett mönster."""
        from fnmatch import fnmatch
        return fnmatch(path, pattern)

    def _get_gdpr_remediation(self, check_name: str) -> str:
        """Hämta GDPR-åtgärdsrekommendation."""
        remediations = {
            "personal_data_logging": (
                "1. Granska all loggning och ta bort personuppgifter\n"
                "2. Implementera log scrubbing för känslig data\n"
                "3. Använd pseudonymisering i loggar\n"
                "4. Dokumentera laglig grund för eventuell loggning av personuppgifter"
            ),
            "data_retention": (
                "1. Implementera automatisk radering av data efter definierad period\n"
                "2. Dokumentera retentionspolicy\n"
                "3. Lägg till cron-jobb eller scheduled tasks för dataradering\n"
                "4. Implementera 'rätt att bli glömd'-funktion"
            ),
            "consent_mechanism": (
                "1. Implementera cookie consent banner\n"
                "2. Skapa opt-in mekanismer för datainsamling\n"
                "3. Dokumentera samtycken i databasen\n"
                "4. Möjliggör återkallande av samtycke"
            ),
            "encryption_at_rest": (
                "1. Implementera databaskryptering\n"
                "2. Använd krypterade filsystem för känslig data\n"
                "3. Implementera fältnivåkryptering för personuppgifter\n"
                "4. Dokumentera krypteringsrutiner"
            ),
            "data_export": (
                "1. Implementera dataexport-funktion i JSON/CSV-format\n"
                "2. Skapa användargränssnitt för datanedladdning\n"
                "3. Dokumentera dataportabilitetsprocess\n"
                "4. Testa exportfunktionen regelbundet"
            ),
        }
        return remediations.get(check_name, "Granska och åtgärda enligt GDPR-krav.")

    def _get_nis2_remediation(self, check_name: str) -> str:
        """Hämta NIS2/Cybersäkerhetslagen-åtgärdsrekommendation."""
        remediations = {
            "incident_logging": (
                "1. Implementera centraliserad loggning (ELK, Splunk, etc.)\n"
                "2. Skapa incident response-plan\n"
                "3. Implementera alerting för säkerhetshändelser\n"
                "4. Dokumentera rapporteringsrutiner till MCF (CERT-SE)"
            ),
            "backup_mechanism": (
                "1. Implementera automatiska backups\n"
                "2. Skapa disaster recovery-plan\n"
                "3. Testa återställning regelbundet\n"
                "4. Dokumentera RTO och RPO"
            ),
            "access_control": (
                "1. Implementera autentisering på alla endpoints\n"
                "2. Använd RBAC (Role-Based Access Control)\n"
                "3. Implementera session management\n"
                "4. Logga alla åtkomstförsök"
            ),
            "mfa_implementation": (
                "1. Implementera TOTP-baserad MFA\n"
                "2. Erbjud backup-koder\n"
                "3. Kräv MFA för administrativa funktioner\n"
                "4. Dokumentera MFA-policy"
            ),
            "vulnerability_scanning": (
                "1. Lägg till Snyk/Dependabot i CI/CD pipeline\n"
                "2. Implementera SAST-scanning\n"
                "3. Schemalägg regelbundna säkerhetsskanningar\n"
                "4. Dokumentera sårbarhetshanteringsprocess"
            ),
            "rate_limiting": (
                "1. Implementera rate limiting med flask-limiter, express-rate-limit, django-ratelimit eller liknande\n"
                "2. Begränsa auth-endpoints till max 5-10 försök per minut\n"
                "3. Använd en API-gateway eller reverse proxy med inbyggd rate limiting\n"
                "4. Implementera progressiv backoff vid upprepade misslyckade försök"
            ),
            "csrf_protection": (
                "1. Aktivera ramverkets inbyggda CSRF-skydd (Django CsrfViewMiddleware, Flask-WTF CSRFProtect, csurf)\n"
                "2. Inkludera CSRF-tokens i alla formulär och state-changing requests\n"
                "3. Sätt SameSite=Strict på sessions-cookies\n"
                "4. Verifiera Origin/Referer-headers på server-sidan"
            ),
            "webhook_verification": (
                "1. Implementera HMAC-SHA256 signaturverifiering för alla webhook-endpoints\n"
                "2. Jämför X-Hub-Signature-256 (eller motsvarande) med beräknad HMAC\n"
                "3. Använd en delad hemlighet som lagras säkert (miljövariabel/secrets manager)\n"
                "4. Returnera 403 vid ogiltig signatur"
            ),
            "input_validation": (
                "1. Implementera schema-validering med Pydantic, Joi, Zod, Marshmallow eller liknande\n"
                "2. Validera alla request-parametrar mot förväntade typer och format\n"
                "3. Begränsa stränglängder och numeriska intervall\n"
                "4. Använd allowlists istället för blocklists där möjligt"
            ),
        }
        return remediations.get(check_name, "Granska och åtgärda enligt Cybersäkerhetslagen/NIS2-krav.")

    def _get_mcf_remediation(self, check_name: str) -> str:
        """Hämta MCF-åtgärdsrekommendation (f.d. MSB)."""
        remediations = {
            "security_documentation": (
                "1. Skapa SECURITY.md med ansvarsfull disclosure-policy\n"
                "2. Dokumentera säkerhetsprocedurer\n"
                "3. Skapa och publicera security.txt\n"
                "4. Utse säkerhetsansvarig"
            ),
            "network_segmentation": (
                "1. Implementera VPC och subnät-uppdelning\n"
                "2. Konfigurera säkerhetsgrupper/firewall-regler\n"
                "3. Separera produktions- och utvecklingsmiljöer\n"
                "4. Dokumentera nätverksarkitektur"
            ),
        }
        return remediations.get(check_name, "Granska och åtgärda enligt MCF-riktlinjer.")
