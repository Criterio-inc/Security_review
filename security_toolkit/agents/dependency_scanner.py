"""
Beroendegranskningsagent för sårbarhetsdetektering.

Skannar projektberoenden för kända sårbarheter:
- Python (requirements.txt, Pipfile, pyproject.toml)
- JavaScript/Node.js (package.json, package-lock.json)
- Java (pom.xml, build.gradle)
- Ruby (Gemfile)
- PHP (composer.json)
- Go (go.mod)
- Rust (Cargo.toml)
"""

import json
import re
import uuid
from pathlib import Path
from typing import Optional

import httpx

from security_toolkit.agents.base import BaseAgent
from security_toolkit.models import (
    Finding,
    FindingCategory,
    Severity,
    ScanConfig,
    ScanResult,
    CodeLocation,
)


# Dependency file patterns
DEPENDENCY_FILES = {
    "python": [
        "requirements.txt",
        "requirements-*.txt",
        "Pipfile",
        "Pipfile.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
    ],
    "javascript": [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ],
    "java": [
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    ],
    "ruby": [
        "Gemfile",
        "Gemfile.lock",
    ],
    "php": [
        "composer.json",
        "composer.lock",
    ],
    "go": [
        "go.mod",
        "go.sum",
    ],
    "rust": [
        "Cargo.toml",
        "Cargo.lock",
    ],
    "dotnet": [
        "*.csproj",
        "packages.config",
        "*.deps.json",
    ],
}

# OSV API endpoint for vulnerability queries
OSV_API_URL = "https://api.osv.dev/v1/query"


class DependencyScannerAgent(BaseAgent):
    """
    Agent för att skanna projektberoenden efter kända sårbarheter.

    Använder OSV (Open Source Vulnerabilities) databas för att
    identifiera sårbarheter i tredjepartsbibliotek.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__(config)
        self.client: Optional[httpx.AsyncClient] = None

    @property
    def scan_type(self) -> str:
        return "Dependency"

    async def scan(self, target: str) -> ScanResult:
        """
        Skanna projektberoenden efter sårbarheter.

        Args:
            target: Sökväg till projektkatalog.

        Returns:
            ScanResult med alla upptäckta sårbara beroenden.
        """
        result = self._create_scan_result(target)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Målsökväg existerar inte: {target}")
            return self._finalize_scan_result(result)

        self.log(f"Startar beroendesskanning av: {target}")

        async with httpx.AsyncClient(timeout=30.0) as self.client:
            # Hitta och analysera beroendefiler
            for language, patterns in DEPENDENCY_FILES.items():
                for pattern in patterns:
                    if "*" in pattern:
                        files = list(target_path.rglob(pattern))
                    else:
                        files = list(target_path.rglob(pattern))

                    for file_path in files:
                        if self._should_exclude(str(file_path)):
                            continue
                        await self._scan_dependency_file(file_path, language, target_path)

        return self._finalize_scan_result(result)

    async def _scan_dependency_file(
        self,
        file_path: Path,
        language: str,
        base_path: Path,
    ) -> None:
        """Skanna en beroendefil för sårbarheter."""
        rel_path = str(file_path.relative_to(base_path))
        self.log(f"Analyserar: {rel_path}")

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.log(f"Kunde inte läsa: {file_path}: {e}", "error")
            return

        # Extrahera beroenden baserat på filtyp
        dependencies = self._extract_dependencies(file_path.name, content, language)

        for dep_name, dep_version in dependencies:
            # Kontrollera efter sårbarheter via OSV
            vulns = await self._query_osv(dep_name, dep_version, language)

            for vuln in vulns:
                severity = self._determine_severity(vuln)

                self.add_finding(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Sårbart beroende: {dep_name}",
                    description=self._format_vuln_description(vuln),
                    severity=severity,
                    category=FindingCategory.VULNERABLE_COMPONENT,
                    location=CodeLocation(
                        file_path=rel_path,
                        line_start=1,
                    ),
                    cve_id=self._extract_cve(vuln),
                    cvss_score=self._extract_cvss(vuln),
                    remediation=self._format_remediation(vuln, dep_name),
                    references=vuln.get("references", [])[:5],
                    compliance_frameworks=["nis2", "owasp_top10"],
                    metadata={
                        "package": dep_name,
                        "installed_version": dep_version,
                        "vuln_id": vuln.get("id"),
                        "language": language,
                    },
                ))

    def _extract_dependencies(
        self,
        filename: str,
        content: str,
        language: str,
    ) -> list[tuple[str, str]]:
        """Extrahera beroenden och versioner från en beroendefil."""
        dependencies = []

        if filename == "requirements.txt" or filename.startswith("requirements"):
            # Python requirements.txt
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9][^\s;#]*)?", line)
                if match:
                    dependencies.append((match.group(1).lower(), match.group(3) or ""))

        elif filename == "package.json":
            # JavaScript package.json
            try:
                data = json.loads(content)
                for dep_type in ["dependencies", "devDependencies"]:
                    for name, version in data.get(dep_type, {}).items():
                        # Rensa version från prefix
                        clean_version = re.sub(r"^[\^~>=<]+", "", str(version))
                        dependencies.append((name, clean_version))
            except json.JSONDecodeError:
                pass

        elif filename in ("Gemfile.lock", "Gemfile"):
            # Ruby
            gem_pattern = re.compile(r"^\s*([a-zA-Z0-9_-]+)\s*\(([0-9][^\)]*)\)", re.MULTILINE)
            for match in gem_pattern.finditer(content):
                dependencies.append((match.group(1), match.group(2)))

        elif filename == "composer.json":
            # PHP Composer
            try:
                data = json.loads(content)
                for dep_type in ["require", "require-dev"]:
                    for name, version in data.get(dep_type, {}).items():
                        if name != "php":
                            clean_version = re.sub(r"^[\^~>=<]+", "", str(version))
                            dependencies.append((name, clean_version))
            except json.JSONDecodeError:
                pass

        elif filename == "go.mod":
            # Go modules
            require_pattern = re.compile(
                r"^\s*([a-zA-Z0-9_./\-]+)\s+v([0-9][^\s]*)",
                re.MULTILINE,
            )
            for match in require_pattern.finditer(content):
                dependencies.append((match.group(1), match.group(2)))

        elif filename == "Cargo.toml":
            # Rust Cargo
            dep_pattern = re.compile(
                r'^\s*([a-zA-Z0-9_-]+)\s*=\s*["\']?([0-9][^"\']*)["\']?',
                re.MULTILINE,
            )
            for match in dep_pattern.finditer(content):
                dependencies.append((match.group(1), match.group(2)))

        elif filename == "pom.xml":
            # Java Maven
            dep_pattern = re.compile(
                r"<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>",
                re.DOTALL,
            )
            for match in dep_pattern.finditer(content):
                full_name = f"{match.group(1)}:{match.group(2)}"
                dependencies.append((full_name, match.group(3)))

        elif filename == "pyproject.toml":
            # Python pyproject.toml
            dep_pattern = re.compile(
                r'^\s*"?([a-zA-Z0-9_-]+)"?\s*[=<>!~]+\s*"?([0-9][^"]*)"?',
                re.MULTILINE,
            )
            for match in dep_pattern.finditer(content):
                dependencies.append((match.group(1).lower(), match.group(2)))

        return dependencies

    async def _query_osv(
        self,
        package_name: str,
        version: str,
        language: str,
    ) -> list[dict]:
        """Fråga OSV-databasen efter sårbarheter."""
        ecosystem_map = {
            "python": "PyPI",
            "javascript": "npm",
            "java": "Maven",
            "ruby": "RubyGems",
            "php": "Packagist",
            "go": "Go",
            "rust": "crates.io",
            "dotnet": "NuGet",
        }

        ecosystem = ecosystem_map.get(language)
        if not ecosystem:
            return []

        query = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }

        if version:
            query["version"] = version

        try:
            response = await self.client.post(OSV_API_URL, json=query)
            if response.status_code == 200:
                data = response.json()
                return data.get("vulns", [])
        except httpx.RequestError as e:
            self.log(f"Kunde inte fråga OSV: {e}", "warning")

        return []

    def _determine_severity(self, vuln: dict) -> Severity:
        """Bestäm allvarlighetsgrad från sårbarhetsinformation."""
        # Försök extrahera CVSS
        cvss = self._extract_cvss(vuln)
        if cvss:
            if cvss >= 9.0:
                return Severity.CRITICAL
            elif cvss >= 7.0:
                return Severity.HIGH
            elif cvss >= 4.0:
                return Severity.MEDIUM
            else:
                return Severity.LOW

        # Fallback till severity i data
        severity_str = ""
        for severity_data in vuln.get("severity", []):
            if severity_data.get("type") == "CVSS_V3":
                score = severity_data.get("score", "")
                if "CRITICAL" in score:
                    return Severity.CRITICAL
                elif "HIGH" in score:
                    return Severity.HIGH
                elif "MEDIUM" in score:
                    return Severity.MEDIUM
                elif "LOW" in score:
                    return Severity.LOW

        return Severity.MEDIUM  # Default

    def _extract_cve(self, vuln: dict) -> Optional[str]:
        """Extrahera CVE-ID från sårbarhetsinformation."""
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return None

    def _extract_cvss(self, vuln: dict) -> Optional[float]:
        """Extrahera CVSS-poäng från sårbarhetsinformation."""
        for severity_data in vuln.get("severity", []):
            if severity_data.get("type") == "CVSS_V3":
                score = severity_data.get("score", "")
                # Försök extrahera numeriskt värde
                match = re.search(r"(\d+\.?\d*)", score)
                if match:
                    return float(match.group(1))
        return None

    def _format_vuln_description(self, vuln: dict) -> str:
        """Formatera sårbarhetsbeskrivning."""
        summary = vuln.get("summary", "")
        details = vuln.get("details", "")

        if summary and details:
            return f"{summary}\n\n{details[:500]}"
        return summary or details or "Ingen beskrivning tillgänglig."

    def _format_remediation(self, vuln: dict, package_name: str) -> str:
        """Formatera åtgärdsrekommendation."""
        fixed_versions = []
        for affected in vuln.get("affected", []):
            for range_data in affected.get("ranges", []):
                for event in range_data.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        if fixed_versions:
            versions = ", ".join(set(fixed_versions))
            return f"Uppgradera {package_name} till version {versions} eller senare."

        return f"Kontrollera om en uppdaterad version av {package_name} finns tillgänglig."
