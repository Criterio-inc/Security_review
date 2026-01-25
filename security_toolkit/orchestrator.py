"""
Huvudorkestrerare för säkerhetsgranskningar.

Koordinerar alla agenter och sammanställer resultat.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from security_toolkit.models import ScanConfig, ScanResult, Finding
from security_toolkit.agents import (
    CodeScannerAgent,
    WebScannerAgent,
    DependencyScannerAgent,
    SecretScannerAgent,
    ComplianceCheckerAgent,
)


class SecurityOrchestrator:
    """
    Orkestrerare som koordinerar alla säkerhetsgranskningsagenter.

    Stöder parallell körning av agenter och aggregering av resultat.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initiera orkestreraren med konfiguration.

        Args:
            config: Global konfiguration för alla agenter.
        """
        self.config = config or ScanConfig()
        self.results: list[ScanResult] = []

    async def scan_repository(self, path: str) -> list[ScanResult]:
        """
        Utför fullständig säkerhetsgranskning av ett repository.

        Args:
            path: Sökväg till repository att granska.

        Returns:
            Lista med resultat från alla agenter.
        """
        self.results.clear()
        target_path = Path(path).resolve()

        if not target_path.exists():
            raise ValueError(f"Sökvägen existerar inte: {path}")

        # Skapa agenterna
        agents = []
        scan_types = self.config.scan_types

        if "all" in scan_types or "code" in scan_types or "sast" in scan_types:
            agents.append(("SAST", CodeScannerAgent(self.config)))

        if "all" in scan_types or "secrets" in scan_types:
            agents.append(("Secrets", SecretScannerAgent(self.config)))

        if "all" in scan_types or "dependencies" in scan_types or "sca" in scan_types:
            agents.append(("Dependencies", DependencyScannerAgent(self.config)))

        if "all" in scan_types or "compliance" in scan_types:
            agents.append(("Compliance", ComplianceCheckerAgent(self.config)))

        # Kör agenter parallellt
        tasks = [self._run_agent(name, agent, str(target_path)) for name, agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Samla resultat
        for result in results:
            if isinstance(result, Exception):
                print(f"Agent error: {result}")
            elif result is not None:
                self.results.append(result)

        return self.results

    async def scan_web_application(self, url: str) -> list[ScanResult]:
        """
        Utför säkerhetsgranskning av en webbapplikation.

        Args:
            url: URL till webbapplikationen.

        Returns:
            Lista med resultat från webbskanningen.
        """
        self.results.clear()

        # Validera URL
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Ogiltig URL: {url}")

        # Kör webbscanner
        agent = WebScannerAgent(self.config)
        result = await self._run_agent("DAST", agent, url)
        if result:
            self.results.append(result)

        return self.results

    async def scan_all(
        self,
        repo_path: Optional[str] = None,
        web_url: Optional[str] = None,
    ) -> list[ScanResult]:
        """
        Utför både repository- och webbgranskning.

        Args:
            repo_path: Sökväg till repository (valfritt).
            web_url: URL till webbapplikation (valfritt).

        Returns:
            Kombinerad lista med alla resultat.
        """
        self.results.clear()
        tasks = []

        if repo_path:
            tasks.append(self.scan_repository(repo_path))

        if web_url:
            tasks.append(self.scan_web_application(web_url))

        if not tasks:
            raise ValueError("Minst en av repo_path eller web_url måste anges.")

        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result_list in all_results:
            if isinstance(result_list, Exception):
                print(f"Scan error: {result_list}")
            elif isinstance(result_list, list):
                self.results.extend(result_list)

        return self.results

    async def _run_agent(
        self,
        name: str,
        agent,
        target: str,
    ) -> Optional[ScanResult]:
        """Kör en agent och hantera eventuella fel."""
        try:
            if self.config.verbose:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Startar {name}-skanning...")
            return await agent.scan(target)
        except Exception as e:
            if self.config.verbose:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {name}-fel: {e}")
            return None

    def get_summary(self) -> dict:
        """
        Generera sammanfattning av alla skanningsresultat.

        Returns:
            Dictionary med sammanfattande statistik.
        """
        total_findings = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        compliance_summary: dict[str, dict] = {}

        for result in self.results:
            total_findings += result.total_findings
            critical += result.critical_count
            high += result.high_count
            medium += result.medium_count
            low += result.low_count
            info += result.info_count

            # Aggregera compliance
            for framework, stats in result.compliance_summary.items():
                if framework not in compliance_summary:
                    compliance_summary[framework] = {
                        "total": 0,
                        "compliant": 0,
                        "non_compliant": 0,
                        "partial": 0,
                    }
                for key in ["total", "compliant", "non_compliant", "partial"]:
                    compliance_summary[framework][key] += stats.get(key, 0)

        return {
            "total_findings": total_findings,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
            },
            "compliance": compliance_summary,
            "scan_count": len(self.results),
        }

    def get_all_findings(self) -> list[Finding]:
        """
        Hämta alla fynd från alla skanningar.

        Returns:
            Lista med alla findings.
        """
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """
        Filtrera fynd efter allvarlighetsgrad.

        Args:
            severity: Allvarlighetsgrad att filtrera på.

        Returns:
            Lista med matchande findings.
        """
        from security_toolkit.models import Severity
        target_severity = Severity(severity.lower())

        return [f for f in self.get_all_findings() if f.severity == target_severity]

    def get_findings_by_framework(self, framework: str) -> list[Finding]:
        """
        Filtrera fynd efter compliance-ramverk.

        Args:
            framework: Ramverk att filtrera på (gdpr, nis2, etc).

        Returns:
            Lista med matchande findings.
        """
        framework_lower = framework.lower()
        return [
            f for f in self.get_all_findings()
            if framework_lower in [fw.lower() for fw in f.compliance_frameworks]
        ]
