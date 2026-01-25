"""
Basagent för säkerhetsgranskningar.
"""

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

from security_toolkit.models import ScanConfig, ScanResult, Finding


def load_ignore_patterns(target_path: Path) -> list[str]:
    """
    Ladda ignore-mönster från .security-toolkit-ignore fil.

    Filen stöder:
    - Glob-mönster (*.py, **/*.test.js)
    - Kommentarer med #
    - Tomma rader ignoreras
    """
    ignore_file = target_path / ".security-toolkit-ignore"
    patterns = []

    if ignore_file.exists():
        for line in ignore_file.read_text().splitlines():
            line = line.strip()
            # Ignorera tomma rader och kommentarer
            if line and not line.startswith("#"):
                patterns.append(line)

    return patterns


class BaseAgent(ABC):
    """
    Abstrakt basklass för alla säkerhetsgranskningsagenter.

    Alla agenter ärver från denna klass och implementerar
    den abstrakta scan-metoden.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initiera agenten med konfiguration.

        Args:
            config: Skanningskonfiguration, använder standardvärden om None.
        """
        self.config = config or ScanConfig()
        self.agent_name = self.__class__.__name__
        self._findings: list[Finding] = []
        self._ignore_patterns: list[str] = []

    def load_ignore_file(self, target_path: Path) -> None:
        """Ladda ignore-mönster från projektets .security-toolkit-ignore."""
        self._ignore_patterns = load_ignore_patterns(target_path)

    @property
    @abstractmethod
    def scan_type(self) -> str:
        """Returnera typ av skanning som agenten utför."""
        pass

    @abstractmethod
    async def scan(self, target: str) -> ScanResult:
        """
        Utför säkerhetsskanning av målet.

        Args:
            target: Sökväg eller URL att skanna.

        Returns:
            ScanResult med alla fynd och metadata.
        """
        pass

    def _create_scan_result(self, target: str) -> ScanResult:
        """Skapa ett nytt ScanResult-objekt."""
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            scan_type=self.scan_type,
            target=target,
            started_at=datetime.now(),
        )

    def _finalize_scan_result(self, result: ScanResult) -> ScanResult:
        """Avsluta skanningen och sätt tidsstämpel."""
        result.completed_at = datetime.now()
        result.findings = self._findings.copy()
        self._findings.clear()
        return result

    def add_finding(self, finding: Finding) -> None:
        """Lägg till ett fynd i resultatet."""
        # Filtrera baserat på allvarlighetströskel
        if finding.severity.score >= self.config.severity_threshold.score:
            self._findings.append(finding)

    def _should_exclude(self, path: str) -> bool:
        """Kontrollera om en sökväg ska exkluderas från skanning."""
        # Kolla config-mönster
        for pattern in self.config.exclude_patterns:
            if fnmatch(path, pattern):
                return True

        # Kolla .security-toolkit-ignore mönster
        for pattern in self._ignore_patterns:
            if fnmatch(path, pattern):
                return True

        return False

    def _should_include(self, path: str) -> bool:
        """Kontrollera om en sökväg ska inkluderas i skanning."""
        if not self.config.include_patterns:
            return True

        for pattern in self.config.include_patterns:
            if fnmatch(path, pattern):
                return True
        return False

    def _get_files_to_scan(self, target_path: Path) -> list[Path]:
        """Hämta lista över filer att skanna."""
        files = []

        if target_path.is_file():
            if self._should_include(str(target_path)) and not self._should_exclude(str(target_path)):
                files.append(target_path)
        elif target_path.is_dir():
            for file_path in target_path.rglob("*"):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(target_path))
                    if self._should_include(rel_path) and not self._should_exclude(rel_path):
                        files.append(file_path)

        return files

    def log(self, message: str, level: str = "info") -> None:
        """Logga ett meddelande om verbose är aktiverat."""
        if self.config.verbose:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [{level.upper()}] [{self.agent_name}] {message}")
