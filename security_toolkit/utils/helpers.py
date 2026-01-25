"""
Hjälpfunktioner för Security Toolkit.
"""

import os
from pathlib import Path
from typing import Optional

import yaml

from security_toolkit.models import ScanConfig, Severity


def load_config(config_path: Optional[Path] = None) -> ScanConfig:
    """
    Ladda konfiguration från fil eller använd standardvärden.

    Args:
        config_path: Sökväg till konfigurationsfil (YAML).

    Returns:
        ScanConfig med laddade eller standardvärden.
    """
    if config_path and config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f)

        return ScanConfig(
            exclude_patterns=data.get("exclude_patterns", []),
            include_patterns=data.get("include_patterns", []),
            compliance_frameworks=data.get("compliance_frameworks", ["gdpr", "nis2", "owasp_top10"]),
            severity_threshold=Severity(data.get("severity_threshold", "low")),
            max_depth=data.get("max_depth", 10),
            timeout_seconds=data.get("timeout_seconds", 3600),
            parallel_workers=data.get("parallel_workers", 4),
            output_format=data.get("output_format", "json"),
            verbose=data.get("verbose", False),
        )

    return ScanConfig()


def sanitize_path(path: str) -> str:
    """
    Sanitera en sökväg för säker användning.

    Tar bort path traversal-försök och normaliserar sökvägen.

    Args:
        path: Sökväg att sanitera.

    Returns:
        Saniterad och normaliserad sökväg.
    """
    # Ta bort null bytes
    path = path.replace("\x00", "")

    # Normalisera sökvägen
    path = os.path.normpath(path)

    # Ta bort leading path traversal
    while path.startswith(".."):
        path = path[2:]
        if path.startswith(os.sep):
            path = path[1:]

    return path


def is_binary_file(file_path: Path) -> bool:
    """
    Kontrollera om en fil är binär.

    Args:
        file_path: Sökväg till fil att kontrollera.

    Returns:
        True om filen är binär, False annars.
    """
    binary_extensions = {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".svg",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pyc", ".pyo", ".class", ".o", ".obj", ".a", ".lib",
        ".sqlite", ".db", ".sqlite3",
    }

    if file_path.suffix.lower() in binary_extensions:
        return True

    # Kontrollera första bytes för binärt innehåll
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            # Leta efter null bytes
            if b"\x00" in chunk:
                return True
            # Kontrollera om det är mestadels icke-text bytes
            text_characters = bytes(range(32, 127)) + b"\n\r\t\b"
            non_text = sum(1 for byte in chunk if byte not in text_characters)
            if len(chunk) > 0 and non_text / len(chunk) > 0.30:
                return True
    except (IOError, OSError):
        return True

    return False


def calculate_risk_score(findings: list) -> float:
    """
    Beräkna en total risknivå baserat på fynd.

    Args:
        findings: Lista med Finding-objekt.

    Returns:
        Risknivå mellan 0-100.
    """
    if not findings:
        return 0.0

    # Vikter för olika allvarlighetsgrader
    weights = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0,
    }

    total_weight = sum(weights.get(f.severity, 0) for f in findings)
    max_weight = len(findings) * 10  # Om alla var kritiska

    if max_weight == 0:
        return 0.0

    return min(100.0, (total_weight / max_weight) * 100)


def format_duration(seconds: float) -> str:
    """
    Formatera varaktighet i sekunder till läsbart format.

    Args:
        seconds: Antal sekunder.

    Returns:
        Formaterad sträng (t.ex. "2m 30s").
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def get_language_from_extension(extension: str) -> Optional[str]:
    """
    Bestäm programspråk baserat på filändelse.

    Args:
        extension: Filändelse (med eller utan punkt).

    Returns:
        Språknamn eller None.
    """
    ext = extension.lower().lstrip(".")

    language_map = {
        "py": "python",
        "pyw": "python",
        "pyx": "python",
        "js": "javascript",
        "jsx": "javascript",
        "mjs": "javascript",
        "cjs": "javascript",
        "ts": "typescript",
        "tsx": "typescript",
        "java": "java",
        "kt": "kotlin",
        "kts": "kotlin",
        "scala": "scala",
        "rb": "ruby",
        "erb": "ruby",
        "php": "php",
        "go": "go",
        "rs": "rust",
        "c": "c",
        "h": "c",
        "cpp": "cpp",
        "hpp": "cpp",
        "cc": "cpp",
        "cxx": "cpp",
        "cs": "csharp",
        "swift": "swift",
        "m": "objective-c",
        "mm": "objective-c",
        "pl": "perl",
        "pm": "perl",
        "sh": "shell",
        "bash": "shell",
        "zsh": "shell",
        "ps1": "powershell",
        "psm1": "powershell",
        "sql": "sql",
        "html": "html",
        "htm": "html",
        "css": "css",
        "scss": "scss",
        "sass": "sass",
        "less": "less",
        "vue": "vue",
        "svelte": "svelte",
        "yaml": "yaml",
        "yml": "yaml",
        "json": "json",
        "xml": "xml",
        "md": "markdown",
        "rst": "restructuredtext",
        "tf": "terraform",
        "hcl": "hcl",
    }

    return language_map.get(ext)
