"""
Kommandoradsgränssnitt för säkerhetsverktygslådan.

Användning:
    security-scan repo /path/to/repo --output report.json
    security-scan web https://example.com --output report.html
    security-scan full /path/to/repo --url https://example.com
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from security_toolkit.models import ScanConfig, Severity
from security_toolkit.orchestrator import SecurityOrchestrator
from security_toolkit.reports import ReportGenerator


console = Console()


def print_banner():
    """Visa välkomstbanner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║          🔒 Security Toolkit - Säkerhetsgranskare 🔒          ║
║                                                               ║
║  Omfattande säkerhetsgranskning för kod och webbapplikationer ║
║  Kompatibel med GDPR, NIS2, OWASP Top 10, ISO 27001, MSB      ║
╚═══════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold blue")


def create_config(
    exclude: tuple,
    include: tuple,
    frameworks: tuple,
    severity: str,
    verbose: bool,
    scan_types: tuple,
) -> ScanConfig:
    """Skapa konfiguration från CLI-argument."""
    return ScanConfig(
        exclude_patterns=list(exclude) if exclude else [],
        include_patterns=list(include) if include else [],
        compliance_frameworks=list(frameworks) if frameworks else ["gdpr", "nis2", "owasp_top10"],
        severity_threshold=Severity(severity.lower()),
        verbose=verbose,
        scan_types=list(scan_types) if scan_types else ["all"],
    )


@click.group()
@click.version_option(version="1.0.0", prog_name="Security Toolkit")
def main():
    """
    Security Toolkit - Säkerhetsgranskningsverktygslåda

    Utför omfattande säkerhetsgranskning av kod, repositories
    och webbapplikationer enligt EU- och svenska standarder.
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", help="Sökväg för rapportfil")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "html", "markdown", "sarif"]),
              default="json", help="Rapportformat")
@click.option("--exclude", "-e", multiple=True, help="Mönster att exkludera")
@click.option("--include", "-i", multiple=True, help="Mönster att inkludera")
@click.option("--framework", "-fw", "frameworks", multiple=True,
              help="Compliance-ramverk (gdpr, nis2, owasp_top10, iso27001, msb)")
@click.option("--severity", "-s",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="low", help="Minsta allvarlighetsgrad att rapportera")
@click.option("--scan-type", "-t", "scan_types", multiple=True,
              help="Skanningstyper (sast, secrets, dependencies, compliance, all)")
@click.option("--verbose", "-v", is_flag=True, help="Visa detaljerad output")
def repo(
    path: str,
    output: Optional[str],
    output_format: str,
    exclude: tuple,
    include: tuple,
    frameworks: tuple,
    severity: str,
    scan_types: tuple,
    verbose: bool,
):
    """
    Skanna ett repository efter säkerhetsproblem.

    Utför SAST, hemlighetsdetektering, beroendeanalys och compliance-granskning.
    """
    print_banner()

    config = create_config(exclude, include, frameworks, severity, verbose, scan_types)
    orchestrator = SecurityOrchestrator(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Skannar repository...", total=None)

        results = asyncio.run(orchestrator.scan_repository(path))

        progress.update(task, completed=True)

    _display_results(orchestrator, output, output_format)


@main.command()
@click.argument("url")
@click.option("--output", "-o", help="Sökväg för rapportfil")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "html", "markdown", "sarif"]),
              default="json", help="Rapportformat")
@click.option("--severity", "-s",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="low", help="Minsta allvarlighetsgrad att rapportera")
@click.option("--verbose", "-v", is_flag=True, help="Visa detaljerad output")
def web(
    url: str,
    output: Optional[str],
    output_format: str,
    severity: str,
    verbose: bool,
):
    """
    Skanna en webbapplikation efter säkerhetsproblem.

    Utför DAST-skanning inklusive kontroll av säkerhetsheaders,
    SSL/TLS, cookies och exponerade filer.
    """
    print_banner()

    config = ScanConfig(
        severity_threshold=Severity(severity.lower()),
        verbose=verbose,
        scan_types=["web"],
    )
    orchestrator = SecurityOrchestrator(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Skannar webbapplikation...", total=None)

        results = asyncio.run(orchestrator.scan_web_application(url))

        progress.update(task, completed=True)

    _display_results(orchestrator, output, output_format)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--url", "-u", help="URL till webbapplikation")
@click.option("--output", "-o", help="Sökväg för rapportfil")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "html", "markdown", "sarif"]),
              default="json", help="Rapportformat")
@click.option("--exclude", "-e", multiple=True, help="Mönster att exkludera")
@click.option("--framework", "-fw", "frameworks", multiple=True,
              help="Compliance-ramverk")
@click.option("--severity", "-s",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="low", help="Minsta allvarlighetsgrad")
@click.option("--verbose", "-v", is_flag=True, help="Visa detaljerad output")
def full(
    path: str,
    url: Optional[str],
    output: Optional[str],
    output_format: str,
    exclude: tuple,
    frameworks: tuple,
    severity: str,
    verbose: bool,
):
    """
    Utför fullständig säkerhetsgranskning (repo + webb).

    Kombinerar repository-skanning med webbapplikationsanalys
    för en komplett säkerhetsbild.
    """
    print_banner()

    config = create_config(exclude, (), frameworks, severity, verbose, ("all",))
    orchestrator = SecurityOrchestrator(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Utför fullständig säkerhetsgranskning...", total=None)

        results = asyncio.run(orchestrator.scan_all(repo_path=path, web_url=url))

        progress.update(task, completed=True)

    _display_results(orchestrator, output, output_format)


@main.command()
@click.option("--output", "-o", help="Sökväg för rapportfil")
def interactive(output: Optional[str]):
    """
    Interaktiv säkerhetsgranskning med guidade frågor.

    Ställer frågor för att anpassa skanningen efter dina behov.
    """
    print_banner()

    console.print("\n[bold cyan]Välkommen till interaktiv säkerhetsgranskning![/bold cyan]\n")
    console.print("Besvara frågorna nedan för att konfigurera din skanning.\n")

    # Fråga 1: Vad ska skannas?
    console.print("[bold]1. Vad vill du skanna?[/bold]")
    console.print("   [1] Lokal kod/repository")
    console.print("   [2] Webbapplikation (URL)")
    console.print("   [3] Båda")
    scan_choice = click.prompt("   Välj", type=click.Choice(["1", "2", "3"]), default="1")

    repo_path = None
    web_url = None

    if scan_choice in ["1", "3"]:
        repo_path = click.prompt("\n   Sökväg till repository", type=click.Path(exists=True), default=".")

    if scan_choice in ["2", "3"]:
        web_url = click.prompt("\n   URL till webbapplikation", type=str)

    # Fråga 2: Vilka skanningstyper?
    console.print("\n[bold]2. Vilka skanningar vill du köra?[/bold]")
    console.print("   [1] Alla (rekommenderas)")
    console.print("   [2] Endast kodgranskning (SAST)")
    console.print("   [3] Endast hemlighetsdetektering")
    console.print("   [4] Endast beroendesårbarheter")
    console.print("   [5] Endast compliance-granskning")
    scan_type_choice = click.prompt("   Välj", type=click.Choice(["1", "2", "3", "4", "5"]), default="1")

    scan_type_map = {
        "1": ["all"],
        "2": ["sast"],
        "3": ["secrets"],
        "4": ["dependencies"],
        "5": ["compliance"],
    }
    scan_types = scan_type_map[scan_type_choice]

    # Fråga 3: Compliance-ramverk
    console.print("\n[bold]3. Vilka compliance-ramverk är relevanta?[/bold]")
    console.print("   [1] Alla (GDPR, NIS2, OWASP)")
    console.print("   [2] Endast GDPR")
    console.print("   [3] Endast NIS2")
    console.print("   [4] Endast OWASP Top 10")
    console.print("   [5] GDPR + NIS2 (EU-fokus)")
    framework_choice = click.prompt("   Välj", type=click.Choice(["1", "2", "3", "4", "5"]), default="1")

    framework_map = {
        "1": ["gdpr", "nis2", "owasp_top10"],
        "2": ["gdpr"],
        "3": ["nis2"],
        "4": ["owasp_top10"],
        "5": ["gdpr", "nis2"],
    }
    frameworks = framework_map[framework_choice]

    # Fråga 4: Allvarlighetsgrad
    console.print("\n[bold]4. Vilken lägsta allvarlighetsgrad vill du se?[/bold]")
    console.print("   [1] Alla fynd (info och uppåt)")
    console.print("   [2] Låg och uppåt")
    console.print("   [3] Medium och uppåt")
    console.print("   [4] Endast hög och kritisk")
    severity_choice = click.prompt("   Välj", type=click.Choice(["1", "2", "3", "4"]), default="2")

    severity_map = {
        "1": "info",
        "2": "low",
        "3": "medium",
        "4": "high",
    }
    severity = severity_map[severity_choice]

    # Fråga 5: Rapportformat
    console.print("\n[bold]5. Vilket rapportformat vill du ha?[/bold]")
    console.print("   [1] Endast terminal (ingen fil)")
    console.print("   [2] HTML (visuell rapport)")
    console.print("   [3] JSON (maskinläsbart)")
    console.print("   [4] Markdown (dokumentation)")
    format_choice = click.prompt("   Välj", type=click.Choice(["1", "2", "3", "4"]), default="2")

    format_map = {
        "1": None,
        "2": "html",
        "3": "json",
        "4": "markdown",
    }
    output_format = format_map[format_choice]

    if output_format and not output:
        default_name = f"security-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{output_format}"
        output = click.prompt("\n   Filnamn för rapporten", default=default_name)

    # Sammanfattning
    console.print("\n" + "=" * 50)
    console.print("[bold green]Konfiguration:[/bold green]")
    console.print(f"  Mål: {repo_path or ''} {web_url or ''}")
    console.print(f"  Skanningstyper: {', '.join(scan_types)}")
    console.print(f"  Ramverk: {', '.join(frameworks)}")
    console.print(f"  Allvarlighetsgrad: {severity}+")
    console.print(f"  Rapport: {output or 'Endast terminal'}")
    console.print("=" * 50 + "\n")

    if not click.confirm("Starta skanningen?", default=True):
        console.print("[yellow]Avbrutet.[/yellow]")
        return

    # Kör skanningen
    config = ScanConfig(
        compliance_frameworks=frameworks,
        severity_threshold=Severity(severity),
        scan_types=scan_types,
        verbose=False,
    )
    orchestrator = SecurityOrchestrator(config)

    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Utför säkerhetsgranskning...", total=None)

        if scan_choice == "1":
            asyncio.run(orchestrator.scan_repository(repo_path))
        elif scan_choice == "2":
            asyncio.run(orchestrator.scan_web_application(web_url))
        else:
            asyncio.run(orchestrator.scan_all(repo_path=repo_path, web_url=web_url))

        progress.update(task, completed=True)

    _display_results(orchestrator, output, output_format or "json")


@main.command()
def frameworks():
    """Visa information om stödda compliance-ramverk."""
    print_banner()

    table = Table(title="Stödda Compliance-ramverk", box=box.ROUNDED)
    table.add_column("Ramverk", style="cyan", no_wrap=True)
    table.add_column("Version", style="green")
    table.add_column("Beskrivning", style="white")

    frameworks_info = [
        ("GDPR", "2016/679", "EU:s dataskyddsförordning"),
        ("NIS2", "2022/2555", "EU:s direktiv för nätverks- och informationssäkerhet"),
        ("OWASP Top 10", "2021", "De 10 vanligaste webbapplikationssårbarheterna"),
        ("ISO 27001", "2022", "Internationell standard för informationssäkerhet"),
        ("MSB Riktlinjer", "2024", "Myndigheten för samhällsskydd och beredskaps riktlinjer"),
        ("EU CRA", "2024", "EU Cyber Resilience Act"),
    ]

    for name, version, desc in frameworks_info:
        table.add_row(name, version, desc)

    console.print(table)


def _display_results(
    orchestrator: SecurityOrchestrator,
    output: Optional[str],
    output_format: str,
):
    """Visa resultat i terminalen och spara rapport."""
    summary = orchestrator.get_summary()

    # Visa sammanfattning
    console.print()
    console.print(Panel.fit(
        f"[bold]Skanning slutförd[/bold]\n\n"
        f"Totalt antal fynd: [bold]{summary['total_findings']}[/bold]",
        title="Resultat",
        border_style="green" if summary['total_findings'] == 0 else "yellow",
    ))

    # Visa allvarlighetstabell
    severity_table = Table(title="Fynd per allvarlighetsgrad", box=box.ROUNDED)
    severity_table.add_column("Nivå", style="bold")
    severity_table.add_column("Antal", justify="right")

    severity_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for level, count in summary["by_severity"].items():
        color = severity_colors.get(level, "white")
        severity_table.add_row(
            f"[{color}]{level.upper()}[/{color}]",
            str(count),
        )

    console.print(severity_table)

    # Visa compliance-status
    if summary["compliance"]:
        compliance_table = Table(title="Compliance-status", box=box.ROUNDED)
        compliance_table.add_column("Ramverk", style="cyan")
        compliance_table.add_column("Godkänd", justify="right", style="green")
        compliance_table.add_column("Ej godkänd", justify="right", style="red")
        compliance_table.add_column("Delvis", justify="right", style="yellow")

        for framework, stats in summary["compliance"].items():
            compliance_table.add_row(
                framework,
                str(stats["compliant"]),
                str(stats["non_compliant"]),
                str(stats["partial"]),
            )

        console.print(compliance_table)

    # Visa top 10 kritiska fynd
    findings = orchestrator.get_all_findings()
    critical_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    if critical_findings:
        console.print()
        console.print("[bold red]Kritiska och höga fynd:[/bold red]")

        for i, finding in enumerate(critical_findings[:10], 1):
            color = "red" if finding.severity == Severity.CRITICAL else "orange1"
            location = f" ({finding.location})" if finding.location else ""
            console.print(f"  [{color}]{i}. {finding.title}{location}[/{color}]")

        if len(critical_findings) > 10:
            console.print(f"  ... och {len(critical_findings) - 10} till")

    # Generera och spara rapport
    if output:
        generator = ReportGenerator(orchestrator.results)
        report_path = Path(output)

        if output_format == "json":
            generator.generate_json(report_path)
        elif output_format == "html":
            generator.generate_html(report_path)
        elif output_format == "markdown":
            generator.generate_markdown(report_path)
        elif output_format == "sarif":
            generator.generate_sarif(report_path)

        console.print(f"\n[green]Rapport sparad till: {output}[/green]")

    # Exit code baserat på kritiska fynd
    if summary["by_severity"]["critical"] > 0:
        sys.exit(2)
    elif summary["by_severity"]["high"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
