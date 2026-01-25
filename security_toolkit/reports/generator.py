"""
Rapportgenerator för olika format.

Stödjer:
- JSON (maskinläsbart)
- HTML (visuell rapport)
- Markdown (dokumentation)
- SARIF (GitHub/IDE-integration)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from security_toolkit.models import ScanResult, Finding, Severity


class ReportGenerator:
    """
    Genererar säkerhetsrapporter i olika format.
    """

    def __init__(self, results: list[ScanResult]):
        """
        Initiera rapportgeneratorn.

        Args:
            results: Lista med skanningsresultat.
        """
        self.results = results
        self.generated_at = datetime.now()

    def generate_json(self, output_path: Path) -> None:
        """Generera JSON-rapport."""
        report = {
            "metadata": {
                "generated_at": self.generated_at.isoformat(),
                "generator": "Security Toolkit v1.0.0",
                "scan_count": len(self.results),
            },
            "summary": self._generate_summary(),
            "scans": [result.to_dict() for result in self.results],
        }

        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    def generate_html(self, output_path: Path) -> None:
        """Generera HTML-rapport."""
        summary = self._generate_summary()
        findings = self._get_all_findings()

        html = f"""<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Säkerhetsrapport - {self.generated_at.strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --success: #16a34a;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f3f4f6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 1rem;
        }}
        header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        header p {{ opacity: 0.9; }}
        .card {{
            background: white;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .card h2 {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            color: #374151;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 0.5rem;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }}
        .stat {{
            text-align: center;
            padding: 1rem;
            border-radius: 0.5rem;
            background: #f9fafb;
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .stat-label {{ color: #6b7280; font-size: 0.875rem; }}
        .stat.critical {{ border-left: 4px solid var(--critical); }}
        .stat.high {{ border-left: 4px solid var(--high); }}
        .stat.medium {{ border-left: 4px solid var(--medium); }}
        .stat.low {{ border-left: 4px solid var(--low); }}
        .finding {{
            border: 1px solid #e5e7eb;
            border-radius: 0.5rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        .finding-title {{ font-weight: 600; }}
        .severity {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity.critical {{ background: #fef2f2; color: var(--critical); }}
        .severity.high {{ background: #fff7ed; color: var(--high); }}
        .severity.medium {{ background: #fefce8; color: var(--medium); }}
        .severity.low {{ background: #eff6ff; color: var(--low); }}
        .severity.info {{ background: #f3f4f6; color: var(--info); }}
        .finding-meta {{
            font-size: 0.875rem;
            color: #6b7280;
            margin-bottom: 0.5rem;
        }}
        .finding-description {{ margin-bottom: 0.75rem; }}
        .finding-remediation {{
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
        }}
        .finding-remediation strong {{ color: var(--success); }}
        .compliance-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .compliance-table th, .compliance-table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        .compliance-table th {{ background: #f9fafb; font-weight: 600; }}
        .status-compliant {{ color: var(--success); }}
        .status-non-compliant {{ color: var(--critical); }}
        .frameworks {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
        .framework-badge {{
            background: #e0e7ff;
            color: #3730a3;
            padding: 0.125rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
        }}
        footer {{
            text-align: center;
            padding: 2rem;
            color: #6b7280;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Säkerhetsrapport</h1>
            <p>Genererad: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="card">
            <h2>Sammanfattning</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{summary['total_findings']}</div>
                    <div class="stat-label">Totalt antal fynd</div>
                </div>
                <div class="stat critical">
                    <div class="stat-value" style="color: var(--critical)">{summary['by_severity']['critical']}</div>
                    <div class="stat-label">Kritiska</div>
                </div>
                <div class="stat high">
                    <div class="stat-value" style="color: var(--high)">{summary['by_severity']['high']}</div>
                    <div class="stat-label">Höga</div>
                </div>
                <div class="stat medium">
                    <div class="stat-value" style="color: var(--medium)">{summary['by_severity']['medium']}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat low">
                    <div class="stat-value" style="color: var(--low)">{summary['by_severity']['low']}</div>
                    <div class="stat-label">Låga</div>
                </div>
            </div>
        </div>

        {self._generate_compliance_html(summary)}

        <div class="card">
            <h2>Säkerhetsfynd ({len(findings)})</h2>
            {self._generate_findings_html(findings)}
        </div>

        <footer>
            <p>Genererad av Security Toolkit v1.0.0</p>
            <p>Kompatibel med GDPR, NIS2, OWASP Top 10, ISO 27001, MSB</p>
        </footer>
    </div>
</body>
</html>"""

        output_path.write_text(html)

    def _generate_compliance_html(self, summary: dict) -> str:
        """Generera HTML för compliance-sektion."""
        if not summary.get("compliance"):
            return ""

        rows = ""
        for framework, stats in summary["compliance"].items():
            total = stats["total"]
            compliant = stats["compliant"]
            rate = (compliant / total * 100) if total > 0 else 0

            status_class = "status-compliant" if rate >= 80 else "status-non-compliant"

            rows += f"""
            <tr>
                <td>{framework}</td>
                <td>{stats['compliant']}</td>
                <td>{stats['non_compliant']}</td>
                <td>{stats['partial']}</td>
                <td class="{status_class}">{rate:.0f}%</td>
            </tr>"""

        return f"""
        <div class="card">
            <h2>Compliance-status</h2>
            <table class="compliance-table">
                <thead>
                    <tr>
                        <th>Ramverk</th>
                        <th>Godkänd</th>
                        <th>Ej godkänd</th>
                        <th>Delvis</th>
                        <th>Efterlevnad</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _generate_findings_html(self, findings: list[Finding]) -> str:
        """Generera HTML för findings."""
        if not findings:
            return "<p>Inga säkerhetsfynd upptäcktes.</p>"

        # Sortera efter allvarlighetsgrad
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

        html = ""
        for finding in sorted_findings:
            location = f"<strong>Plats:</strong> {finding.location}" if finding.location else ""
            url = f"<strong>URL:</strong> {finding.url}" if finding.url else ""
            cwe = f"CWE: {finding.cwe_id}" if finding.cwe_id else ""
            owasp = f"OWASP: {finding.owasp_id}" if finding.owasp_id else ""

            meta_parts = [x for x in [location, url, cwe, owasp] if x]
            meta = " | ".join(meta_parts)

            frameworks_html = ""
            if finding.compliance_frameworks:
                badges = "".join(
                    f'<span class="framework-badge">{fw}</span>'
                    for fw in finding.compliance_frameworks
                )
                frameworks_html = f'<div class="frameworks" style="margin-top: 0.5rem">{badges}</div>'

            remediation_html = ""
            if finding.remediation:
                remediation_html = f"""
                <div class="finding-remediation">
                    <strong>Åtgärd:</strong> {finding.remediation}
                </div>"""

            html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">{finding.title}</span>
                    <span class="severity {finding.severity.value}">{finding.severity.value}</span>
                </div>
                <div class="finding-meta">{meta}</div>
                <div class="finding-description">{finding.description}</div>
                {remediation_html}
                {frameworks_html}
            </div>"""

        return html

    def generate_markdown(self, output_path: Path) -> None:
        """Generera Markdown-rapport."""
        summary = self._generate_summary()
        findings = self._get_all_findings()

        md = f"""# Säkerhetsrapport

**Genererad:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
**Generator:** Security Toolkit v1.0.0

---

## Sammanfattning

| Kategori | Antal |
|----------|-------|
| Totalt antal fynd | {summary['total_findings']} |
| Kritiska | {summary['by_severity']['critical']} |
| Höga | {summary['by_severity']['high']} |
| Medium | {summary['by_severity']['medium']} |
| Låga | {summary['by_severity']['low']} |
| Information | {summary['by_severity']['info']} |

"""

        # Compliance-tabell
        if summary.get("compliance"):
            md += "## Compliance-status\n\n"
            md += "| Ramverk | Godkänd | Ej godkänd | Delvis |\n"
            md += "|---------|---------|------------|--------|\n"

            for framework, stats in summary["compliance"].items():
                md += f"| {framework} | {stats['compliant']} | {stats['non_compliant']} | {stats['partial']} |\n"

            md += "\n"

        # Findings
        md += "## Säkerhetsfynd\n\n"

        if not findings:
            md += "Inga säkerhetsfynd upptäcktes.\n"
        else:
            # Gruppera efter allvarlighetsgrad
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                severity_findings = [f for f in findings if f.severity == severity]
                if severity_findings:
                    md += f"### {severity.value.upper()} ({len(severity_findings)})\n\n"

                    for finding in severity_findings:
                        md += f"#### {finding.title}\n\n"
                        md += f"{finding.description}\n\n"

                        if finding.location:
                            md += f"**Plats:** `{finding.location}`\n\n"
                        if finding.url:
                            md += f"**URL:** {finding.url}\n\n"
                        if finding.cwe_id:
                            md += f"**CWE:** {finding.cwe_id}\n\n"
                        if finding.owasp_id:
                            md += f"**OWASP:** {finding.owasp_id}\n\n"
                        if finding.remediation:
                            md += f"**Åtgärd:**\n{finding.remediation}\n\n"
                        if finding.compliance_frameworks:
                            md += f"**Ramverk:** {', '.join(finding.compliance_frameworks)}\n\n"

                        md += "---\n\n"

        md += f"""
## Om denna rapport

Denna rapport genererades av Security Toolkit, en omfattande säkerhetsgranskningsverktygslåda
som är kompatibel med följande ramverk och standarder:

- **GDPR** - EU:s dataskyddsförordning
- **NIS2** - EU:s direktiv för nätverks- och informationssäkerhet
- **OWASP Top 10** - De 10 vanligaste webbapplikationssårbarheterna
- **ISO 27001** - Internationell standard för informationssäkerhet
- **MSB** - Myndigheten för samhällsskydd och beredskaps riktlinjer
"""

        output_path.write_text(md)

    def generate_sarif(self, output_path: Path) -> None:
        """Generera SARIF-rapport för GitHub/IDE-integration."""
        findings = self._get_all_findings()

        # Skapa regler baserat på unika fynd
        rules = {}
        results = []

        for finding in findings:
            rule_id = finding.cwe_id or f"SECURITY-{finding.category.value}"

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": finding.remediation or "Se dokumentation för åtgärder.",
                        "markdown": finding.remediation or "Se dokumentation för åtgärder.",
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.severity),
                    },
                    "properties": {
                        "security-severity": str(finding.severity.score),
                    },
                }

            result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules.keys()).index(rule_id),
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
            }

            if finding.location:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.file_path},
                        "region": {
                            "startLine": finding.location.line_start,
                            "endLine": finding.location.line_end or finding.location.line_start,
                        },
                    },
                }]

            if finding.url:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.url},
                    },
                }]

            results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Security Toolkit",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/security-toolkit",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            }],
        }

        output_path.write_text(json.dumps(sarif, indent=2))

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """Konvertera Severity till SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")

    def _generate_summary(self) -> dict:
        """Generera sammanfattning av alla resultat."""
        total = 0
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        compliance: dict[str, dict] = {}

        for result in self.results:
            total += result.total_findings
            critical += result.critical_count
            high += result.high_count
            medium += result.medium_count
            low += result.low_count
            info += result.info_count

            for framework, stats in result.compliance_summary.items():
                if framework not in compliance:
                    compliance[framework] = {
                        "total": 0,
                        "compliant": 0,
                        "non_compliant": 0,
                        "partial": 0,
                    }
                for key in ["total", "compliant", "non_compliant", "partial"]:
                    compliance[framework][key] += stats.get(key, 0)

        return {
            "total_findings": total,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
            },
            "compliance": compliance,
        }

    def _get_all_findings(self) -> list[Finding]:
        """Hämta alla fynd från alla resultat."""
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings
