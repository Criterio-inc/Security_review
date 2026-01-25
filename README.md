# Security Toolkit - Säkerhetsgranskningsverktygslåda

En omfattande säkerhetsgranskningsverktygslåda för kod, repositories och webbapplikationer. Fullt kompatibel med EU- och svenska säkerhetsstandarder.

## Funktioner

### Agenter och Skanningstyper

| Agent | Typ | Beskrivning |
|-------|-----|-------------|
| **CodeScannerAgent** | SAST | Statisk kodanalys för säkerhetsproblem |
| **WebScannerAgent** | DAST | Dynamisk webbapplikationstestning |
| **DependencyScannerAgent** | SCA | Sårbarhetsdetektering i beroenden |
| **SecretScannerAgent** | Secret | Detektering av exponerade hemligheter |
| **ComplianceCheckerAgent** | Compliance | Granskning mot säkerhetsstandarder |

### Stödda Compliance-ramverk

- **GDPR** (2016/679) - EU:s dataskyddsförordning
- **NIS2** (2022/2555) - EU:s direktiv för nätverks- och informationssäkerhet
- **OWASP Top 10** (2021) - De 10 vanligaste webbapplikationssårbarheterna
- **ISO 27001** (2022) - Internationell standard för informationssäkerhet
- **MSB Riktlinjer** - Myndigheten för samhällsskydd och beredskap
- **EU Cyber Resilience Act** (2024) - EU:s cyberresilienslag

## Installation

```bash
# Klona repositoryt
git clone https://github.com/Criterio-inc/Security_review.git
cd security-toolkit

# Installera med pip
pip install -e .

# Eller med utvecklingsberoenden
pip install -e ".[dev]"
```

## Användning

### Interaktivt läge (rekommenderas för nybörjare)

```bash
security-scan interactive
```

Detta startar en guidad genomgång där du svarar på frågor om:
1. Vad ska skannas (kod, webb, eller båda)
2. Vilka skanningstyper
3. Vilka compliance-ramverk
4. Allvarlighetsgrad
5. Rapportformat

---

### Använda med Claude Code Desktop

**Metod 1: Be Claude köra skanningen direkt**
```
"Kör en säkerhetsskanning på detta repository"
"Skanna min kod efter säkerhetsproblem"
"Gör en GDPR-compliance-granskning av projektet"
```

**Metod 2: Installera och kör själv**
```
"Installera security-toolkit och kör security-scan repo ."
```

**Metod 3: Interaktiv skanning via Claude**
```
"Kör security-scan interactive och hjälp mig välja rätt inställningar"
```

**Tips för Claude Code:**
- Claude kan tolka resultaten och förklara vad de betyder
- Be Claude föreslå åtgärder för varje fynd
- Claude kan automatiskt fixa enkla säkerhetsproblem

---

### CLI-kommandon

#### Skanna ett repository
```bash
# Grundläggande skanning
security-scan repo /path/to/your/project

# Med rapport
security-scan repo /path/to/project --output report.json --format json

# Endast kritiska/höga fynd
security-scan repo /path/to/project --severity high

# Specifika skanningstyper
security-scan repo /path/to/project --scan-type sast --scan-type secrets

# Med compliance-ramverk
security-scan repo /path/to/project --framework gdpr --framework nis2
```

#### Skanna en webbapplikation
```bash
# Grundläggande webbskanning
security-scan web https://example.com

# Med HTML-rapport
security-scan web https://example.com --output report.html --format html

# Detaljerad output
security-scan web https://example.com --verbose
```

#### Fullständig skanning (repo + webb)
```bash
security-scan full /path/to/project --url https://example.com --output full-report.html --format html
```

#### Visa stödda ramverk
```bash
security-scan frameworks
```

### Programmatisk användning (Python)

```python
import asyncio
from security_toolkit.orchestrator import SecurityOrchestrator
from security_toolkit.models import ScanConfig, Severity

# Skapa konfiguration
config = ScanConfig(
    compliance_frameworks=["gdpr", "nis2", "owasp_top10"],
    severity_threshold=Severity.MEDIUM,
    verbose=True,
)

# Initiera orkestreraren
orchestrator = SecurityOrchestrator(config)

# Skanna repository
async def scan_repo():
    results = await orchestrator.scan_repository("/path/to/project")

    # Visa sammanfattning
    summary = orchestrator.get_summary()
    print(f"Totalt fynd: {summary['total_findings']}")
    print(f"Kritiska: {summary['by_severity']['critical']}")

    # Hämta alla fynd
    for finding in orchestrator.get_all_findings():
        print(f"{finding.severity.value}: {finding.title}")

    return results

asyncio.run(scan_repo())
```

### Generera rapporter

```python
from security_toolkit.reports import ReportGenerator
from pathlib import Path

# Efter skanning
generator = ReportGenerator(orchestrator.results)

# JSON (maskinläsbart)
generator.generate_json(Path("report.json"))

# HTML (visuell)
generator.generate_html(Path("report.html"))

# Markdown (dokumentation)
generator.generate_markdown(Path("report.md"))

# SARIF (GitHub/IDE-integration)
generator.generate_sarif(Path("report.sarif"))
```

## Skanningstyper i detalj

### SAST (Static Application Security Testing)

Detekterar säkerhetsproblem i källkod:

- SQL Injection (CWE-89)
- Cross-Site Scripting/XSS (CWE-79)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Osäker kryptografi (CWE-327)
- Osäker deserialisering (CWE-502)
- Server-Side Request Forgery (CWE-918)
- Hårdkodade credentials (CWE-798)
- Bristande loggning (CWE-778)

### DAST (Dynamic Application Security Testing)

Testar webbapplikationer i runtime:

- SSL/TLS-konfiguration
- Saknade säkerhetsheaders (HSTS, CSP, X-Frame-Options, etc.)
- Cookie-säkerhet (Secure, HttpOnly, SameSite)
- CORS-felkonfiguration
- Directory listing
- Information disclosure
- Exponerade känsliga filer (.git, .env, etc.)

### Secret Detection

Detekterar exponerade hemligheter:

- AWS Access Keys / Secret Keys
- Google Cloud API Keys / Service Accounts
- Azure Connection Strings
- GitHub/GitLab Tokens
- Slack/Discord Tokens
- Stripe API Keys
- JWT Tokens
- SSH/SSL Private Keys
- Database Connection Strings
- Generiska API-nycklar och lösenord

### Dependency Scanning (SCA)

Kontrollerar beroenden via OSV-databasen:

- Python (requirements.txt, Pipfile, pyproject.toml)
- JavaScript (package.json, yarn.lock)
- Java (pom.xml, build.gradle)
- Ruby (Gemfile)
- PHP (composer.json)
- Go (go.mod)
- Rust (Cargo.toml)
- .NET (*.csproj)

### Compliance Checking

Granskar kod mot säkerhetsstandarder:

**GDPR:**
- Loggning av personuppgifter
- Datalagringspolicy
- Samtyckehantering
- Kryptering av lagrad data
- Dataportabilitet

**NIS2:**
- Incidenthantering
- Backup-mekanismer
- Åtkomstkontroll
- Multifaktorautentisering
- Automatisk sårbarhetsscanning

**MSB:**
- Säkerhetsdokumentation
- Nätverkssegmentering

## Rapportformat

| Format | Användning |
|--------|------------|
| JSON | Maskinläsbart, CI/CD-integration |
| HTML | Visuella rapporter för stakeholders |
| Markdown | Dokumentation, GitHub Issues |
| SARIF | GitHub Code Scanning, IDE-integration |

## Exit-koder

| Kod | Betydelse |
|-----|-----------|
| 0 | Inga kritiska eller höga fynd |
| 1 | Höga fynd upptäcktes |
| 2 | Kritiska fynd upptäcktes |

## CI/CD-integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Security Toolkit
        run: pip install security-toolkit

      - name: Run Security Scan
        run: |
          security-scan repo . \
            --output security-report.sarif \
            --format sarif \
            --severity medium

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-report.sarif
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  script:
    - pip install security-toolkit
    - security-scan repo . --output report.json --format json
  artifacts:
    reports:
      sast: report.json
```

## Konfiguration

### Ignore-fil (.security-toolkit-ignore)

Skapa `.security-toolkit-ignore` i projektets rot för att exkludera filer från skanning:

```gitignore
# Testfiler
**/*test*.py
**/*.spec.js
**/tests/**

# Byggda filer
**/dist/**
**/node_modules/**

# Dokumentation
**/*.md

# False positives (t.ex. säkerhetsregler)
**/security_toolkit/agents/secret_scanner.py
```

### Konfigurationsfil (.security-toolkit.yaml)

```yaml
exclude_patterns:
  - "node_modules/**"
  - "**/*.test.js"
  - "dist/**"

compliance_frameworks:
  - gdpr
  - nis2
  - owasp_top10

severity_threshold: low

scan_types:
  - all

verbose: false
```

## Licens

MIT License

## Bidra

Bidrag välkomnas! Se [CONTRIBUTING.md](CONTRIBUTING.md) för riktlinjer.

## Support

- Skapa en [GitHub Issue](https://github.com/Criterio-inc/Security_review/issues) för buggar
- Diskutera nya funktioner i [Discussions](https://github.com/Criterio-inc/Security_review/discussions)
