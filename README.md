# Security Toolkit - Säkerhetsgranskningsverktygslåda

En omfattande säkerhetsgranskningsverktygslåda för kod, repositories och webbapplikationer. Fullt kompatibel med EU- och svenska säkerhetsstandarder.

---

## Hur fungerar det? Två sätt att använda

Security Toolkit kan användas på **två sätt** som kompletterar varandra:

### 1. Fristående CLI-verktyg (utan agent)

Du kör `security-scan` direkt i terminalen mot din kodbas eller webbapplikation. Perfekt för utvecklare som vill integrera i sitt arbetsflöde eller CI/CD-pipeline.

```
Du (utvecklare)
  │
  ▼
security-scan repo ./mitt-projekt
  │
  ├── SAST (kodanalys)
  ├── Secrets (hemligheter)
  ├── Dependencies (sårbara beroenden)
  └── Compliance (NIS2, GDPR, MCF...)
  │
  ▼
Rapport (JSON/HTML/Markdown/SARIF)
```

### 2. Med Claude Code Desktop (agent-assisterad)

Du öppnar ditt projekt i Claude Code och ber Claude skanna det. Claude kör verktyget, tolkar resultaten, förklarar dem på svenska och kan till och med fixa problemen direkt.

```
Du (i Claude Code Desktop)
  │
  "Skanna detta repo med security-scan"
  │
  ▼
Claude Code (agent)
  │
  ├── Kör security-scan automatiskt
  ├── Tolkar resultaten
  ├── Förklarar vad det betyder
  └── Kan fixa problemen direkt i koden
  │
  ▼
Fixad och säkrare kod
```

### Vad är skillnaden?

| | Fristående CLI | Med Claude Code |
|---|---|---|
| **Vem kör?** | Du, i terminalen | Claude kör åt dig |
| **Resultat** | Rapport (fil) | Förklaring + automatiska fixar |
| **Bäst för** | CI/CD, rutinskanningar | Förstå problem, snabba fixar |
| **Kräver** | Python + pip install | Claude Code Desktop |

**Båda sätten kör exakt samma skanningsmotor** - det är bara gränssnittet som skiljer.

---

## Snabbstart

### Alt A: Fristående (terminal)

```bash
# Installera
git clone https://github.com/Criterio-inc/Security_review.git
cd Security_review && pip install -e .

# Skanna
security-scan repo /path/to/your/project
security-scan web https://your-app.com
security-scan interactive  # guidad genomgång
```

### Alt B: Med Claude Code Desktop

**Steg 1:** Installera (en gång)
```bash
git clone https://github.com/Criterio-inc/Security_review.git
```
Öppna Claude Code Desktop:
```
Installera Security Toolkit från ~/Security_review
```

**Steg 2:** Skanna (när som helst)

Öppna valfritt projekt i Claude Code Desktop och skriv:
```
"Skanna detta repo med security-scan"
"Gör en GDPR-granskning"
"Hitta läckta API-nycklar i koden"
"Kör security-scan interactive"
```

---

## Arkitektur: Tvåfas-orkestrering

Verktyget kör agenterna i **två faser** för att compliance-rapporteringen ska vara så komplett som möjligt:

```
┌─ Fas 1 (parallellt) ──────────────────────────────────┐
│                                                        │
│  SAST             Secrets          Dependencies        │
│  (kodanalys)      (hemligheter)    (beroenden)         │
│                                                        │
│  Hittar: SQL injection, XSS, saknad rate limiting,     │
│  CSRF-problem, webhook utan HMAC, input-validering...  │
│                                                        │
└───────────────────────┬────────────────────────────────┘
                        │ findings matas vidare
                        ▼
┌─ Fas 2 ───────────────────────────────────────────────┐
│                                                        │
│  Compliance (NIS2, GDPR, MCF)                         │
│                                                        │
│  Egna mönsterkontroller + berikas med findings         │
│  från fas 1 via enrich_with_findings()                 │
│                                                        │
│  Resultat: Komplett compliance-rapport som inkluderar   │
│  både compliance-agentens egna kontroller OCH           │
│  säkerhetsproblem från SAST/DAST                       │
│                                                        │
└────────────────────────────────────────────────────────┘
```

Detta innebär att NIS2-compliance-rapporten automatiskt inkluderar fynd som saknad rate limiting eller CSRF-problem som hittats av kodscannern, istället för att bara kontrollera compliance-mönster isolerat.

---

## Funktioner

### Agenter och skanningstyper

| Agent | Typ | Beskrivning |
|-------|-----|-------------|
| **CodeScannerAgent** | SAST | Statisk kodanalys - hittar sårbarheter i källkod |
| **WebScannerAgent** | DAST | Dynamisk testning - testar en körande webbapp |
| **DependencyScannerAgent** | SCA | Kontrollerar beroenden mot kända sårbarheter |
| **SecretScannerAgent** | Secret | Hittar API-nycklar, lösenord och hemligheter i kod |
| **ComplianceCheckerAgent** | Compliance | Granskar mot NIS2, GDPR, MCF m.fl. + berikas med findings |

### Stödda compliance-ramverk

- **GDPR** (2016/679) - EU:s dataskyddsförordning
- **NIS2 / Cybersäkerhetslagen** (SFS 2025:1506) - Sveriges implementering av NIS2
- **OWASP Top 10** (2025) - De 10 vanligaste webbapplikationssårbarheterna
- **ISO 27001** (2022) - Internationell standard för informationssäkerhet
- **MCF Riktlinjer** - Myndigheten för civilt försvar (f.d. MSB)
- **EU Cyber Resilience Act** (2024/2847) - EU:s cyberresilienslag

Se [COMPLIANCE_VERSIONS.md](COMPLIANCE_VERSIONS.md) för detaljerad versionsinformation.

## Installation

```bash
# Klona repositoryt
git clone https://github.com/Criterio-inc/Security_review.git
cd Security_review

# Installera med pip
pip install -e .

# Eller med utvecklingsberoenden
pip install -e ".[dev]"
```

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
- Saknad rate limiting (CWE-770) - auth-endpoints utan begränsning
- Saknat CSRF-skydd (CWE-352) - POST-endpoints utan CSRF-tokens
- Webhook utan HMAC-verifiering (CWE-345) - webhook-endpoints utan signaturkontroll
- Otillräcklig input-validering (CWE-20) - direkt användning av request-data utan sanitering

### DAST (Dynamic Application Security Testing)

Testar webbapplikationer i runtime:

- SSL/TLS-konfiguration
- Saknade säkerhetsheaders (HSTS, CSP, X-Frame-Options, etc.)
- Cookie-säkerhet (Secure, HttpOnly, SameSite)
- CORS-felkonfiguration
- Directory listing
- Information disclosure
- Exponerade känsliga filer (.git, .env, etc.)
- CSRF-skydd - kontrollerar formulär efter CSRF-tokens och SameSite-cookies
- Rate limiting - kontrollerar rate limit-headers och testar auth-endpoints

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

**NIS2 / Cybersäkerhetslagen:**
- Incidenthantering (CSL-7)
- Backup-mekanismer (CSL-8)
- Åtkomstkontroll (CSL-9)
- Multifaktorautentisering (CSL-10)
- Automatisk sårbarhetsscanning (CSL-11)
- Rate limiting / skydd mot överbelastning (CSL-12)
- CSRF-skydd (CSL-13)
- Webhook-signaturverifiering / HMAC (CSL-14)
- Input-validering (CSL-15)

NIS2-compliance berikas automatiskt med findings från SAST/DAST (se Arkitektur ovan).

**MCF (f.d. MSB):**
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
