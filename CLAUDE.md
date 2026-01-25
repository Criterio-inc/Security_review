# CLAUDE.md - Security Toolkit Guide

## Vad är Security Toolkit?

En säkerhetsgranskningsverktygslåda som skannar din kod efter säkerhetsproblem. Tänk på det som en "säkerhetsvakt" som kollar igenom din kod och hittar problem innan hackare gör det.

---

## Snabbstart (3 steg)

```bash
# 1. Installera
cd Security_review
pip install -e .

# 2. Skanna ett projekt
security-scan repo /sökväg/till/ditt/projekt

# 3. Se rapporten
security-scan repo /sökväg/till/ditt/projekt --output rapport.html --format html
```

---

## Var kan jag köra verktygslådan?

### 1. Lokalt på din dator
```bash
# Skanna en lokal mapp
security-scan repo ~/mina-projekt/min-app

# Skanna flera projekt
security-scan repo ~/mina-projekt/app1
security-scan repo ~/mina-projekt/app2
```

### 2. På en webbsida/webbapplikation
```bash
# Skanna en live webbsida
security-scan web https://min-webbsida.se

# Skanna staging-miljö
security-scan web https://staging.min-webbsida.se
```

### 3. Båda samtidigt (kod + webbsida)
```bash
security-scan full ~/mitt-projekt --url https://min-webbsida.se
```

### 4. I CI/CD (GitHub Actions)
Lägg till i `.github/workflows/security.yml`:
```yaml
name: Säkerhetsskanning
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Installera Security Toolkit
        run: pip install git+https://github.com/Criterio-inc/Security_review.git

      - name: Kör säkerhetsskanning
        run: security-scan repo . --output rapport.sarif --format sarif

      - name: Ladda upp till GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: rapport.sarif
```

### 5. Som Python-bibliotek
```python
import asyncio
from security_toolkit.orchestrator import SecurityOrchestrator

async def skanna_mitt_projekt():
    scanner = SecurityOrchestrator()
    resultat = await scanner.scan_repository("/sökväg/till/projekt")

    for finding in scanner.get_all_findings():
        print(f"⚠️  {finding.severity.value}: {finding.title}")
        print(f"   Plats: {finding.location}")
        print(f"   Åtgärd: {finding.remediation}\n")

asyncio.run(skanna_mitt_projekt())
```

---

## De 5 agenterna - Vad gör de?

| Agent | Vad den gör | Exempel på fynd |
|-------|-------------|-----------------|
| **CodeScanner** | Läser din kod och letar efter säkerhetshål | SQL injection, XSS, hårdkodade lösenord |
| **WebScanner** | Testar din webbsida utifrån | Saknade säkerhetsheaders, SSL-problem |
| **DependencyScanner** | Kollar dina paket/bibliotek | Sårbara versioner av React, Django, etc. |
| **SecretScanner** | Hittar läckta hemligheter | API-nycklar, lösenord i koden |
| **ComplianceChecker** | Kollar mot lagar/regler | GDPR-brott, NIS2-krav |

---

## Vanliga kommandon

### Grundläggande skanning
```bash
# Skanna aktuell mapp
security-scan repo .

# Skanna med detaljerad output
security-scan repo . --verbose

# Visa endast allvarliga problem
security-scan repo . --severity high
```

### Rapporter
```bash
# HTML-rapport (snygg, för människor)
security-scan repo . -o rapport.html -f html

# JSON-rapport (för maskiner/API)
security-scan repo . -o rapport.json -f json

# Markdown (för dokumentation)
security-scan repo . -o rapport.md -f markdown

# SARIF (för GitHub Security)
security-scan repo . -o rapport.sarif -f sarif
```

### Specifika skanningar
```bash
# Endast hemlighetsdetektering
security-scan repo . --scan-type secrets

# Endast beroendesårbarheter
security-scan repo . --scan-type dependencies

# Endast GDPR-compliance
security-scan repo . --framework gdpr
```

### Exkludera mappar
```bash
# Hoppa över test-filer
security-scan repo . --exclude "**/*test*" --exclude "**/node_modules/**"
```

---

## Compliance-ramverk

Verktygslådan stödjer dessa standarder:

| Ramverk | Flagga | Beskrivning |
|---------|--------|-------------|
| GDPR | `--framework gdpr` | EU:s dataskyddslag |
| NIS2 | `--framework nis2` | EU:s cybersäkerhetsdirektiv |
| OWASP | `--framework owasp_top10` | Topp 10 webbsårbarheter |
| ISO 27001 | `--framework iso27001` | Informationssäkerhetsstandard |
| MSB | `--framework msb` | Svenska myndighetskrav |

```bash
# Kör alla compliance-kontroller
security-scan repo . --framework gdpr --framework nis2 --framework owasp_top10
```

---

## Exit-koder (för CI/CD)

| Kod | Betydelse | Åtgärd |
|-----|-----------|--------|
| `0` | Inga allvarliga problem | ✅ Pipeline fortsätter |
| `1` | Höga problem hittades | ⚠️ Granska innan merge |
| `2` | Kritiska problem hittades | 🛑 Stoppa deployment |

---

## Exempel: Skanna detta repo

```bash
# Klona och installera
git clone https://github.com/Criterio-inc/Security_review.git
cd Security_review
pip install -e .

# Skanna sig själv (meta!)
security-scan repo . --output self-scan.html --format html

# Öppna rapporten
open self-scan.html  # macOS
xdg-open self-scan.html  # Linux
```

---

## Projektstruktur

```
Security_review/
├── security_toolkit/
│   ├── agents/              # De 5 säkerhetsagenterna
│   │   ├── code_scanner.py      # SAST - statisk kodanalys
│   │   ├── web_scanner.py       # DAST - webbskanning
│   │   ├── dependency_scanner.py # Beroendesårbarheter
│   │   ├── secret_scanner.py    # Hemlighetsdetektering
│   │   └── compliance_checker.py # Compliance-granskning
│   ├── reports/             # Rapportgenerering
│   ├── cli.py               # Kommandoradsgränssnitt
│   └── orchestrator.py      # Koordinerar alla agenter
├── configs/                 # Konfigurationsfiler
└── CLAUDE.md               # Denna fil
```

---

## Behöver du hjälp?

1. **Visa hjälp**: `security-scan --help`
2. **Visa tillgängliga ramverk**: `security-scan frameworks`
3. **GitHub Issues**: https://github.com/Criterio-inc/Security_review/issues
