# Security_review

## Projektöversikt

- **Beskrivning:** Security Toolkit — en Python-baserad säkerhetsgranskningsverktygslåda för kod, repositories och webbapplikationer. Utför SAST (statisk kodanalys), DAST (dynamisk webbapplikationstestning), hemlighetsdetektering, beroendeanalys och compliance-granskning. Kompatibel med GDPR, NIS2, OWASP Top 10, ISO 27001, MCF och EU CRA.
- **Produktions-URL:** Ej tillämpligt (open-source CLI-verktyg, ingen hosted URL)
- **GitHub:** https://github.com/criterio-inc/Security_review
- **Status:** Aktiv

## Techstack

- **Frontend:** CLI-baserat med Rich (terminal UI)
- **Backend/API:** Python 3.10+ (async/await med asyncio)
- **Databas:** Ingen — verktyget är stateless
- **Autentisering:** Ingen (standalone tool)
- **Hosting/Deploy:** Python-paket (installeras via pip)
- **Byggverktyg:** setuptools, pytest, black, ruff, mypy

## Tjänster och integrationer

| Tjänst | Användning | Env-variabelnamn |
|--------|-----------|-----------------|
| OSV (Open Source Vulnerabilities) | Beroendeanalys via API | — |
| Semgrep | SAST-analys (optional integration) | — |
| Bandit | Python-säkerhetslinting | — |
| Safety | Dependency vulnerability scanning | — |
| httpx | HTTP-förfrågningar för DAST | — |

## Miljö och deploy

- **Deploy-metod:** `pip install -e .` eller `pip install -e "[dev]"`
- **Huvud-branch:** main
- **Miljövariabler:** Inga — konfigureras via `.security-toolkit.yaml` och CLI-argument

## Arkitektur — Tvåfas-orkestrering med 5 agenter

Orchestrator koordinerar agenterna i **två faser** via asyncio:

```
┌─ Fas 1 (parallellt) ──────────────────────────────┐
│  CodeScannerAgent   SecretScannerAgent             │
│  DependencyScannerAgent                            │
└──────────────────────┬─────────────────────────────┘
                       │ findings
                       ▼
┌─ Fas 2 ──────────────────────────────────────────-─┐
│  ComplianceCheckerAgent                             │
│  (egna kontroller + berikas med findings från fas 1 │
│   via enrich_with_findings())                       │
└─────────────────────────────────────────────────────┘

WebScannerAgent körs separat vid DAST-skanning.
```

### Agenter

| Agent | Funktion |
|-------|---------|
| `CodeScannerAgent` | SAST — 17 regelkategorier: SQL injection, XSS, command injection, path traversal, osäker kryptografi, osäker deserialisering, SSRF, hårdkodade credentials, bristande loggning, **saknad rate limiting**, **saknat CSRF-skydd**, **webhook utan HMAC-verifiering**, **otillräcklig input-validering** m.fl. Stöder Python, JS/TS, Java, PHP, Ruby, Go, C#, C++ m.fl. |
| `SecretScannerAgent` | 40+ mönster: AWS-keys, GCP-tokens, GitHub/GitLab-tokens, Stripe, Slack, Discord, JWT, SSH/SSL-nycklar, databasanslutningar m.fl. |
| `DependencyScannerAgent` | Skannar via OSV-databasen: Python, JS, Java, Ruby, PHP, Go, Rust, .NET |
| `WebScannerAgent` | DAST — 7 security headers, SSL/TLS, cookies, CORS, directory listing, känsliga filer, **CSRF-formulärkontroll**, **rate limiting-headers** |
| `ComplianceCheckerAgent` | GDPR (5 kontroller), NIS2/CSL (15 kontroller: CSL-7 till CSL-15), MCF (2 kontroller). **Berikas med findings från fas 1** — NIS2-rapporten inkluderar automatiskt SAST/DAST-fynd |

### Tvåfas-berikning (NIS2)

Compliance-agenten har egna mönsterkontroller (letar efter att skydd *finns* i koden) men berikas dessutom med specifika findings från SAST-agenten (som hittar ställen där skydd *saknas*). Mappning sker via `_FINDING_TO_NIS2_MAP`:

| SAST-regel | NIS2-krav |
|---|---|
| `missing_rate_limiting` | CSL-12: Skydd mot överbelastning |
| `missing_csrf_protection` | CSL-13: Skydd mot CSRF-attacker |
| `missing_webhook_verification` | CSL-14: Verifiering av extern input |
| `missing_input_sanitization` | CSL-15: Input-validering |

Rapporter genereras i JSON, HTML, Markdown och SARIF.

## CLI-kommandon

```bash
security-scan repo /path/to/project          # Skanna repository
security-scan web https://example.com        # Skanna webbapp
security-scan full /path/to/project --url …  # Fullständig skanning
security-scan interactive                    # Guidad skanning
security-scan frameworks                     # Visa compliance-ramverk
```

**Exit-koder:** 0 (OK), 1 (höga fynd), 2 (kritiska fynd) — integrerat med CI/CD

## Compliance-ramverk

| Ramverk | Version | NIS2-krav |
|---------|---------|-----------|
| GDPR | 2016/679 | 5 kontroller (Art. 5, 7, 20, 32) |
| NIS2 / Cybersäkerhetslagen | 2022/2555 + SFS 2025:1506 | 15 kontroller (CSL-7 till CSL-15) |
| OWASP Top 10 | 2025 | Mappat via CWE/OWASP-ID per finding |
| ISO 27001 | 2022 | — |
| MCF Riktlinjer | 2026 | 2 kontroller |
| EU Cyber Resilience Act | 2024/2847 | — |

### NIS2-kontroller i detalj

| Krav-ID | Namn | Källa |
|---------|------|-------|
| CSL-7 | Incidenthantering | Compliance-agent (mönstermatchning) |
| CSL-8 | Driftskontinuitet (backup) | Compliance-agent |
| CSL-9 | Åtkomstkontroll | Compliance-agent |
| CSL-10 | Stark autentisering (MFA) | Compliance-agent |
| CSL-11 | Säkerhetstestning | Compliance-agent |
| CSL-12 | Skydd mot överbelastning (rate limiting) | Compliance-agent + SAST-berikning |
| CSL-13 | Skydd mot CSRF-attacker | Compliance-agent + SAST-berikning |
| CSL-14 | Verifiering av extern input (webhook HMAC) | Compliance-agent + SAST-berikning |
| CSL-15 | Input-validering | Compliance-agent + SAST-berikning |

## Kända begränsningar och teknisk skuld

- SAST är regex-baserad (ingen AST-parsing/dataflödesanalys) — false positives möjliga
- DAST är passiv (kontrollerar headers/formulär, ingen aktiv fuzzing/injection-testning)
- Beroendeanalys kräver internet (OSV-API)
- DAST kräver live URL (kan ej skanna localhost utan exponering)
- Ingen databas för historiska skanningsresultat
- Ingen CI/CD webhook-integration (enbart CLI + SARIF-export)
- Compliance-kontroller är mönsterbaserade — verifierar att mönster finns/saknas, inte att implementation är korrekt
- Tvåfas-berikning fungerar enbart för NIS2 (GDPR/MCF berikas ej ännu med externa findings)

## Anteckningar

- **Senast uppdaterad:** 2026-03-12
- Licens: MIT
- Språk: 100% Python
- Code quality: black, ruff, mypy
- Stöder `.security-toolkit-ignore` för undantag
- Konfiguration via `.security-toolkit.yaml`
