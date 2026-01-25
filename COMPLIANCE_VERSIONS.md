# Compliance-versioner

Detta dokument spårar vilka versioner av ramverk och regelverk som Security Toolkit kontrollerar mot.

**Senast granskad:** 2026-01-25

---

## Aktiva ramverk

| Ramverk | Version | Officiell källa | Senast verifierad |
|---------|---------|-----------------|-------------------|
| **GDPR** | 2016/679 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj) | 2026-01 |
| **NIS2 / Cybersäkerhetslagen** | 2022/2555 / SFS 2025:1506 | [EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555) / [Riksdagen](https://www.riksdagen.se/sv/dokument-och-lagar/) | 2026-01 |
| **OWASP Top 10** | 2025 | [OWASP](https://owasp.org/Top10/2025/) | 2026-01 |
| **ISO 27001** | 2022 | [ISO](https://www.iso.org/standard/27001) | 2026-01 |
| **MCF Riktlinjer** | 2026 | [MCF](https://www.mcf.se/) | 2026-01 |
| **EU Cyber Resilience Act** | 2024/2847 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847) | 2026-01 |

---

## Viktiga ändringar 2025-2026

### MSB → MCF (1 januari 2026)
Myndigheten för samhällsskydd och beredskap (MSB) bytte namn till **Myndigheten för civilt försvar (MCF)**. MCF är nu den ledande myndigheten för civilt försvar i Sverige och nationell koordinator för NIS2.

### Cybersäkerhetslagen (15 januari 2026)
Sveriges implementering av NIS2-direktivet trädde i kraft genom:
- **Cybersäkerhetslagen (SFS 2025:1506)**
- **Cybersäkerhetsförordningen**

Ersätter den tidigare NIS-lagen (2018:1174).

### OWASP Top 10: 2025
Ny version släppt med uppdaterade kategorier:
- A01:2025 - Broken Access Control
- A02:2025 - Security Misconfiguration
- A03:2025 - Software Supply Chain Failures (ny/utökad)
- A04:2025 - Cryptographic Failures
- A05:2025 - Injection
- A06:2025 - Insecure Design
- A07:2025 - Authentication Failures
- A08:2025 - Software or Data Integrity Failures
- A09:2025 - Logging & Alerting Failures
- A10:2025 - Mishandling of Exceptional Conditions (ny)

### EU Cyber Resilience Act - Tidslinje
| Datum | Händelse |
|-------|----------|
| 10 dec 2024 | CRA trädde i kraft |
| 11 jun 2026 | Krav på Conformity Assessment Bodies |
| 11 sep 2026 | **Obligatorisk sårbarhetsrapportering börjar** |
| 11 dec 2027 | Full efterlevnad krävs |

---

## Versionshistorik

### 2026-01-25
- Uppdaterat OWASP Top 10 från 2021 till 2025
- Lagt till svenska Cybersäkerhetslagen (SFS 2025:1506)
- Uppdaterat MSB till MCF (namnbyte 1 jan 2026)
- Lagt till EU CRA-tidslinje med kommande deadlines

### 2025-01-25
- Initial version

---

## Kommande uppdateringar att bevaka

| Ramverk | Datum | Notering |
|---------|-------|----------|
| **EU CRA rapportering** | 11 sep 2026 | Obligatorisk sårbarhetsrapportering |
| **EU CRA full efterlevnad** | 11 dec 2027 | Alla krav gäller |
| **ISO 27001** | ~2028 | Normalt 5-6 års uppdateringscykel |
| **OWASP Top 10** | ~2029 | Normalt 3-4 års cykel |

---

## Uppdateringsprocess

1. **Årlig granskning** - Varje januari skapas automatiskt en GitHub Issue för att verifiera att alla ramverk är aktuella
2. **Vid regeländringar** - Uppdatera tabellen ovan och motsvarande kontroller i `security_toolkit/agents/compliance_checker.py`
3. **Pull requests** - Community-bidrag för uppdateringar välkomnas

---

## Hur du bidrar med uppdateringar

Om ett ramverk uppdateras:

1. Uppdatera versionen i tabellen ovan
2. Uppdatera kontrollerna i `security_toolkit/agents/compliance_checker.py`
3. Lägg till i versionshistoriken
4. Skicka en Pull Request med referens till officiell källa

---

## Referenser

- [OWASP Top 10: 2025](https://owasp.org/Top10/2025/)
- [NIS2 implementation Sweden](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive-sweden)
- [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [MCF - Myndigheten för civilt försvar](https://www.mcf.se/)
- [Regeringen - Cybersäkerhet](https://www.regeringen.se/regeringens-politik/cybersakerhet/)
