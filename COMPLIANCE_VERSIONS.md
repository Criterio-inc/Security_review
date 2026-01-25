# Compliance-versioner

Detta dokument spårar vilka versioner av ramverk och regelverk som Security Toolkit kontrollerar mot.

**Senast granskad:** 2025-01-25

---

## Aktiva ramverk

| Ramverk | Version | Officiell källa | Senast verifierad |
|---------|---------|-----------------|-------------------|
| **GDPR** | 2016/679 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj) | 2025-01 |
| **NIS2** | 2022/2555 | [EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555) | 2025-01 |
| **OWASP Top 10** | 2021 | [OWASP](https://owasp.org/Top10/) | 2025-01 |
| **ISO 27001** | 2022 | [ISO](https://www.iso.org/standard/27001) | 2025-01 |
| **MSB Riktlinjer** | 2024 | [MSB](https://www.msb.se/sv/amnesomraden/informationssakerhet-cybersakerhet-och-sakra-kommunikationer/) | 2025-01 |
| **EU Cyber Resilience Act** | 2024 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847) | 2025-01 |

---

## Versionshistorik

### 2025-01-25
- Initial version
- Alla ramverk verifierade mot senaste officiella källor

---

## Kommande uppdateringar att bevaka

| Ramverk | Förväntat | Notering |
|---------|-----------|----------|
| **OWASP Top 10** | ~2025 | Ny version under utveckling |
| **NIS2 implementering** | 2024-2025 | Svenska implementeringsregler |
| **ISO 27001** | ~2028 | Normalt 5-6 års cykel |

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
