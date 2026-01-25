"""
Webbapplikationsscanner (DAST - Dynamic Application Security Testing).

Skannar webbapplikationer för säkerhetsproblem som:
- Saknade säkerhetsheaders
- CORS-felkonfiguration
- Cookie-säkerhet
- SSL/TLS-konfiguration
- Information disclosure
- Öppna redirects
"""

import asyncio
import re
import ssl
import uuid
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from security_toolkit.agents.base import BaseAgent
from security_toolkit.models import (
    Finding,
    FindingCategory,
    Severity,
    ScanConfig,
    ScanResult,
)


# Säkerhetsheaders att kontrollera
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS-header saknas. Webbläsare kan tillåta HTTP-anslutningar.",
        "remediation": "Lägg till header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP-header saknas. Webbplatsen är mer sårbar för XSS-attacker.",
        "remediation": "Implementera en Content-Security-Policy som begränsar tillåtna källor för scripts och resurser.",
        "frameworks": ["owasp_top10"],
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options saknas. MIME-sniffing kan aktiveras.",
        "remediation": "Lägg till header: X-Content-Type-Options: nosniff",
        "frameworks": ["owasp_top10"],
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options saknas. Webbplatsen kan vara sårbar för clickjacking.",
        "remediation": "Lägg till header: X-Frame-Options: DENY eller SAMEORIGIN",
        "frameworks": ["owasp_top10"],
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection saknas (äldre webbläsare).",
        "remediation": "Lägg till header: X-XSS-Protection: 1; mode=block",
        "frameworks": ["owasp_top10"],
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy saknas. Känslig information kan läcka via referer-header.",
        "remediation": "Lägg till header: Referrer-Policy: strict-origin-when-cross-origin",
        "frameworks": ["gdpr", "owasp_top10"],
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy saknas. Webbläsar-API:er kan missbrukas.",
        "remediation": "Lägg till header: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "frameworks": ["gdpr"],
    },
}

# Osäkra header-värden att kontrollera
INSECURE_HEADER_VALUES = {
    "Access-Control-Allow-Origin": {
        "pattern": r"^\*$",
        "severity": Severity.HIGH,
        "description": "CORS tillåter alla origins (*), vilket kan möjliggöra dataläckage.",
        "remediation": "Begränsa CORS till specifika betrodda domäner.",
        "frameworks": ["owasp_top10"],
    },
    "Content-Security-Policy": {
        "pattern": r"unsafe-inline|unsafe-eval",
        "severity": Severity.MEDIUM,
        "description": "CSP innehåller osäkra direktiv (unsafe-inline/unsafe-eval).",
        "remediation": "Ta bort unsafe-inline och unsafe-eval från CSP. Använd nonces eller hashes istället.",
        "frameworks": ["owasp_top10"],
    },
}


class WebScannerAgent(BaseAgent):
    """
    Agent för dynamisk applikationssäkerhetstestning (DAST).

    Skannar webbapplikationer för säkerhetskonfigurationsproblem.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        super().__init__(config)
        self.client: Optional[httpx.AsyncClient] = None
        self.visited_urls: set[str] = set()

    @property
    def scan_type(self) -> str:
        return "DAST"

    async def scan(self, target: str) -> ScanResult:
        """
        Utför säkerhetsskanning av webbapplikation.

        Args:
            target: URL till webbapplikationen att skanna.

        Returns:
            ScanResult med alla upptäckta säkerhetsproblem.
        """
        result = self._create_scan_result(target)

        # Validera URL
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            result.errors.append(f"Ogiltig URL: {target}")
            return self._finalize_scan_result(result)

        self.log(f"Startar DAST-skanning av: {target}")

        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=True,
        ) as self.client:
            # Utför alla skanningar
            await self._check_ssl_tls(target)
            await self._check_security_headers(target)
            await self._check_cookies(target)
            await self._check_information_disclosure(target)
            await self._check_common_vulnerabilities(target)
            await self._check_sensitive_files(target)

        return self._finalize_scan_result(result)

    async def _check_ssl_tls(self, url: str) -> None:
        """Kontrollera SSL/TLS-konfiguration."""
        parsed = urlparse(url)

        # Kontrollera om HTTPS används
        if parsed.scheme != "https":
            self.add_finding(Finding(
                id=str(uuid.uuid4()),
                title="Webbplats använder inte HTTPS",
                description="Webbplatsen är tillgänglig via HTTP, vilket innebär att data skickas okrypterat.",
                severity=Severity.CRITICAL,
                category=FindingCategory.CRYPTOGRAPHY,
                url=url,
                cwe_id="CWE-319",
                owasp_id="A02:2021",
                remediation="Aktivera HTTPS och omdirigera all HTTP-trafik till HTTPS.",
                compliance_frameworks=["gdpr", "nis2", "owasp_top10"],
            ))
            return

        # Kontrollera SSL-certifikat
        try:
            context = ssl.create_default_context()
            hostname = parsed.netloc.split(":")[0]

            # Enkel TLS-kontroll
            import socket
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Kontrollera TLS-version
                    version = ssock.version()
                    if version and version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        self.add_finding(Finding(
                            id=str(uuid.uuid4()),
                            title=f"Föråldrad TLS-version: {version}",
                            description=f"Servern använder {version} som är föråldrad och osäker.",
                            severity=Severity.HIGH,
                            category=FindingCategory.CRYPTOGRAPHY,
                            url=url,
                            cwe_id="CWE-326",
                            owasp_id="A02:2021",
                            remediation="Uppgradera till TLS 1.2 eller TLS 1.3.",
                            compliance_frameworks=["gdpr", "nis2", "owasp_top10"],
                        ))

        except ssl.SSLCertVerificationError as e:
            self.add_finding(Finding(
                id=str(uuid.uuid4()),
                title="SSL-certifikatproblem",
                description=f"SSL-certifikatet kunde inte verifieras: {str(e)}",
                severity=Severity.CRITICAL,
                category=FindingCategory.CRYPTOGRAPHY,
                url=url,
                cwe_id="CWE-295",
                owasp_id="A02:2021",
                remediation="Installera ett giltigt SSL-certifikat från en betrodd CA.",
                compliance_frameworks=["gdpr", "nis2", "owasp_top10"],
            ))
        except Exception as e:
            self.log(f"Kunde inte kontrollera SSL: {e}", "warning")

    async def _check_security_headers(self, url: str) -> None:
        """Kontrollera säkerhetsheaders."""
        try:
            response = await self.client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Kontrollera saknade headers
            for header, info in SECURITY_HEADERS.items():
                header_lower = header.lower()
                if header_lower not in headers:
                    self.add_finding(Finding(
                        id=str(uuid.uuid4()),
                        title=f"Saknad säkerhetsheader: {header}",
                        description=info["description"],
                        severity=info["severity"],
                        category=FindingCategory.CONFIGURATION,
                        url=url,
                        cwe_id="CWE-693",
                        owasp_id="A05:2021",
                        remediation=info["remediation"],
                        compliance_frameworks=info["frameworks"],
                    ))

            # Kontrollera osäkra header-värden
            for header, info in INSECURE_HEADER_VALUES.items():
                header_lower = header.lower()
                if header_lower in headers:
                    if re.search(info["pattern"], headers[header_lower]):
                        self.add_finding(Finding(
                            id=str(uuid.uuid4()),
                            title=f"Osäkert värde för header: {header}",
                            description=info["description"],
                            severity=info["severity"],
                            category=FindingCategory.CONFIGURATION,
                            url=url,
                            cwe_id="CWE-693",
                            owasp_id="A05:2021",
                            remediation=info["remediation"],
                            compliance_frameworks=info["frameworks"],
                        ))

            # Kontrollera Server-header information disclosure
            if "server" in headers:
                server = headers["server"]
                if re.search(r"[\d\.]+", server):
                    self.add_finding(Finding(
                        id=str(uuid.uuid4()),
                        title="Server-version exponerad",
                        description=f"Server-headern exponerar versionsinformation: {server}",
                        severity=Severity.LOW,
                        category=FindingCategory.DATA_EXPOSURE,
                        url=url,
                        cwe_id="CWE-200",
                        owasp_id="A05:2021",
                        remediation="Dölj eller ta bort versionsinformation från Server-headern.",
                        compliance_frameworks=["owasp_top10"],
                    ))

        except httpx.RequestError as e:
            self.log(f"Kunde inte hämta headers: {e}", "error")

    async def _check_cookies(self, url: str) -> None:
        """Kontrollera cookie-säkerhet."""
        try:
            response = await self.client.get(url)

            for cookie in response.cookies.jar:
                issues = []

                if not cookie.secure:
                    issues.append("Secure-flagga saknas")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("HttpOnly-flagga saknas")

                # Kontrollera SameSite
                samesite = cookie.get_nonstandard_attr("SameSite")
                if not samesite or samesite.lower() == "none":
                    issues.append("SameSite är inte satt eller är 'None'")

                if issues:
                    self.add_finding(Finding(
                        id=str(uuid.uuid4()),
                        title=f"Osäker cookie: {cookie.name}",
                        description=f"Cookie '{cookie.name}' har säkerhetsproblem: {', '.join(issues)}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.CONFIGURATION,
                        url=url,
                        cwe_id="CWE-614",
                        owasp_id="A05:2021",
                        remediation="Sätt Secure, HttpOnly och SameSite=Strict på alla cookies.",
                        compliance_frameworks=["gdpr", "owasp_top10"],
                    ))

        except httpx.RequestError as e:
            self.log(f"Kunde inte kontrollera cookies: {e}", "error")

    async def _check_information_disclosure(self, url: str) -> None:
        """Kontrollera information disclosure."""
        try:
            response = await self.client.get(url)
            content = response.text.lower()

            # Kontrollera efter känslig information i HTML
            patterns = [
                (r"<!--.*?(password|secret|api[_-]?key|token).*?-->", "Känslig information i HTML-kommentarer"),
                (r"(todo|fixme|hack|xxx).*?(password|secret|credential)", "Känslig TODO/FIXME-kommentar"),
                (r"console\.(log|debug)\s*\(", "Debug-loggning i produktion"),
            ]

            for pattern, description in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.add_finding(Finding(
                        id=str(uuid.uuid4()),
                        title="Information Disclosure",
                        description=description,
                        severity=Severity.LOW,
                        category=FindingCategory.DATA_EXPOSURE,
                        url=url,
                        cwe_id="CWE-200",
                        owasp_id="A05:2021",
                        remediation="Ta bort känslig information och debug-kod innan deployment.",
                        compliance_frameworks=["gdpr", "owasp_top10"],
                    ))
                    break

        except httpx.RequestError as e:
            self.log(f"Kunde inte kontrollera information disclosure: {e}", "error")

    async def _check_common_vulnerabilities(self, url: str) -> None:
        """Kontrollera vanliga sårbarheter."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Testa för directory listing
        test_paths = ["/", "/images/", "/assets/", "/uploads/", "/static/"]
        for path in test_paths:
            try:
                test_url = urljoin(base_url, path)
                response = await self.client.get(test_url)
                if response.status_code == 200:
                    content = response.text.lower()
                    if "index of" in content or "directory listing" in content:
                        self.add_finding(Finding(
                            id=str(uuid.uuid4()),
                            title="Directory Listing aktiverat",
                            description=f"Directory listing är aktiverat på: {test_url}",
                            severity=Severity.MEDIUM,
                            category=FindingCategory.CONFIGURATION,
                            url=test_url,
                            cwe_id="CWE-548",
                            owasp_id="A05:2021",
                            remediation="Inaktivera directory listing i webbserver-konfigurationen.",
                            compliance_frameworks=["owasp_top10"],
                        ))
            except httpx.RequestError:
                pass

    async def _check_sensitive_files(self, url: str) -> None:
        """Kontrollera efter exponerade känsliga filer."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        sensitive_paths = [
            ("/.git/config", "Git-konfiguration exponerad"),
            ("/.env", "Miljövariabler exponerade (.env)"),
            ("/config.php", "PHP-konfiguration exponerad"),
            ("/wp-config.php", "WordPress-konfiguration exponerad"),
            ("/web.config", "IIS-konfiguration exponerad"),
            ("/.htaccess", "Apache .htaccess exponerad"),
            ("/robots.txt", "Robots.txt (info)"),
            ("/.well-known/security.txt", "Security.txt (info)"),
            ("/phpinfo.php", "PHPInfo exponerad"),
            ("/server-status", "Apache server-status exponerad"),
            ("/elmah.axd", "ELMAH error log exponerad"),
            ("/.DS_Store", "macOS .DS_Store exponerad"),
            ("/backup.sql", "SQL-backup exponerad"),
            ("/database.sql", "Databas-dump exponerad"),
        ]

        for path, description in sensitive_paths:
            try:
                test_url = urljoin(base_url, path)
                response = await self.client.get(test_url)

                if response.status_code == 200:
                    # Bestäm allvarlighetsgrad baserat på filtyp
                    if any(x in path for x in [".git", ".env", "config", "backup", "database", "phpinfo"]):
                        severity = Severity.CRITICAL
                    elif any(x in path for x in [".htaccess", "web.config"]):
                        severity = Severity.HIGH
                    elif path in ["/robots.txt", "/.well-known/security.txt"]:
                        severity = Severity.INFO
                    else:
                        severity = Severity.MEDIUM

                    if severity != Severity.INFO:
                        self.add_finding(Finding(
                            id=str(uuid.uuid4()),
                            title=f"Känslig fil exponerad: {path}",
                            description=description,
                            severity=severity,
                            category=FindingCategory.DATA_EXPOSURE,
                            url=test_url,
                            cwe_id="CWE-538",
                            owasp_id="A05:2021",
                            remediation=f"Blockera åtkomst till {path} via webbserver-konfiguration.",
                            compliance_frameworks=["gdpr", "nis2", "owasp_top10"],
                        ))

            except httpx.RequestError:
                pass

            # Liten fördröjning för att inte överbelasta servern
            await asyncio.sleep(0.1)
