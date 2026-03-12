"""
Kodgranskningsagent (SAST - Static Application Security Testing).

Skannar källkod för säkerhetsproblem som:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Osäker kryptografi
- Hårdkodade hemligheter
- Osäkra funktioner
- Saknad rate limiting
- Saknat CSRF-skydd
- Webhook-endpoints utan HMAC-verifiering
- Otillräcklig input-validering
"""

import re
import uuid
from pathlib import Path
from typing import Optional

from security_toolkit.agents.base import BaseAgent
from security_toolkit.models import (
    Finding,
    FindingCategory,
    Severity,
    ScanConfig,
    ScanResult,
    CodeLocation,
)


# Säkerhetsmönster för olika programspråk
SECURITY_PATTERNS = {
    "sql_injection": {
        "patterns": [
            # Python
            r'execute\s*\(\s*["\'].*%s.*["\']\s*%',
            r'execute\s*\(\s*f["\'].*\{.*\}.*["\']',
            r'execute\s*\(\s*["\'].*\+.*["\']',
            r'cursor\.execute\s*\([^,]+\+',
            # JavaScript/TypeScript
            r'query\s*\(\s*[`"\'].*\$\{.*\}.*[`"\']',
            r'query\s*\(\s*["\'].*\+.*["\']',
            # PHP
            r'mysql_query\s*\(\s*["\'].*\$',
            r'mysqli_query\s*\([^,]+,\s*["\'].*\$',
            # Java
            r'executeQuery\s*\(\s*["\'].*\+',
            r'prepareStatement\s*\(\s*["\'].*\+',
        ],
        "severity": Severity.CRITICAL,
        "category": FindingCategory.INJECTION,
        "cwe_id": "CWE-89",
        "owasp_id": "A03:2021",
        "title": "Potentiell SQL Injection",
        "description": "SQL-frågor konstrueras med användarinput utan parameterisering, vilket möjliggör SQL-injektionsattacker.",
        "remediation": "Använd parameteriserade frågor (prepared statements) istället för strängkonkatenering.",
        "frameworks": ["gdpr", "nis2", "owasp_top10"],
    },
    "xss": {
        "patterns": [
            # JavaScript/TypeScript
            r'innerHTML\s*=\s*[^"\'`;]+',
            r'outerHTML\s*=\s*[^"\'`;]+',
            r'document\.write\s*\(',
            r'\.html\s*\([^)]*\+',
            # Python (Flask/Django)
            r'\|\s*safe\s*\}\}',
            r'mark_safe\s*\(',
            r'Markup\s*\(',
            # PHP
            r'echo\s+\$_(GET|POST|REQUEST)',
            r'print\s+\$_(GET|POST|REQUEST)',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.INJECTION,
        "cwe_id": "CWE-79",
        "owasp_id": "A03:2021",
        "title": "Potentiell Cross-Site Scripting (XSS)",
        "description": "Användardata renderas utan korrekt escaping, vilket kan leda till XSS-attacker.",
        "remediation": "Escapea alltid användardata innan rendering. Använd ramverkets inbyggda skydd.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "command_injection": {
        "patterns": [
            # Python
            r'os\.system\s*\([^)]*\+',
            r'os\.popen\s*\([^)]*\+',
            r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'subprocess\.(call|run|Popen)\s*\(\s*f["\']',
            r'eval\s*\(',
            r'exec\s*\(',
            # JavaScript/Node.js
            r'child_process\.exec\s*\([^)]*\+',
            r'child_process\.execSync\s*\([^)]*\+',
            # PHP
            r'shell_exec\s*\(\s*\$',
            r'exec\s*\(\s*\$',
            r'system\s*\(\s*\$',
            r'passthru\s*\(\s*\$',
            # Ruby
            r'system\s*\([^)]*#\{',
            r'`[^`]*#\{',
        ],
        "severity": Severity.CRITICAL,
        "category": FindingCategory.INJECTION,
        "cwe_id": "CWE-78",
        "owasp_id": "A03:2021",
        "title": "Potentiell Command Injection",
        "description": "Systemkommandon konstrueras med användarinput, vilket möjliggör command injection-attacker.",
        "remediation": "Undvik shell=True. Använd parameterlistor istället för strängkonkatenering. Validera och sanitera all input.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "path_traversal": {
        "patterns": [
            # Generellt
            r'open\s*\([^)]*\+[^)]*\)',
            r'open\s*\(\s*f["\'][^"\']*\{',
            r'Path\s*\([^)]*\+',
            # JavaScript/Node.js
            r'fs\.(readFile|writeFile|readdir)\s*\([^)]*\+',
            r'require\s*\([^)]*\+',
            # PHP
            r'(include|require|fopen)\s*\(\s*\$',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.ACCESS_CONTROL,
        "cwe_id": "CWE-22",
        "owasp_id": "A01:2021",
        "title": "Potentiell Path Traversal",
        "description": "Filsökvägar konstrueras med användarinput utan validering, vilket kan möjliggöra path traversal-attacker.",
        "remediation": "Validera och normalisera alla filsökvägar. Använd allowlists för tillåtna sökvägar.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "weak_crypto": {
        "patterns": [
            # Svaga algoritmer
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'MD5\s*\(',
            r'SHA1\s*\(',
            r'DES\s*\(',
            r'RC4\s*\(',
            # Svaga lägen
            r'AES\.MODE_ECB',
            r'mode\s*=\s*["\']ECB["\']',
            # Osäkra slumptal
            r'random\.random\s*\(',
            r'Math\.random\s*\(',
        ],
        "severity": Severity.MEDIUM,
        "category": FindingCategory.CRYPTOGRAPHY,
        "cwe_id": "CWE-327",
        "owasp_id": "A02:2021",
        "title": "Svag kryptografi",
        "description": "Användning av svaga eller föråldrade kryptografiska algoritmer upptäcktes.",
        "remediation": "Använd moderna algoritmer som SHA-256/SHA-3 för hashing och AES-GCM för kryptering.",
        "frameworks": ["gdpr", "nis2", "owasp_top10"],
    },
    "insecure_deserialization": {
        "patterns": [
            # Python
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*\)',
            r'marshal\.loads?\s*\(',
            # PHP
            r'unserialize\s*\(\s*\$',
            # Java
            r'ObjectInputStream\s*\(',
            r'readObject\s*\(',
            # JavaScript
            r'JSON\.parse\s*\([^)]*\)\s*\.',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.DESERIALIZATION,
        "cwe_id": "CWE-502",
        "owasp_id": "A08:2021",
        "title": "Osäker deserialisering",
        "description": "Deserialisering av opålitlig data kan leda till remote code execution.",
        "remediation": "Undvik deserialisering av opålitlig data. Använd säkrare format som JSON med strikt schemavalidering.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "ssrf": {
        "patterns": [
            # Python
            r'requests\.(get|post|put|delete)\s*\([^)]*\+',
            r'urllib\.request\.urlopen\s*\([^)]*\+',
            r'httpx\.(get|post)\s*\([^)]*\+',
            # JavaScript
            r'fetch\s*\([^)]*\+',
            r'axios\.(get|post)\s*\([^)]*\+',
            # PHP
            r'file_get_contents\s*\(\s*\$',
            r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.SSRF,
        "cwe_id": "CWE-918",
        "owasp_id": "A10:2021",
        "title": "Potentiell Server-Side Request Forgery (SSRF)",
        "description": "URLs konstrueras med användarinput, vilket kan möjliggöra SSRF-attacker.",
        "remediation": "Validera och sanitera alla URL:er. Använd allowlists för tillåtna domäner.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "hardcoded_credentials": {
        "patterns": [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',
            r'AWS_SECRET_ACCESS_KEY\s*=\s*["\']',
            r'PRIVATE_KEY\s*=\s*["\']',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.SECRET_EXPOSURE,
        "cwe_id": "CWE-798",
        "owasp_id": "A07:2021",
        "title": "Hårdkodade autentiseringsuppgifter",
        "description": "Hårdkodade lösenord, API-nycklar eller hemligheter upptäcktes i källkoden.",
        "remediation": "Använd miljövariabler eller en säker secrets manager. Rotera komprometterade hemligheter omedelbart.",
        "frameworks": ["gdpr", "nis2", "owasp_top10"],
    },
    "missing_authentication": {
        "patterns": [
            # Python/Flask
            r'@app\.route\s*\([^)]+\)\s*\n(?!.*@login_required)',
            # Express.js
            r'app\.(get|post|put|delete)\s*\([^,]+,\s*(?!.*auth)',
        ],
        "severity": Severity.MEDIUM,
        "category": FindingCategory.AUTHENTICATION,
        "cwe_id": "CWE-306",
        "owasp_id": "A07:2021",
        "title": "Endpoint utan autentisering",
        "description": "API-endpoint saknar autentiseringskontroll.",
        "remediation": "Implementera autentisering för alla känsliga endpoints.",
        "frameworks": ["owasp_top10", "nis2", "gdpr"],
    },
    "insecure_tls": {
        "patterns": [
            r'verify\s*=\s*False',
            r'ssl\s*=\s*False',
            r'CERT_NONE',
            r'rejectUnauthorized\s*:\s*false',
            r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.CRYPTOGRAPHY,
        "cwe_id": "CWE-295",
        "owasp_id": "A02:2021",
        "title": "Inaktiverad TLS-verifiering",
        "description": "TLS-certifikatverifiering är inaktiverad, vilket möjliggör man-in-the-middle-attacker.",
        "remediation": "Aktivera alltid TLS-certifikatverifiering i produktionsmiljöer.",
        "frameworks": ["gdpr", "nis2", "owasp_top10"],
    },
    "debug_enabled": {
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'debug\s*=\s*true',
            r'app\.debug\s*=\s*True',
            r'FLASK_DEBUG\s*=\s*1',
            r'NODE_ENV\s*=\s*["\']development["\']',
        ],
        "severity": Severity.MEDIUM,
        "category": FindingCategory.CONFIGURATION,
        "cwe_id": "CWE-489",
        "owasp_id": "A05:2021",
        "title": "Debug-läge aktiverat",
        "description": "Debug-läge verkar vara aktiverat, vilket kan exponera känslig information.",
        "remediation": "Inaktivera debug-läge i produktionsmiljöer.",
        "frameworks": ["owasp_top10"],
    },
    "insufficient_logging": {
        "patterns": [
            r'except\s*:\s*\n\s*pass',
            r'except\s+\w+\s*:\s*\n\s*pass',
            r'catch\s*\([^)]*\)\s*\{\s*\}',
            r'\.catch\s*\(\s*\(\)\s*=>\s*\{\s*\}\s*\)',
        ],
        "severity": Severity.LOW,
        "category": FindingCategory.LOGGING,
        "cwe_id": "CWE-778",
        "owasp_id": "A09:2021",
        "title": "Bristande felhantering/loggning",
        "description": "Undantag fångas men ignoreras utan loggning, vilket försvårar felsökning och incidentdetektering.",
        "remediation": "Logga alla undantag med tillräcklig kontextinformation.",
        "frameworks": ["nis2", "owasp_top10"],
    },
    "missing_rate_limiting": {
        "patterns": [
            # Python/Flask - route utan rate limiting
            r'@app\.route\s*\(\s*["\']/(login|auth|api|register|reset|forgot)',
            # Express.js - auth/login-endpoints utan rate limiter
            r'app\.(post|get)\s*\(\s*["\']/?(login|auth|api/auth|register|reset-password|forgot-password)',
            # Django - auth views utan throttling
            r'path\s*\(\s*["\'](login|auth|api/token|register)',
            # FastAPI - auth endpoints
            r'@(app|router)\.(post|get)\s*\(\s*["\']/?(login|auth|token|register)',
            # PHP - login/auth endpoints
            r'Route::(post|get)\s*\(\s*["\']/?(login|auth|register|reset)',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.CONFIGURATION,
        "cwe_id": "CWE-770",
        "owasp_id": "A04:2021",
        "title": "Potentiellt saknad rate limiting på känslig endpoint",
        "description": "Känsliga endpoints (login, registrering, API) saknar troligen rate limiting, vilket möjliggör brute force-attacker och resursmissbruk.",
        "remediation": "Implementera rate limiting med t.ex. flask-limiter, express-rate-limit, django-ratelimit, eller en API-gateway. Begränsa till max 5-10 försök per minut för auth-endpoints.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "missing_csrf_protection": {
        "patterns": [
            # Flask - formulär utan CSRF-skydd
            r'@app\.route\s*\([^)]*methods\s*=\s*\[[^\]]*["\']POST["\']',
            # Express.js - POST-routes (bör ha csurf)
            r'app\.post\s*\(\s*["\'][^"\']+["\']\s*,\s*(?!.*csrf)',
            # Django - csrf_exempt decorator
            r'@csrf_exempt',
            # PHP/Laravel - without middleware
            r'Route::post\s*\([^)]+\)\s*(?!.*->middleware.*csrf)',
            # HTML-formulär utan CSRF-token
            r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>(?![\s\S]{0,500}csrf)',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.ACCESS_CONTROL,
        "cwe_id": "CWE-352",
        "owasp_id": "A01:2021",
        "title": "Potentiellt saknat CSRF-skydd",
        "description": "POST-endpoint eller formulär saknar troligen CSRF-skydd, vilket gör det möjligt för angripare att utföra åtgärder i autentiserade användares namn.",
        "remediation": "Implementera CSRF-tokens i alla formulär och state-changing requests. Använd ramverkets inbyggda CSRF-skydd (t.ex. Flask-WTF CSRFProtect, Django CSRF middleware, csurf för Express).",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "missing_webhook_verification": {
        "patterns": [
            # Webhook-endpoints utan HMAC-verifiering
            r'@app\.route\s*\(\s*["\'][^"\']*webhook[^"\']*["\']',
            r'app\.(post|get)\s*\(\s*["\'][^"\']*webhook[^"\']*["\']',
            r'@(app|router)\.(post|get)\s*\(\s*["\'][^"\']*webhook[^"\']*["\']',
            r'path\s*\(\s*["\'][^"\']*webhook[^"\']*["\']',
            r'Route::(post|get)\s*\(\s*["\'][^"\']*webhook[^"\']*["\']',
            # Generella callback-/hook-endpoints
            r'@app\.route\s*\(\s*["\'][^"\']*callback[^"\']*["\']',
            r'app\.post\s*\(\s*["\'][^"\']*hook[^"\']*["\']',
        ],
        "severity": Severity.HIGH,
        "category": FindingCategory.AUTHENTICATION,
        "cwe_id": "CWE-345",
        "owasp_id": "A07:2021",
        "title": "Webhook-endpoint utan signaturverifiering",
        "description": "Webhook-endpoint upptäckt utan tydlig HMAC-signaturverifiering. Utan verifiering kan angripare fejka webhook-anrop till servern.",
        "remediation": "Verifiera alla inkommande webhooks med HMAC-SHA256 signatur. Jämför signaturen i headern (t.ex. X-Hub-Signature-256) med en beräknad HMAC av request body och en delad hemlighet.",
        "frameworks": ["owasp_top10", "nis2"],
    },
    "missing_input_sanitization": {
        "patterns": [
            # Direkt användning av request-data utan validering
            # Python/Flask
            r'request\.(form|args|json)\s*\[\s*["\'][^"\']+["\']\s*\]',
            r'request\.get_json\s*\(\)',
            # Express.js
            r'req\.(body|query|params)\s*\.\s*\w+',
            r'req\.(body|query|params)\s*\[\s*["\']',
            # PHP
            r'\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*["\']',
            # Django
            r'request\.(GET|POST|data)\s*\[\s*["\']',
            r'request\.(GET|POST|data)\.get\s*\(',
        ],
        "severity": Severity.MEDIUM,
        "category": FindingCategory.INJECTION,
        "cwe_id": "CWE-20",
        "owasp_id": "A03:2021",
        "title": "Användarinput utan validering/sanitering",
        "description": "Användarinput hämtas direkt utan synlig validering eller sanitering. All input bör valideras mot förväntade typer, längder och format.",
        "remediation": "Validera och sanitera ALL användarinput. Använd schema-validering (t.ex. Pydantic, Joi, Marshmallow, Zod) för att säkerställa att indata matchar förväntade format. Begränsa stränglängder och använd allowlists där möjligt.",
        "frameworks": ["owasp_top10", "nis2", "gdpr"],
    },
}

# Filtyper att skanna
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".php", ".rb", ".go",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".swift", ".kt", ".scala", ".rs",
    ".vue", ".svelte", ".html", ".htm", ".xml", ".yaml", ".yml", ".json",
    ".sql", ".sh", ".bash", ".ps1", ".psm1",
}


class CodeScannerAgent(BaseAgent):
    """
    Agent för statisk kodanalys (SAST).

    Skannar källkod för säkerhetsproblem och sårbarheter
    enligt OWASP, GDPR, NIS2 och andra standarder.
    """

    @property
    def scan_type(self) -> str:
        return "SAST"

    async def scan(self, target: str) -> ScanResult:
        """
        Utför statisk kodanalys av målkatalogen.

        Args:
            target: Sökväg till katalog eller fil att skanna.

        Returns:
            ScanResult med alla upptäckta säkerhetsproblem.
        """
        result = self._create_scan_result(target)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Målsökväg existerar inte: {target}")
            return self._finalize_scan_result(result)

        self.log(f"Startar SAST-skanning av: {target}")

        files = self._get_files_to_scan(target_path)
        self.log(f"Hittade {len(files)} filer att skanna")

        for file_path in files:
            await self._scan_file(file_path, target_path)

        return self._finalize_scan_result(result)

    async def _scan_file(self, file_path: Path, base_path: Path) -> None:
        """Skanna en enskild fil för säkerhetsproblem."""
        if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
        except Exception as e:
            self.log(f"Kunde inte läsa fil: {file_path}: {e}", "error")
            return

        rel_path = str(file_path.relative_to(base_path))
        self.log(f"Skannar: {rel_path}")

        for rule_name, rule in SECURITY_PATTERNS.items():
            for pattern in rule["patterns"]:
                try:
                    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    for match in regex.finditer(content):
                        line_num = content[:match.start()].count("\n") + 1
                        code_snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                        finding = Finding(
                            id=str(uuid.uuid4()),
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            category=rule["category"],
                            location=CodeLocation(
                                file_path=rel_path,
                                line_start=line_num,
                                code_snippet=code_snippet[:200],
                            ),
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                            remediation=rule["remediation"],
                            compliance_frameworks=rule["frameworks"],
                            metadata={"rule": rule_name, "pattern": pattern},
                        )
                        self.add_finding(finding)
                except re.error as e:
                    self.log(f"Regex-fel för mönster {pattern}: {e}", "warning")

    def _get_files_to_scan(self, target_path: Path) -> list[Path]:
        """Hämta lista över filer att skanna, exkludera oönskade kataloger."""
        exclude_dirs = {
            ".git", ".svn", ".hg", "node_modules", "__pycache__",
            ".venv", "venv", "env", ".env", "vendor", "dist", "build",
            ".idea", ".vscode", "coverage", ".nyc_output",
        }

        files = []

        if target_path.is_file():
            files.append(target_path)
        elif target_path.is_dir():
            for file_path in target_path.rglob("*"):
                # Exkludera oönskade kataloger
                if any(excluded in file_path.parts for excluded in exclude_dirs):
                    continue
                if file_path.is_file():
                    if not self._should_exclude(str(file_path)):
                        files.append(file_path)

        return files
