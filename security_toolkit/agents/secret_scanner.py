"""
Hemlighetsdetekteringsagent.

Skannar kod och konfigurationsfiler för exponerade hemligheter:
- API-nycklar
- Lösenord
- Tokens (JWT, OAuth, etc.)
- Privata nycklar (SSH, SSL/TLS)
- Databaskonfiguration
- Cloud-credentials (AWS, GCP, Azure)
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


# Mönster för hemlighetsdetektering
SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "pattern": r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "title": "AWS Access Key ID",
        "description": "AWS Access Key ID exponerad i källkoden.",
        "severity": Severity.CRITICAL,
    },
    "aws_secret_key": {
        "pattern": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "title": "Potentiell AWS Secret Access Key",
        "description": "Möjlig AWS Secret Access Key exponerad.",
        "severity": Severity.CRITICAL,
        "context_required": ["aws", "secret", "key"],
    },

    # Google Cloud
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "title": "Google Cloud API Key",
        "description": "Google Cloud API-nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },
    "gcp_service_account": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "title": "GCP Service Account JSON",
        "description": "Google Cloud service account-nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },

    # Azure
    "azure_connection_string": {
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+",
        "title": "Azure Storage Connection String",
        "description": "Azure Storage connection string exponerad.",
        "severity": Severity.CRITICAL,
    },

    # GitHub
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "title": "GitHub Personal Access Token",
        "description": "GitHub Personal Access Token exponerad.",
        "severity": Severity.CRITICAL,
    },
    "github_oauth": {
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "title": "GitHub OAuth Access Token",
        "description": "GitHub OAuth-token exponerad.",
        "severity": Severity.CRITICAL,
    },

    # GitLab
    "gitlab_token": {
        "pattern": r"glpat-[A-Za-z0-9\-_]{20,}",
        "title": "GitLab Personal Access Token",
        "description": "GitLab Personal Access Token exponerad.",
        "severity": Severity.CRITICAL,
    },

    # Slack
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "title": "Slack Token",
        "description": "Slack API-token exponerad.",
        "severity": Severity.HIGH,
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "title": "Slack Webhook URL",
        "description": "Slack Webhook-URL exponerad.",
        "severity": Severity.MEDIUM,
    },

    # Stripe
    "stripe_secret_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "title": "Stripe Secret Key (Live)",
        "description": "Stripe Live Secret Key exponerad - kritisk ekonomisk risk!",
        "severity": Severity.CRITICAL,
    },
    "stripe_publishable_key": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
        "title": "Stripe Publishable Key (Live)",
        "description": "Stripe Live Publishable Key exponerad.",
        "severity": Severity.LOW,
    },

    # Twilio
    "twilio_api_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "title": "Twilio API Key",
        "description": "Twilio API-nyckel exponerad.",
        "severity": Severity.HIGH,
    },

    # SendGrid
    "sendgrid_api_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "title": "SendGrid API Key",
        "description": "SendGrid API-nyckel exponerad.",
        "severity": Severity.HIGH,
    },

    # JWT
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "title": "JSON Web Token (JWT)",
        "description": "JWT-token exponerad i källkoden.",
        "severity": Severity.MEDIUM,
    },

    # Private Keys
    "private_key_rsa": {
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "title": "RSA Private Key",
        "description": "RSA privat nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },
    "private_key_openssh": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "title": "OpenSSH Private Key",
        "description": "OpenSSH privat nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },
    "private_key_ec": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "title": "EC Private Key",
        "description": "Elliptic Curve privat nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },
    "private_key_dsa": {
        "pattern": r"-----BEGIN DSA PRIVATE KEY-----",
        "title": "DSA Private Key",
        "description": "DSA privat nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },
    "private_key_pgp": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "title": "PGP Private Key",
        "description": "PGP privat nyckel exponerad.",
        "severity": Severity.CRITICAL,
    },

    # Database
    "database_url": {
        "pattern": r"(mysql|postgres|postgresql|mongodb|redis|amqp|mssql):\/\/[^:]+:[^@]+@[^\s]+",
        "title": "Database Connection String",
        "description": "Databasanslutningssträng med autentisering exponerad.",
        "severity": Severity.CRITICAL,
    },

    # Generic patterns
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
        "title": "API Key",
        "description": "Generisk API-nyckel exponerad.",
        "severity": Severity.HIGH,
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "title": "Hardcoded Secret/Password",
        "description": "Hårdkodat lösenord eller hemlighet exponerad.",
        "severity": Severity.HIGH,
    },
    "generic_token": {
        "pattern": r"(?i)(token|bearer)\s*[=:]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]",
        "title": "Hardcoded Token",
        "description": "Hårdkodad token exponerad.",
        "severity": Severity.HIGH,
    },

    # Heroku
    "heroku_api_key": {
        "pattern": r"[hH]eroku[a-zA-Z0-9_]*[=:]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]",
        "title": "Heroku API Key",
        "description": "Heroku API-nyckel exponerad.",
        "severity": Severity.HIGH,
    },

    # npm
    "npm_token": {
        "pattern": r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+",
        "title": "NPM Token",
        "description": "NPM authentication token exponerad.",
        "severity": Severity.HIGH,
    },

    # Docker
    "docker_auth": {
        "pattern": r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
        "title": "Docker Registry Auth",
        "description": "Docker registry autentisering exponerad.",
        "severity": Severity.HIGH,
    },

    # Mailchimp
    "mailchimp_api_key": {
        "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",
        "title": "Mailchimp API Key",
        "description": "Mailchimp API-nyckel exponerad.",
        "severity": Severity.MEDIUM,
    },

    # Discord
    "discord_bot_token": {
        "pattern": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        "title": "Discord Bot Token",
        "description": "Discord bot-token exponerad.",
        "severity": Severity.HIGH,
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        "title": "Discord Webhook URL",
        "description": "Discord webhook-URL exponerad.",
        "severity": Severity.MEDIUM,
    },

    # Telegram
    "telegram_bot_token": {
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        "title": "Telegram Bot Token",
        "description": "Telegram bot-token exponerad.",
        "severity": Severity.HIGH,
    },

    # Facebook
    "facebook_access_token": {
        "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "title": "Facebook Access Token",
        "description": "Facebook access token exponerad.",
        "severity": Severity.HIGH,
    },

    # Twitter
    "twitter_bearer_token": {
        "pattern": r"AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+",
        "title": "Twitter Bearer Token",
        "description": "Twitter bearer token exponerad.",
        "severity": Severity.HIGH,
    },
}

# Filer att exkludera från skanning
EXCLUDE_FILES = {
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "go.sum",
}

# Kataloger att exkludera
EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".nyc_output",
}


class SecretScannerAgent(BaseAgent):
    """
    Agent för att detektera exponerade hemligheter i källkod.

    Skannar efter API-nycklar, lösenord, tokens och andra
    känsliga uppgifter som inte bör finnas i version control.
    """

    @property
    def scan_type(self) -> str:
        return "Secret"

    async def scan(self, target: str) -> ScanResult:
        """
        Skanna efter exponerade hemligheter.

        Args:
            target: Sökväg till katalog eller fil att skanna.

        Returns:
            ScanResult med alla upptäckta hemligheter.
        """
        result = self._create_scan_result(target)
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"Målsökväg existerar inte: {target}")
            return self._finalize_scan_result(result)

        self.log(f"Startar hemlighetsdetektering av: {target}")

        files = self._get_files_to_scan(target_path)
        self.log(f"Skannar {len(files)} filer efter hemligheter")

        for file_path in files:
            await self._scan_file(file_path, target_path)

        return self._finalize_scan_result(result)

    def _get_files_to_scan(self, target_path: Path) -> list[Path]:
        """Hämta lista över filer att skanna."""
        files = []

        if target_path.is_file():
            files.append(target_path)
        elif target_path.is_dir():
            for file_path in target_path.rglob("*"):
                # Exkludera oönskade kataloger
                if any(excluded in file_path.parts for excluded in EXCLUDE_DIRS):
                    continue
                # Exkludera låsfiler
                if file_path.name in EXCLUDE_FILES:
                    continue
                if file_path.is_file():
                    # Hoppa över binärfiler
                    if self._is_binary(file_path):
                        continue
                    files.append(file_path)

        return files

    def _is_binary(self, file_path: Path) -> bool:
        """Kontrollera om en fil är binär."""
        binary_extensions = {
            ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".zip", ".tar", ".gz", ".rar", ".7z",
            ".mp3", ".mp4", ".wav", ".avi", ".mov",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".pyc", ".pyo", ".class", ".o", ".obj",
        }
        return file_path.suffix.lower() in binary_extensions

    async def _scan_file(self, file_path: Path, base_path: Path) -> None:
        """Skanna en fil efter hemligheter."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.log(f"Kunde inte läsa: {file_path}: {e}", "error")
            return

        rel_path = str(file_path.relative_to(base_path))
        lines = content.split("\n")

        for secret_type, config in SECRET_PATTERNS.items():
            pattern = config["pattern"]

            # Kontrollera om kontextkrav finns
            context_required = config.get("context_required", [])
            if context_required:
                content_lower = content.lower()
                if not any(ctx in content_lower for ctx in context_required):
                    continue

            try:
                regex = re.compile(pattern)
                for match in regex.finditer(content):
                    # Beräkna radnummer
                    line_num = content[:match.start()].count("\n") + 1
                    matched_text = match.group(0)

                    # Maskera hemligheten för säker rapportering
                    masked = self._mask_secret(matched_text)

                    # Hämta kodkontext
                    code_line = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Kontrollera om det är en false positive
                    if self._is_false_positive(code_line, secret_type, file_path):
                        continue

                    finding = Finding(
                        id=str(uuid.uuid4()),
                        title=config["title"],
                        description=f"{config['description']}\n\nMaskerat värde: {masked}",
                        severity=config["severity"],
                        category=FindingCategory.SECRET_EXPOSURE,
                        location=CodeLocation(
                            file_path=rel_path,
                            line_start=line_num,
                            code_snippet=self._sanitize_snippet(code_line),
                        ),
                        cwe_id="CWE-798",
                        owasp_id="A07:2021",
                        remediation=self._get_remediation(secret_type),
                        compliance_frameworks=["gdpr", "nis2", "owasp_top10"],
                        metadata={
                            "secret_type": secret_type,
                            "masked_value": masked,
                        },
                    )
                    self.add_finding(finding)

            except re.error as e:
                self.log(f"Regex-fel för {secret_type}: {e}", "warning")

    def _mask_secret(self, secret: str) -> str:
        """Maskera en hemlighet för säker visning."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _sanitize_snippet(self, code_line: str) -> str:
        """Sanitera kodrad för att dölja känsliga värden."""
        # Ersätt känsliga värden med asterisker
        patterns = [
            (r'(["\'])[A-Za-z0-9_\-/+=]{20,}(["\'])', r'\1****REDACTED****\2'),
            (r'(password|secret|key|token)\s*[=:]\s*["\'][^"\']+["\']', r'\1 = "****REDACTED****"'),
        ]
        result = code_line
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result[:200]

    def _is_false_positive(
        self,
        code_line: str,
        secret_type: str,
        file_path: Path,
    ) -> bool:
        """Kontrollera om en match troligen är en false positive."""
        code_lower = code_line.lower()

        # Ignorera kommentarer och dokumentation
        if file_path.suffix in (".md", ".rst", ".txt"):
            return True

        # Ignorera uppenbart exempel-data
        example_indicators = [
            "example", "sample", "test", "fake", "mock", "dummy",
            "placeholder", "your_", "xxx", "000000", "123456",
            "<your", "{your", "INSERT_", "REPLACE_", "TODO",
        ]
        if any(indicator in code_lower for indicator in example_indicators):
            return True

        # Ignorera environment variable references
        if re.search(r'(os\.environ|process\.env|getenv|ENV\[)', code_line):
            return True

        # Ignorera config file keys (without values)
        if re.search(r'^\s*(#|//|/\*|\*|;)', code_line):
            return True

        return False

    def _get_remediation(self, secret_type: str) -> str:
        """Hämta åtgärdsrekommendation för hemlighettyp."""
        remediations = {
            "aws_access_key": "1. Invalidera omedelbart denna AWS-nyckel i AWS Console\n2. Rotera credentials\n3. Använd AWS Secrets Manager eller miljövariabler",
            "aws_secret_key": "1. Invalidera omedelbart denna AWS-nyckel\n2. Kontrollera CloudTrail för obehörig användning\n3. Använd IAM roles istället för långlivade credentials",
            "gcp_api_key": "1. Invalidera nyckeln i Google Cloud Console\n2. Skapa en ny nyckel med restriktioner\n3. Lagra nycklar i Secret Manager",
            "github_token": "1. Revokera token omedelbart på GitHub\n2. Kontrollera aktivitetsloggen för obehörig användning\n3. Använd GitHub Apps istället för PATs",
            "private_key_rsa": "1. Generera ett nytt nyckelpar\n2. Uppdatera alla system som använder nyckeln\n3. Lagra privata nycklar i en säker vault",
            "database_url": "1. Ändra databaslösenord omedelbart\n2. Begränsa databasåtkomst via nätverksregler\n3. Använd secrets management för connection strings",
            "stripe_secret_key": "1. Rotera nyckeln omedelbart i Stripe Dashboard\n2. Kontrollera transaktionsloggen\n3. Använd Stripe's restricted keys med minimala behörigheter",
        }
        return remediations.get(
            secret_type,
            "1. Invalidera/rotera hemligheten omedelbart\n2. Använd en secrets manager (t.ex. HashiCorp Vault, AWS Secrets Manager)\n3. Lägg till filen i .gitignore om tillämpligt"
        )
