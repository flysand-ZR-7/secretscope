"""Secret detection patterns for SecretScope."""
import math
import re
from collections import Counter

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity": "critical",
        "description": "AWS Access Key ID starting with AKIA",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}',
        "severity": "critical",
        "description": "AWS Secret Access Key assignment",
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r'ghp_[A-Za-z0-9_]{36,}',
        "severity": "critical",
        "description": "GitHub Personal Access Token (classic)",
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": r'gho_[A-Za-z0-9_]{36,}',
        "severity": "high",
        "description": "GitHub OAuth Access Token",
    },
    {
        "name": "GitHub App Token",
        "pattern": r'ghs_[A-Za-z0-9_]{36,}',
        "severity": "high",
        "description": "GitHub App Installation Token",
    },
    {
        "name": "GitHub Fine-grained Token",
        "pattern": r'github_pat_[A-Za-z0-9_]{22,}',
        "severity": "critical",
        "description": "GitHub Fine-grained Personal Access Token",
    },
    {
        "name": "Slack Bot Token",
        "pattern": r'xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}',
        "severity": "critical",
        "description": "Slack Bot User OAuth Token",
    },
    {
        "name": "Slack Webhook URL",
        "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}',
        "severity": "high",
        "description": "Slack Incoming Webhook URL",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r'sk_live_[A-Za-z0-9]{24,}',
        "severity": "critical",
        "description": "Stripe Live Secret Key",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r'pk_live_[A-Za-z0-9]{24,}',
        "severity": "medium",
        "description": "Stripe Live Publishable Key",
    },
    {
        "name": "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "severity": "high",
        "description": "Google API Key",
    },
    {
        "name": "Google OAuth Client Secret",
        "pattern": r'(?i)client_secret["\s:=]+[A-Za-z0-9_\-]{24,}',
        "severity": "high",
        "description": "Google OAuth Client Secret",
    },
    {
        "name": "RSA Private Key",
        "pattern": r'-----BEGIN RSA PRIVATE KEY-----',
        "severity": "critical",
        "description": "RSA Private Key header",
    },
    {
        "name": "EC Private Key",
        "pattern": r'-----BEGIN EC PRIVATE KEY-----',
        "severity": "critical",
        "description": "Elliptic Curve Private Key header",
    },
    {
        "name": "OpenSSH Private Key",
        "pattern": r'-----BEGIN OPENSSH PRIVATE KEY-----',
        "severity": "critical",
        "description": "OpenSSH Private Key header",
    },
    {
        "name": "DSA Private Key",
        "pattern": r'-----BEGIN DSA PRIVATE KEY-----',
        "severity": "critical",
        "description": "DSA Private Key header",
    },
    {
        "name": "PGP Private Key",
        "pattern": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        "severity": "critical",
        "description": "PGP Private Key Block header",
    },
    {
        "name": "JWT Token",
        "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}',
        "severity": "high",
        "description": "JSON Web Token (JWT)",
    },
    {
        "name": "PostgreSQL Connection String",
        "pattern": r'postgres(?:ql)?://[^\s:]+:[^\s@]+@[^\s/]+',
        "severity": "critical",
        "description": "PostgreSQL connection string with credentials",
    },
    {
        "name": "MySQL Connection String",
        "pattern": r'mysql://[^\s:]+:[^\s@]+@[^\s/]+',
        "severity": "critical",
        "description": "MySQL connection string with credentials",
    },
    {
        "name": "MongoDB Connection String",
        "pattern": r'mongodb(?:\+srv)?://[^\s:]+:[^\s@]+@[^\s/]+',
        "severity": "critical",
        "description": "MongoDB connection string with credentials",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        "severity": "critical",
        "description": "SendGrid API Key",
    },
    {
        "name": "Twilio API Key",
        "pattern": r'SK[0-9a-fA-F]{32}',
        "severity": "high",
        "description": "Twilio API Key",
    },
    {
        "name": "Twilio Account SID",
        "pattern": r'AC[0-9a-fA-F]{32}',
        "severity": "medium",
        "description": "Twilio Account SID",
    },
    {
        "name": "Mailgun API Key",
        "pattern": r'key-[0-9a-zA-Z]{32}',
        "severity": "high",
        "description": "Mailgun API Key",
    },
    {
        "name": "Heroku API Key",
        "pattern": r'(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        "severity": "high",
        "description": "Heroku API Key (UUID format)",
    },
    {
        "name": "Generic Secret Assignment",
        "pattern": r'(?i)(?:secret|password|passwd|pwd|token|api_key|apikey|access_key|auth)[\s]*[=:]+[\s]*["\']([A-Za-z0-9/+=_\-]{16,})["\']',
        "severity": "medium",
        "description": "Generic secret or password assignment in code",
    },
    {
        "name": "Authorization Bearer Token",
        "pattern": r'(?i)(?:authorization|bearer)\s*[:=]\s*["\']?Bearer\s+[A-Za-z0-9\-._~+/]+=*["\']?',
        "severity": "high",
        "description": "HTTP Authorization Bearer token",
    },
    {
        "name": "Firebase URL",
        "pattern": r'https://[a-z0-9-]+\.firebaseio\.com',
        "severity": "medium",
        "description": "Firebase Realtime Database URL",
    },
    {
        "name": "Firebase Server Key",
        "pattern": r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        "severity": "critical",
        "description": "Firebase Cloud Messaging Server Key",
    },
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


COMPILED_PATTERNS = []
for p in SECRET_PATTERNS:
    try:
        COMPILED_PATTERNS.append({
            **p,
            "compiled": re.compile(p["pattern"])
        })
    except re.error:
        pass  # skip invalid patterns
