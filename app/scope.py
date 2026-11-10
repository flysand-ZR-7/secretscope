"""Scope management — only scan authorized domains."""
import fnmatch
import os
import logging
from pathlib import Path

logger = logging.getLogger("secretscope.scope")

SCOPE_FILE = Path(__file__).parent.parent / "scope.txt"


class ScopeManager:
    """Manages the allowlist of authorized scan targets."""

    def __init__(self):
        self.domains: list[str] = []
        self.load()

    def load(self):
        """Load domains from scope.txt."""
        self.domains = []
        if SCOPE_FILE.exists():
            for line in SCOPE_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.domains.append(line.lower())
        logger.info(f"Scope loaded: {len(self.domains)} domain(s)")

    def save(self):
        """Save current domains to scope.txt."""
        lines = [
            "# SecretScope — Allowed target domains (one per line, supports *.example.com wildcards)",
            "# Modify via the /api/scope endpoint or edit this file directly.",
            "",
        ]
        lines.extend(self.domains)
        SCOPE_FILE.write_text("\n".join(lines) + "\n")

    def add_domain(self, domain: str):
        """Add a domain to scope."""
        d = domain.strip().lower()
        if d and d not in self.domains:
            self.domains.append(d)
            self.save()

    def remove_domain(self, domain: str):
        """Remove a domain from scope."""
        d = domain.strip().lower()
        self.domains = [x for x in self.domains if x != d]
        self.save()

    def set_domains(self, domains: list[str]):
        """Replace the entire domain list."""
        self.domains = [d.strip().lower() for d in domains if d.strip()]
        self.save()

    def is_in_scope(self, target: str) -> bool:
        """Check if a target (domain or URL) is within the allowed scope.
        Returns True if scope is empty (unrestricted) or target matches.
        """
        if not self.domains:
            return True  # No scope set = allow all (with warning)

        target_lower = target.lower()
        # Extract domain from URL if needed
        if "://" in target_lower:
            from urllib.parse import urlparse
            target_lower = urlparse(target_lower).hostname or target_lower

        for allowed in self.domains:
            if fnmatch.fnmatch(target_lower, allowed):
                return True
            # Also check if target is a subdomain of allowed domain
            if not allowed.startswith("*") and target_lower.endswith("." + allowed):
                return True
            if target_lower == allowed:
                return True

        return False

    def get_domains(self) -> list[str]:
        """Return current scope list."""
        return list(self.domains)


# Singleton instance
scope_manager = ScopeManager()
