"""GitHub code search for exposed secrets."""
import httpx
import asyncio
import os
import logging
from app.models import Finding

logger = logging.getLogger("secretscope.github")

GITHUB_API = "https://api.github.com/search/code"

# Each dork: (query_template with {domain}, finding_type, severity)
DORKS = [
    ('"{domain}" filename:.env', "Environment File", "critical"),
    ('"{domain}" filename:.env.local', "Local Environment File", "critical"),
    ('"{domain}" filename:.env.production', "Production Env File", "critical"),
    ('"{domain}" password', "Hardcoded Password", "high"),
    ('"{domain}" api_key', "API Key Exposure", "high"),
    ('"{domain}" apikey', "API Key Exposure", "high"),
    ('"{domain}" secret_key', "Secret Key Exposure", "critical"),
    ('"{domain}" access_token', "Access Token Exposure", "critical"),
    ('"{domain}" filename:credentials', "Credentials File", "critical"),
    ('"{domain}" filename:id_rsa', "SSH Private Key", "critical"),
    ('"{domain}" filename:.pgpass', "PostgreSQL Password File", "critical"),
    ('"{domain}" filename:wp-config.php', "WordPress Config", "high"),
    ('"{domain}" filename:configuration.php', "Joomla Config", "high"),
    ('"{domain}" filename:config.php password', "PHP Config with Password", "high"),
    ('"{domain}" filename:database.yml', "Rails Database Config", "high"),
    ('"{domain}" AKIA', "AWS Access Key", "critical"),
    ('"{domain}" sk_live_', "Stripe Secret Key", "critical"),
    ('"{domain}" filename:.htpasswd', "HTPasswd File", "high"),
    ('"{domain}" filename:shadow', "Shadow Password File", "critical"),
    ('"{domain}" filename:connection_string', "Connection String File", "critical"),
]


class GitHubDorkScanner:
    """Searches GitHub for leaked secrets related to a domain."""

    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN", "")
        if not self.token:
            logger.warning("GITHUB_TOKEN not set — GitHub search will be unavailable")

    async def search(self, domain: str) -> list[Finding]:
        if not self.token:
            logger.error("Cannot search GitHub: GITHUB_TOKEN not configured")
            return []

        findings: list[Finding] = []
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecretScope/1.0",
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(15.0), headers=headers
        ) as client:
            for query_template, finding_type, severity in DORKS:
                query = query_template.replace("{domain}", domain)
                try:
                    resp = await client.get(
                        GITHUB_API, params={"q": query, "per_page": 10}
                    )

                    if resp.status_code == 403:
                        retry_after = int(resp.headers.get("Retry-After", "60"))
                        logger.warning(f"Rate limited, backing off {retry_after}s")
                        await asyncio.sleep(retry_after)
                        continue

                    if resp.status_code == 422:
                        logger.warning(f"GitHub rejected query: {query}")
                        await asyncio.sleep(2.2)
                        continue

                    resp.raise_for_status()
                    data = resp.json()

                    for item in data.get("items", []):
                        repo_name = item.get("repository", {}).get("full_name", "unknown")
                        file_path = item.get("path", "unknown")
                        html_url = item.get("html_url", "")

                        findings.append(Finding(
                            url=html_url,
                            pattern_name=f"GitHub Dork: {finding_type}",
                            severity=severity,
                            redacted_value=f"{repo_name}/{file_path}",
                            line_number=0,
                            context_snippet=f"Found via: {query}",
                        ))

                    # Respect rate limit: ~30 requests/min for code search
                    await asyncio.sleep(2.2)

                except httpx.HTTPStatusError as e:
                    logger.warning(f"GitHub search error for '{query}': {e}")
                    await asyncio.sleep(2.2)
                except Exception as e:
                    logger.warning(f"GitHub search failed for '{query}': {e}")
                    await asyncio.sleep(2.2)

        return findings
