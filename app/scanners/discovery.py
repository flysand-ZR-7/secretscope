"""URL and path discovery module."""
import httpx
import asyncio
import re
import urllib.parse
import logging

logger = logging.getLogger("secretscope.discovery")

INTERESTING_EXTENSIONS = {
    ".js", ".json", ".env", ".config", ".yml", ".yaml", ".xml",
    ".toml", ".cfg", ".conf", ".properties", ".sql", ".log",
    ".bak", ".backup", ".old", ".txt",
}

INTERESTING_SEGMENTS = [
    "/api/", "/admin/", "/config/", "/backup/", "/internal/",
    "/debug/", "/swagger", "/graphql", "/v1/", "/v2/", "/v3/",
    "/.env", "/wp-config", "/.git/",
]


async def wayback_urls(domain: str) -> list[str]:
    """Query the Wayback Machine CDX API for archived URLs of a domain."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0), follow_redirects=True
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if not data:
                return []
            # First row is headers, rest are data rows
            urls = list({row[0] for row in data[1:]})
            return urls
    except Exception as e:
        logger.warning(f"Wayback Machine query failed for {domain}: {e}")
        return []


def extract_js_urls(html_content: str, base_url: str) -> list[str]:
    """Extract JavaScript URLs from HTML content."""
    pattern = r'''(?:src|href)\s*=\s*["']([^"']*\.js(?:\?[^"']*)?)["']'''
    matches = re.findall(pattern, html_content)
    urls: list[str] = []
    seen: set[str] = set()
    for match in matches:
        resolved = urllib.parse.urljoin(base_url, match)
        if resolved not in seen:
            seen.add(resolved)
            urls.append(resolved)
    return urls


def interesting_paths(urls: list[str]) -> list[str]:
    """Filter URLs that match interesting file extensions or path segments."""
    results: list[str] = []
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()

        # Check file extensions
        has_interesting_ext = any(path.endswith(ext) for ext in INTERESTING_EXTENSIONS)

        # Check path segments
        has_interesting_segment = any(seg in path for seg in INTERESTING_SEGMENTS)

        if has_interesting_ext or has_interesting_segment:
            results.append(url)

    return results
