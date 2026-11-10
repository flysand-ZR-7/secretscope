"""
OSINT Reconnaissance and Dark Web Threat Intelligence Module.
Inspired by Recon-ng, OnionScan, and Ahmia Domain Extractor.
Features:
- Certificate Transparency (crt.sh) passive subdomain discovery.
- Security headers & misconfiguration scanner (CORS, HSTS, CSP, banner leaks).
- Ahmia Dark Web threat intelligence query for leaked credentials and onion mirrors.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("secretscope.recon")

# Common high-value subdomains to probe
COMMON_SUBDOMAINS = [
    "api", "dev", "staging", "admin", "vpn", "auth",
    "corp", "portal", "test", "internal", "mail", "git"
]


async def query_crtsh_subdomains(domain: str) -> List[str]:
    """
    Passively extracts subdomains from Certificate Transparency logs via crt.sh.
    Never sends network traffic to the target domain directly.
    """
    clean_domain = domain.strip().lower()
    url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"

    discovered = set()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub.endswith(clean_domain) and sub != clean_domain:
                            discovered.add(sub)
    except Exception as exc:
        logger.warning(f"crt.sh reconnaissance failed for '{domain}': {exc}")

    return sorted(list(discovered))


async def check_security_headers(target_url: str) -> List[Dict[str, Any]]:
    """
    Inspects HTTP headers for security misconfigurations and information disclosures
    (inspired by OnionScan and Recon-ng).
    """
    issues: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(target_url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # 1. Missing Content-Security-Policy
            if "content-security-policy" not in headers:
                issues.append({
                    "type": "Missing CSP Header",
                    "severity": "medium",
                    "detail": "No Content-Security-Policy header defined. Vulnerable to XSS injection."
                })

            # 2. Missing Strict-Transport-Security (HSTS)
            if target_url.startswith("https://") and "strict-transport-security" not in headers:
                issues.append({
                    "type": "Missing HSTS Header",
                    "severity": "low",
                    "detail": "Strict-Transport-Security (HSTS) not enforced. Man-in-the-middle downgrade risk."
                })

            # 3. Permissive CORS Wildcard
            cors = headers.get("access-control-allow-origin")
            if cors == "*":
                issues.append({
                    "type": "Wildcard CORS Policy",
                    "severity": "high",
                    "detail": "Access-Control-Allow-Origin is set to '*'. Any external domain can read responses."
                })

            # 4. Server Banner & Technology Leak
            if "x-powered-by" in headers:
                issues.append({
                    "type": "Technology Disclosure (X-Powered-By)",
                    "severity": "low",
                    "detail": f"Server discloses backend technology: {headers['x-powered-by']}"
                })

            server = headers.get("server")
            if server and re.search(r"\d+\.\d+", server):
                issues.append({
                    "type": "Detailed Server Version Disclosure",
                    "severity": "low",
                    "detail": f"Server discloses exact software version: {server}"
                })

    except Exception as exc:
        logger.warning(f"Security headers check failed for '{target_url}': {exc}")

    return issues


async def check_darkweb_breach_mentions(domain: str) -> List[Dict[str, str]]:
    """
    Queries Ahmia for Dark Web and .onion leak discussions referencing the domain.
    """
    clean_domain = domain.strip().lower()
    query = f'"{clean_domain}" password OR leak OR database'
    url = "https://ahmia.fi/search/"

    mentions: List[Dict[str, str]] = []
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(url, params={"q": query})
            if resp.status_code == 200:
                html = resp.text
                pattern = re.compile(
                    r'<li[^>]*class=["\']result["\'][^>]*>.*?<h4><a\s+href=["\']([^"\']+)["\'][^>]*>(.*?)</a></h4>.*?<p>(.*?)</p>',
                    re.DOTALL | re.IGNORECASE
                )
                for match in pattern.finditer(html):
                    raw_url, raw_title, raw_desc = match.groups()
                    clean_title = re.sub(r"<[^>]+>", "", raw_title).strip()
                    clean_desc = re.sub(r"<[^>]+>", "", raw_desc).strip()
                    mentions.append({
                        "url": raw_url.strip(),
                        "title": clean_title,
                        "snippet": clean_desc,
                    })
                    if len(mentions) >= 5:
                        break
    except Exception as exc:
        logger.warning(f"Ahmia dark web lookup failed for '{domain}': {exc}")

    return mentions


async def perform_full_recon(domain: str) -> Dict[str, Any]:
    """
    Runs passive Certificate Transparency discovery, security headers check,
    and Ahmia Dark Web intelligence in parallel.
    """
    target_url = f"https://{domain}" if not domain.startswith("http") else domain
    parsed = urlparse(target_url)
    pure_domain = parsed.netloc.split(":")[0]

    subdomains_task = query_crtsh_subdomains(pure_domain)
    headers_task = check_security_headers(target_url)
    darkweb_task = check_darkweb_breach_mentions(pure_domain)

    subdomains, header_issues, darkweb_mentions = await asyncio.gather(
        subdomains_task, headers_task, darkweb_task
    )

    return {
        "domain": pure_domain,
        "target_url": target_url,
        "subdomain_count": len(subdomains),
        "subdomains": subdomains[:50],  # Return top 50 discovered subdomains
        "header_issues": header_issues,
        "darkweb_mentions_count": len(darkweb_mentions),
        "darkweb_mentions": darkweb_mentions,
    }
