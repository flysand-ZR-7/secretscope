"""
Unit tests for OSINT reconnaissance and threat intelligence module.
"""

import pytest
import respx
from httpx import Response

from app.scanners.recon import (
    query_crtsh_subdomains,
    check_security_headers,
    check_darkweb_breach_mentions,
    perform_full_recon,
)


@pytest.mark.asyncio
@respx.mock
async def test_crtsh_subdomains():
    crt_data = [
        {"name_value": "api.example.com\nadmin.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "example.com"},
    ]
    respx.get("https://crt.sh/?q=%25.example.com&output=json").mock(
        return_value=Response(200, json=crt_data)
    )

    subs = await query_crtsh_subdomains("example.com")
    assert "api.example.com" in subs
    assert "admin.example.com" in subs
    assert "dev.example.com" in subs
    assert "example.com" not in subs  # root domain excluded


@pytest.mark.asyncio
@respx.mock
async def test_check_security_headers():
    respx.get("https://example.com").mock(
        return_value=Response(
            200,
            headers={
                "Server": "Apache/2.4.49",
                "X-Powered-By": "PHP/7.4.3",
                "Access-Control-Allow-Origin": "*",
            },
        )
    )

    issues = await check_security_headers("https://example.com")
    types = [i["type"] for i in issues]

    assert "Missing CSP Header" in types
    assert "Wildcard CORS Policy" in types
    assert "Technology Disclosure (X-Powered-By)" in types
    assert "Detailed Server Version Disclosure" in types


@pytest.mark.asyncio
@respx.mock
async def test_check_darkweb_breach_mentions():
    ahmia_html = """
    <html>
      <body>
        <ol class="searchResults">
          <li class="result">
            <h4><a href="http://leaks789onion.onion/data">Example.com Database Dump</a></h4>
            <p>Customer accounts and credentials table dump.</p>
          </li>
        </ol>
      </body>
    </html>
    """
    respx.get("https://ahmia.fi/search/").mock(
        return_value=Response(200, text=ahmia_html)
    )

    mentions = await check_darkweb_breach_mentions("example.com")
    assert len(mentions) == 1
    assert "leaks789onion.onion" in mentions[0]["url"]
    assert "Database Dump" in mentions[0]["title"]
