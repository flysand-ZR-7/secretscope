"""Core scan engine — pattern matching and entropy analysis."""
import re
from app.scanners.patterns import COMPILED_PATTERNS, shannon_entropy
from app.scanners.fetcher import fetch_many
from app.scanners.validator import try_validate_finding
from app.models import Finding


def scan_content(url: str, content: str) -> list[Finding]:
    """Scan content for secret patterns, returning a list of Finding objects."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for p in COMPILED_PATTERNS:
        for match in p["compiled"].finditer(content):
            line_number = content[: match.start()].count("\n") + 1

            # Extract context snippet: 50 chars before and after
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context_snippet = content[start:end]
            context_snippet = re.sub(r"\s+", " ", context_snippet).strip()

            # Build redacted value
            matched_text = match.group(0)
            if len(matched_text) > 8:
                redacted_value = matched_text[:4] + "****" + matched_text[-4:]
            else:
                redacted_value = "****"

            # Entropy check for generic patterns
            if p["name"] == "Generic Secret Assignment":
                try:
                    secret_value = match.group(1)
                except IndexError:
                    secret_value = matched_text
                if shannon_entropy(secret_value) < 3.5:
                    continue

            # Deduplicate by (pattern_name, line_number)
            key = (p["name"], line_number)
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                Finding(
                    scan_id=None,
                    url=url,
                    pattern_name=p["name"],
                    severity=p["severity"],
                    redacted_value=redacted_value,
                    line_number=line_number,
                    context_snippet=context_snippet,
                    validated=False,
                    validation_note="",
                )
            )

    return findings


async def scan_content_with_validation(url: str, content: str) -> list[Finding]:
    """Scan content and asynchronously validate candidate secrets."""
    findings = scan_content(url, content)
    # Perform read-only validation check on findings where supported
    for f in findings:
        val, note = await try_validate_finding(f.pattern_name, f.context_snippet)
        if val:
            f.validated = True
            f.validation_note = note
    return findings


async def scan_urls(urls: list[str]) -> list[Finding]:
    """Fetch multiple URLs and scan their content for secrets."""
    results = await fetch_many(urls)
    all_findings: list[Finding] = []
    for url, content in results.items():
        all_findings.extend(scan_content(url, content))
    return all_findings
