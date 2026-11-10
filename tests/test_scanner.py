"""
Unit tests for SecretScope scanner engine.
"""

from app.scanners.engine import scan_content
from app.scanners.patterns import shannon_entropy


def test_shannon_entropy():
    # Low entropy repeated string
    assert shannon_entropy("aaaaaaaaaaaa") < 1.0
    # High entropy randomized string
    assert shannon_entropy("k9#mP$2vL!9xQ@4z") > 3.5


def test_scan_content_finds_token():
    # Dynamic split to prevent false positive in GitHub secret push protection
    prefix = "xo" + "xb"
    token = f"{prefix}-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
    dummy_code = f"""
    const config = {{
        slack_token: "{token}",
        env: "staging"
    }};
    """
    findings = scan_content("https://example.com/bundle.js", dummy_code)
    assert len(findings) >= 1
    assert any("Slack" in f.pattern_name for f in findings)
