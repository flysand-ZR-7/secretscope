"""Safe validation of discovered tokens — read-only checks only."""
import httpx
import logging

logger = logging.getLogger("secretscope.validator")


async def validate_github_token(token: str) -> tuple[bool, str]:
    """Check if a GitHub token is valid via /user endpoint."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"token {token}",
                    "User-Agent": "SecretScope-Validator/1.0",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                login = data.get("login", "unknown")
                scopes = resp.headers.get("X-OAuth-Scopes", "none")
                return True, f"Valid token for user '{login}', scopes: {scopes}"
            return False, f"Invalid or expired (HTTP {resp.status_code})"
    except Exception as e:
        return False, f"Validation error: {e}"


async def validate_aws_key(access_key: str, secret_key: str) -> tuple[bool, str]:
    """Check AWS credentials via STS GetCallerIdentity."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        client = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        identity = client.get_caller_identity()
        account = identity.get("Account", "unknown")
        arn = identity.get("Arn", "unknown")
        return True, f"Valid AWS key — Account: {account}, ARN: {arn}"
    except (ClientError, NoCredentialsError):
        return False, "Invalid or expired AWS credentials"
    except ImportError:
        return False, "boto3 not installed — cannot validate AWS keys"
    except Exception as e:
        return False, f"Validation error: {e}"


async def validate_slack_webhook(url: str) -> tuple[bool, str]:
    """Check Slack webhook by posting a harmless empty-text message."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.post(url, json={"text": ""})
            if resp.status_code == 200:
                return True, "Webhook is active (accepted empty payload)"
            if resp.status_code in (400, 403):
                # 400 = "no_text" means webhook exists but rejected empty text
                return True, "Webhook exists (returned expected error for empty text)"
            return False, f"Webhook may be invalid (HTTP {resp.status_code})"
    except Exception as e:
        return False, f"Validation error: {e}"


async def try_validate_finding(pattern_name: str, raw_value: str) -> tuple[bool, str]:
    """Attempt safe, non-destructive validation based on pattern name."""
    clean_val = raw_value.strip().strip("'\"")
    if "Slack Webhook" in pattern_name:
        return await validate_slack_webhook(clean_val)
    elif "GitHub" in pattern_name and ("Token" in pattern_name or "PAT" in pattern_name):
        return await validate_github_token(clean_val)
    return False, ""
