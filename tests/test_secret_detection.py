from __future__ import annotations

from intentguard.secrets import (
    SecretFinding,
    detect_secrets_in_text,
    secret_finding_reason,
)

def test_secret_finding_does_not_store_raw_secret_value() -> None:
    raw_secret = "sk-live-raw-secret-value"

    findings = detect_secrets_in_text(
        path="src/settings.py",
        text=f'OPENAI_API_KEY = "{raw_secret}"',
    )

    assert len(findings) == 1
    finding = findings[0]

    assert finding.path == "src/settings.py"
    assert finding.pattern_id == "generic_api_key"
    assert finding.line_type == "added"
    assert finding.redacted_sample == "api_key=<redacted>"
    assert raw_secret not in repr(finding)
    assert raw_secret not in str(finding)



def test_secret_reason_does_not_include_raw_secret_value() -> None:
    raw_secret = "sk-live-raw-secret-value"

    findings = detect_secrets_in_text(
        path="src/settings.py",
        text=f'OPENAI_API_KEY = "{raw_secret}"',
    )

    reason = secret_finding_reason(findings[0])

    assert "secret" in reason.lower()
    assert raw_secret not in reason


def test_normal_text_has_no_secret_findings() -> None:
    findings = detect_secrets_in_text(
        path="README.md",
        text="This is normal documentation without credentials.",
    )

    assert findings == []


def test_detects_aws_access_key_id() -> None:
    findings = detect_secrets_in_text(
        path="src/settings.py",
        text='AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"',
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "aws_access_key_id"
    assert findings[0].redacted_sample == "aws_access_key_id=<redacted>"


def test_detects_aws_secret_access_key_assignment() -> None:
    findings = detect_secrets_in_text(
        path="src/settings.py",
        text='aws_secret_access_key = "abc123secretvalue"',
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "aws_secret_access_key"
    assert findings[0].redacted_sample == "aws_secret_access_key=<redacted>"


def test_detects_private_key_block_header() -> None:
    findings = detect_secrets_in_text(
        path="keys/private.pem",
        text="-----BEGIN OPENSSH PRIVATE KEY-----",
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "private_key_block"
    assert findings[0].redacted_sample == "private_key=<redacted>"


def test_detects_github_token_prefix() -> None:
    findings = detect_secrets_in_text(
        path="src/settings.py",
        text='GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"',
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "github_token"
    assert findings[0].redacted_sample == "github_token=<redacted>"


def test_detects_client_secret_assignment() -> None:
    findings = detect_secrets_in_text(
        path="src/settings.py",
        text='CLIENT_SECRET = "client-secret-value"',
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "generic_client_secret"
    assert findings[0].redacted_sample == "client_secret=<redacted>"


def test_detects_access_token_assignment() -> None:
    findings = detect_secrets_in_text(
        path="src/settings.py",
        text='ACCESS_TOKEN = "access-token-value"',
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "generic_token"
    assert findings[0].redacted_sample == "token=<redacted>"


def test_detects_auth_token_assignment() -> None:
    findings = detect_secrets_in_text(
        path="src/settings.py",
        text='AUTH_TOKEN = "auth-token-value"',
    )

    assert len(findings) == 1
    assert findings[0].pattern_id == "generic_token"
    assert findings[0].redacted_sample == "token=<redacted>"
