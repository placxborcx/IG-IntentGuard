from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class SecretFinding:
    path: str
    line_number: int | None
    line_type: str
    pattern_id: str
    redacted_sample: str


SECRET_PATTERNS = [
    (
        "aws_secret_access_key",
        "aws_secret_access_key=<redacted>",
        re.compile(
            r"(?i)\baws_secret_access_key\s*=\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "aws_access_key_id",
        "aws_access_key_id=<redacted>",
        re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "github_token",
        "github_token=<redacted>",
        re.compile(r"\b(ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "private_key_block",
        "private_key=<redacted>",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "generic_client_secret",
        "client_secret=<redacted>",
        re.compile(
            r"(?i)\b[\w-]*client[_-]?secret\s*=\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "generic_api_key",
        "api_key=<redacted>",
        re.compile(
            r"(?i)\b[\w-]*api[_-]?key\s*=\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "generic_password",
        "password=<redacted>",
        re.compile(
            r"(?i)\b[\w-]*password\s*=\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "generic_secret",
        "secret=<redacted>",
        re.compile(
            r"(?i)\b[\w-]*secret\s*=\s*['\"][^'\"]+['\"]"
        ),
    ),
    (
        "generic_token",
        "token=<redacted>",
        re.compile(
            r"(?i)\b[\w-]*token\s*=\s*['\"][^'\"]+['\"]"
        ),
    ),
]


def detect_secrets_in_text(path: str, text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern_id, redacted_sample, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    SecretFinding(
                        path=path,
                        line_number=line_number,
                        line_type="added",
                        pattern_id=pattern_id,
                        redacted_sample=redacted_sample,
                    )
                )
                break

    return findings


def secret_finding_reason(finding: SecretFinding) -> str:
    return (
        f"Blocked: secret-like value detected in changed line for '{finding.path}'. "
        f"Reason: matched built-in secret pattern '{finding.pattern_id}'; "
        "value redacted. "
        "This change cannot be approved through in MVP1a."
    )
