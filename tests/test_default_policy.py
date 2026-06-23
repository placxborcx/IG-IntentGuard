from __future__ import annotations

import yaml

import pytest

from intentguard.policy import PolicyValidationError, default_policy, default_policy_text, validate_policy


def test_default_policy_contains_required_hard_block_paths() -> None:
    policy = default_policy()

    assert policy.blocked_paths == [
        ".env",
        ".env.*",
        "**/*secret*",
        "**/*iam*.json",
    ]


def test_default_policy_contains_required_approval_paths() -> None:
    policy = default_policy()

    assert policy.approval_required_paths == [
        ".github/workflows/**",
        "terraform/**",
        "infra/**",
        "Dockerfile",
        "docker-compose.yml",
        "src/auth/**",
    ]


def test_default_policy_secret_detection_blocks() -> None:
    policy = default_policy()

    assert policy.secret_detection.enabled is True
    assert policy.secret_detection.engine == "builtin"
    assert policy.secret_detection.decision == "BLOCK"


def test_default_policy_paths_are_mutually_exclusive() -> None:
    policy = default_policy()

    assert set(policy.blocked_paths).isdisjoint(policy.approval_required_paths)


def test_overlapping_blocked_and_approval_paths_are_invalid() -> None:
    data = yaml.safe_load(default_policy_text())
    data["approval_required_paths"].append(".env")

    with pytest.raises(PolicyValidationError, match="appears in both blocked_paths"):
        validate_policy(data)
