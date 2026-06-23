from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from intentguard.policy import default_policy_text


def load_default_policy_data() -> dict:
    data = yaml.safe_load(default_policy_text())
    assert isinstance(data, dict)
    return data


def test_sprint1_default_policy_is_external_yaml_artifact() -> None:
    """Security doc: default policy rules should remain reviewable in YAML."""
    policy_path = Path("intentguard/policies/policy.yaml")

    assert policy_path.exists()
    assert policy_path.read_text(encoding="utf-8") == default_policy_text()


def test_sprint1_default_policy_hard_blocks_sensitive_paths() -> None:
    policy = load_default_policy_data()

    for pattern in [".env", ".env.*", "**/*secret*", "**/*iam*.json"]:
        assert pattern in policy["blocked_paths"]


def test_sprint1_default_policy_requires_approval_for_high_risk_engineering_paths() -> None:
    policy = load_default_policy_data()

    for pattern in [
        ".github/workflows/**",
        "terraform/**",
        "infra/**",
        "Dockerfile",
        "docker-compose.yml",
        "src/auth/**",
    ]:
        assert pattern in policy["approval_required_paths"]


def test_sprint1_default_policy_has_no_approval_unlock_for_hard_blocks() -> None:
    policy = load_default_policy_data()

    assert set(policy["blocked_paths"]).isdisjoint(policy["approval_required_paths"])


def test_sprint1_default_policy_uses_uppercase_decision_contract() -> None:
    policy = load_default_policy_data()

    assert policy["default_decision"] == "ALLOW_WITH_AUDIT"
    assert policy["secret_detection"]["decision"] == "BLOCK"


def test_sprint1_allowed_decision_values_are_canonical_uppercase() -> None:
    allowed_decisions = {
        "BLOCK",
        "REQUIRE_APPROVAL",
        "ALLOW_WITH_AUDIT",
        "WARN_OUT_OF_SCOPE",
    }
    policy = load_default_policy_data()

    assert policy["default_decision"] in allowed_decisions
    assert policy["secret_detection"]["decision"] in allowed_decisions


def test_sprint1_policy_lists_do_not_contain_empty_patterns() -> None:
    policy = load_default_policy_data()

    for key in ["blocked_paths", "approval_required_paths"]:
        assert all(isinstance(pattern, str) and pattern.strip() for pattern in policy[key])


def test_sprint1_policy_lists_do_not_contain_duplicate_patterns() -> None:
    policy = load_default_policy_data()

    for key in ["blocked_paths", "approval_required_paths"]:
        assert len(policy[key]) == len(set(policy[key]))


@pytest.mark.parametrize("decision", ["Block", "block", "Require_Approval"])
def test_sprint1_mixed_or_lowercase_decisions_are_not_canonical(decision: str) -> None:
    allowed_decisions = {
        "BLOCK",
        "REQUIRE_APPROVAL",
        "ALLOW_WITH_AUDIT",
        "WARN_OUT_OF_SCOPE",
    }

    assert decision not in allowed_decisions
