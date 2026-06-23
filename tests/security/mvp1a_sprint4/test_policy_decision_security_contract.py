from __future__ import annotations

from intentguard.models import Decision, FileChangeType, RiskLevel, ScannedFile
from intentguard.policy import default_policy, validate_policy
from intentguard.policy.decision import (
    FileDecision,
    decide_file,
    decide_scanned_file,
    summarize_final_decision,
)


def make_policy(
    blocked_paths: list[str],
    approval_required_paths: list[str],
):
    return validate_policy(
        {
            "default_decision": "ALLOW_WITH_AUDIT",
            "approval_ttl_minutes": 30,
            "blocked_paths": blocked_paths,
            "approval_required_paths": approval_required_paths,
            "secret_detection": {
                "enabled": True,
                "engine": "builtin",
                "decision": "BLOCK",
            },
        }
    )


def test_blocked_path_beats_task_allowed_paths() -> None:
    policy = make_policy(
        blocked_paths=[".env", ".env.*"],
        approval_required_paths=["src/auth/**"],
    )

    result = decide_file(
        path=".env",
        policy=policy,
        allowed_paths=[".env"],
    )

    assert result.decision.lower() == "block"
    assert result.risk.lower() == "high"


def test_approval_required_beats_task_drift_warning() -> None:
    policy = make_policy(
        blocked_paths=[".env", ".env.*"],
        approval_required_paths=[".github/workflows/**"],
    )

    result = decide_file(
        path=".github/workflows/deploy.yml",
        policy=policy,
        allowed_paths=["src/auth/**"],
    )

    assert result.decision.lower() == "require_approval"


def test_deleted_sensitive_file_is_still_evaluated() -> None:
    policy = make_policy(
        blocked_paths=[".env", ".env.*"],
        approval_required_paths=["src/auth/**"],
    )

    result = decide_file(
        path=".env",
        policy=policy,
        allowed_paths=["src/**"],
    )

    assert result.decision.lower() == "block"


def test_rename_evaluates_old_and_new_paths() -> None:
    policy = make_policy(
        blocked_paths=[".env", ".env.*"],
        approval_required_paths=["src/auth/**"],
    )

    result = decide_scanned_file(
        scanned_file=ScannedFile(
            path="docs/example.env",
            old_path=".env",
            change_type=FileChangeType.RENAMED,
            is_staged=True,
        ),
        policy=policy,
        allowed_paths=["docs/**"],
    )

    assert result.decision.lower() == "block"


def test_final_scan_decision_uses_strictest_file_decision() -> None:
    final = summarize_final_decision(
        [
            FileDecision(
                path="README.md",
                risk=RiskLevel.LOW,
                decision=Decision.ALLOW_WITH_AUDIT,
                reason="allowed",
            ),
            FileDecision(
                path="docs/notes.md",
                risk=RiskLevel.MEDIUM,
                decision=Decision.WARN_OUT_OF_SCOPE,
                reason="warning",
            ),
            FileDecision(
                path=".github/workflows/deploy.yml",
                risk=RiskLevel.HIGH,
                decision=Decision.REQUIRE_APPROVAL,
                reason="approval",
            ),
            FileDecision(
                path=".env",
                risk=RiskLevel.HIGH,
                decision=Decision.BLOCK,
                reason="block",
            ),
        ]
    )

    assert final.lower() == "block"


def test_block_reason_does_not_include_raw_secret_value() -> None:
    raw_secret = "sk-live-raw-secret-value"
    policy = default_policy()

    result = decide_scanned_file(
        scanned_file=ScannedFile(
            path="src/settings.py",
            change_type=FileChangeType.MODIFIED,
            is_staged=False,
            secret_findings=[
                {
                    "path": "src/settings.py",
                    "line_number": 1,
                    "line_type": "added",
                    "pattern_id": "generic_api_key",
                    "redacted_sample": "api_key=<redacted>",
                }
            ],
        ),
        policy=policy,
        allowed_paths=["src/**"],
    )

    assert result.decision == Decision.BLOCK
    assert "secret" in result.reason.lower()
    assert raw_secret not in result.reason
