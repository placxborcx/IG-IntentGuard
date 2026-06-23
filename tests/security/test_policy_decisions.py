from __future__ import annotations

from intentguard.models import (
    Decision,
    DiffScanResult,
    FileChangeType,
    RiskLevel,
    ScannedFile,
)
from intentguard.policy import default_policy
from intentguard.policy.decision import (
    FileDecision,
    decide_file,
    decide_scan_result,
    decide_scanned_file,
    summarize_final_decision,
    summarize_overall_risk,
)


def test_blocked_path_gets_block_decision() -> None:
    policy = default_policy()

    result = decide_file(
        path=".env",
        policy=policy,
        allowed_paths=[],
    )

    assert result.path == ".env"
    assert result.decision == Decision.BLOCK
    assert result.risk == RiskLevel.HIGH
    assert "blocked" in result.reason.lower()


def test_blocked_glob_path_gets_block_decision() -> None:
    policy = default_policy()

    result = decide_file(
        path="config/app.secret.yaml",
        policy=policy,
        allowed_paths=[],
    )

    assert result.decision == Decision.BLOCK
    assert result.risk == RiskLevel.HIGH


def test_approval_required_path_gets_require_approval_decision() -> None:
    policy = default_policy()

    result = decide_file(
        path=".github/workflows/deploy.yml",
        policy=policy,
        allowed_paths=[],
    )

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.risk == RiskLevel.HIGH
    assert "approval" in result.reason.lower()


def test_docker_approval_required_path_gets_medium_risk() -> None:
    policy = default_policy()

    result = decide_file(
        path="Dockerfile",
        policy=policy,
        allowed_paths=[],
    )

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.risk == RiskLevel.MEDIUM


def test_out_of_scope_path_gets_warn_out_of_scope_decision() -> None:
    policy = default_policy()

    result = decide_file(
        path="README.md",
        policy=policy,
        allowed_paths=["src/auth/**", "tests/**"],
    )

    assert result.decision == Decision.WARN_OUT_OF_SCOPE
    assert result.risk == RiskLevel.MEDIUM
    assert "outside" in result.reason.lower()


def test_summarize_overall_risk_uses_highest_file_risk() -> None:
    decisions = [
        FileDecision(
            path="README.md",
            risk=RiskLevel.LOW,
            decision=Decision.ALLOW_WITH_AUDIT,
            reason="Allowed by default policy.",
        ),
        FileDecision(
            path="Dockerfile",
            risk=RiskLevel.MEDIUM,
            decision=Decision.REQUIRE_APPROVAL,
            reason="Path requires approval by policy: Dockerfile",
        ),
        FileDecision(
            path=".env",
            risk=RiskLevel.HIGH,
            decision=Decision.BLOCK,
            reason="Path is blocked by policy: .env",
        ),
    ]

    assert summarize_overall_risk(decisions) == RiskLevel.HIGH


def test_summarize_final_decision_uses_strictest_file_decision() -> None:
    decisions = [
        FileDecision(
            path="README.md",
            risk=RiskLevel.LOW,
            decision=Decision.ALLOW_WITH_AUDIT,
            reason="Allowed by default policy.",
        ),
        FileDecision(
            path="docs/notes.md",
            risk=RiskLevel.MEDIUM,
            decision=Decision.WARN_OUT_OF_SCOPE,
            reason="Path is outside the active task scope: docs/notes.md",
        ),
        FileDecision(
            path=".github/workflows/deploy.yml",
            risk=RiskLevel.HIGH,
            decision=Decision.REQUIRE_APPROVAL,
            reason="Path requires approval by policy: .github/workflows/deploy.yml",
        ),
    ]

    assert summarize_final_decision(decisions) == Decision.REQUIRE_APPROVAL


def test_warn_out_of_scope_only_final_decision_allows_with_audit() -> None:
    decisions = [
        FileDecision(
            path="README.md",
            risk=RiskLevel.MEDIUM,
            decision=Decision.WARN_OUT_OF_SCOPE,
            reason="Path is outside the active task scope: README.md",
        )
    ]

    assert summarize_overall_risk(decisions) == RiskLevel.MEDIUM
    assert summarize_final_decision(decisions) == Decision.ALLOW_WITH_AUDIT


def test_allowed_paths_do_not_downgrade_blocked_paths() -> None:
    policy = default_policy()

    result = decide_file(
        path=".env",
        policy=policy,
        allowed_paths=[".env"],
    )

    assert result.decision == Decision.BLOCK
    assert result.risk == RiskLevel.HIGH


def test_approval_required_path_beats_task_drift_warning() -> None:
    policy = default_policy()

    result = decide_file(
        path=".github/workflows/deploy.yml",
        policy=policy,
        allowed_paths=["src/auth/**"],
    )

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.risk == RiskLevel.HIGH


def test_docker_approval_required_path_beats_task_drift_warning() -> None:
    policy = default_policy()

    result = decide_file(
        path="Dockerfile",
        policy=policy,
        allowed_paths=["src/auth/**"],
    )

    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.risk == RiskLevel.MEDIUM


def test_renamed_sensitive_old_path_is_evaluated() -> None:
    policy = default_policy()
    scanned_file = ScannedFile(
        old_path=".env",
        path="README.md",
        change_type=FileChangeType.RENAMED,
        is_staged=True,
    )

    result = decide_scanned_file(
        scanned_file=scanned_file,
        policy=policy,
        allowed_paths=["README.md"],
    )

    assert result.path == "README.md"
    assert result.decision == Decision.BLOCK
    assert result.risk == RiskLevel.HIGH
    assert ".env" in result.reason


def test_decide_scan_result_adds_file_decisions_and_summary() -> None:
    policy = default_policy()
    diff_result = DiffScanResult(
        scan_id="scan_001",
        task_id="task_001",
        is_staged=False,
        git_root="/tmp/repo",
        changed_files=[
            ScannedFile(
                path="README.md",
                change_type=FileChangeType.MODIFIED,
                is_staged=False,
            ),
            ScannedFile(
                path=".env",
                change_type=FileChangeType.MODIFIED,
                is_staged=False,
            ),
        ],
    )

    result = decide_scan_result(
        diff_result=diff_result,
        policy=policy,
        allowed_paths=["README.md"],
    )

    assert result.scan_id == "scan_001"
    assert result.task_id == "task_001"
    assert result.repo_path == "/tmp/repo"
    assert len(result.changed_files) == 2

    assert result.changed_files[0].decision == Decision.ALLOW_WITH_AUDIT
    assert result.changed_files[1].decision == Decision.BLOCK
    assert result.overall_risk == RiskLevel.HIGH
    assert result.final_decision == Decision.BLOCK


def test_secret_finding_blocks_file_decision_without_raw_secret() -> None:
    policy = default_policy()
    raw_secret = "sk-live-raw-secret-value"

    scanned_file = ScannedFile(
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
    )

    result = decide_scanned_file(
        scanned_file=scanned_file,
        policy=policy,
        allowed_paths=["src/**"],
    )

    assert result.decision == Decision.BLOCK
    assert result.risk == RiskLevel.HIGH
    assert "secret" in result.reason.lower()
    assert raw_secret not in result.reason
