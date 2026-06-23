from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from intentguard.models import (
    ChangedFile,
    ChangeType,
    Decision,
    DiffScanResult,
    FileChangeType,
    RiskLevel,
    ScanResult,
    ScannedFile,
)
from intentguard.policy import Policy

MEDIUM_APPROVAL_PATHS = {"Dockerfile", "docker-compose.yml"}

DECISION_STRENGTH = {
    Decision.ALLOW_WITH_AUDIT: 0,
    Decision.WARN_OUT_OF_SCOPE: 1,
    Decision.REQUIRE_APPROVAL: 2,
    Decision.BLOCK: 3,
}


def to_change_type(change_type: FileChangeType) -> ChangeType:
    if change_type == FileChangeType.ADDED:
        return ChangeType.ADDED
    if change_type == FileChangeType.DELETED:
        return ChangeType.DELETED
    return ChangeType.MODIFIED


@dataclass
class FileDecision:
    path: str
    risk: RiskLevel
    decision: Decision
    reason: str


def decide_file(
    path: str,
    policy: Policy,
    allowed_paths: list[str],
) -> FileDecision:
    if matches_any_path(path, policy.blocked_paths):
        return FileDecision(
            path=path,
            risk=RiskLevel.HIGH,
            decision=Decision.BLOCK,
            reason=f"Path is blocked by policy: {path}",
        )

    if matches_any_path(path, policy.approval_required_paths):
        return FileDecision(
            path=path,
            risk=approval_required_risk(path),
            decision=Decision.REQUIRE_APPROVAL,
            reason=f"Path requires approval by policy: {path}",
        )

    if allowed_paths and not matches_any_path(path, allowed_paths):
        return FileDecision(
            path=path,
            risk=RiskLevel.MEDIUM,
            decision=Decision.WARN_OUT_OF_SCOPE,
            reason=f"Path is outside the active task scope: {path}",
        )

    return FileDecision(
        path=path,
        risk=RiskLevel.LOW,
        decision=Decision.ALLOW_WITH_AUDIT,
        reason="Allowed by default policy.",
    )


def matches_any_path(path: str, patterns: list[str]) -> bool:
    return any(fnmatch(path, pattern) for pattern in patterns)


def approval_required_risk(path: str) -> RiskLevel:
    if path in MEDIUM_APPROVAL_PATHS:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def summarize_overall_risk(decisions: list[FileDecision]) -> RiskLevel:
    risks = [decision.risk for decision in decisions]

    if RiskLevel.HIGH in risks:
        return RiskLevel.HIGH
    if RiskLevel.MEDIUM in risks:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def summarize_final_decision(decisions: list[FileDecision]) -> Decision:
    file_decisions = [decision.decision for decision in decisions]

    if Decision.BLOCK in file_decisions:
        return Decision.BLOCK
    if Decision.REQUIRE_APPROVAL in file_decisions:
        return Decision.REQUIRE_APPROVAL
    return Decision.ALLOW_WITH_AUDIT


def decide_scanned_file(
    scanned_file: ScannedFile,
    policy: Policy,
    allowed_paths: list[str],
) -> FileDecision:
    if scanned_file.secret_findings:
        pattern_id = scanned_file.secret_findings[0].get(
            "pattern_id",
            "unknown_secret_pattern",
        )
        return FileDecision(
            path=scanned_file.path,
            risk=RiskLevel.HIGH,
            decision=Decision.BLOCK,
            reason=(
                "Blocked: secret-like value detected in changed line for "
                f"'{scanned_file.path}'. "
                f"Reason: matched built-in secret pattern '{pattern_id}'; "
                "value redacted. "
                "This change cannot be approved through in MVP1a."
            ),
        )
    decisions = [
        decide_file(
            path=scanned_file.path,
            policy=policy,
            allowed_paths=allowed_paths,
        )
    ]

    if scanned_file.old_path:
        decisions.append(
            decide_file(
                path=scanned_file.old_path,
                policy=policy,
                allowed_paths=allowed_paths,
            )
        )

    strictest = max(
        decisions,
        key=lambda decision: DECISION_STRENGTH[decision.decision],
    )

    if scanned_file.old_path and strictest.path == scanned_file.old_path:
        return FileDecision(
            path=scanned_file.path,
            risk=strictest.risk,
            decision=strictest.decision,
            reason=(
                f"{strictest.reason} Original path {scanned_file.old_path} "
                f"was evaluated for renamed/copied file {scanned_file.path}."
            ),
        )

    return strictest


def decide_scan_result(
    diff_result: DiffScanResult,
    policy: Policy,
    allowed_paths: list[str],
) -> ScanResult:
    changed_files: list[ChangedFile] = []

    for scanned_file in diff_result.changed_files:
        file_decision = decide_scanned_file(
            scanned_file=scanned_file,
            policy=policy,
            allowed_paths=allowed_paths,
        )

        changed_files.append(
            ChangedFile(
                path=scanned_file.path,
                change_type=to_change_type(scanned_file.change_type),
                risk=file_decision.risk,
                decision=file_decision.decision,
                reason=file_decision.reason,
            )
        )

    return ScanResult(
        scan_id=diff_result.scan_id,
        task_id=diff_result.task_id,
        repo_path=diff_result.git_root or "",
        changed_files=changed_files,
        overall_risk=summarize_overall_risk(
            [
                FileDecision(
                    path=file.path,
                    risk=file.risk,
                    decision=file.decision,
                    reason=file.reason,
                )
                for file in changed_files
            ]
        ),
        final_decision=summarize_final_decision(
            [
                FileDecision(
                    path=file.path,
                    risk=file.risk,
                    decision=file.decision,
                    reason=file.reason,
                )
                for file in changed_files
            ]
        ),
    )
