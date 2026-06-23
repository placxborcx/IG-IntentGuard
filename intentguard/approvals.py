from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4
from datetime import UTC, datetime, timedelta
from intentguard.audit.log import find_scan_record


def make_approval_id() -> str:
    return f"apr_{uuid4().hex}"


def load_approvals(approvals_path: Path) -> list[dict[str, Any]]:
    if not approvals_path.exists():
        return []

    text = approvals_path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    return json.loads(text)


def save_approvals(
    approvals_path: Path,
    approvals: list[dict[str, Any]],
) -> None:
    approvals_path.parent.mkdir(parents=True, exist_ok=True)
    approvals_path.write_text(
        json.dumps(approvals, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def append_approval(
    approvals_path: Path,
    approval: dict[str, Any],
) -> None:
    approvals = load_approvals(approvals_path)
    approvals.append(approval)
    save_approvals(approvals_path, approvals)


def format_utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


def parse_utc_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_approval_expiry(
    *,
    created_at: datetime,
    ttl_minutes: int,
) -> str:
    expires_at = created_at + timedelta(minutes=ttl_minutes)
    return format_utc_timestamp(expires_at)


def is_approval_expired(
    approval: dict[str, Any],
    *,
    now: datetime,
) -> bool:
    expires_at = parse_utc_timestamp(approval["expires_at"])
    return now.astimezone(UTC) > expires_at


def approval_required_files(scan_record: dict[str, Any]) -> list[str]:
    files: list[str] = []

    for changed_file in scan_record.get("changed_files", []):
        if changed_file.get("decision") == "REQUIRE_APPROVAL":
            files.append(changed_file["path"])

    return files


def build_approval_record(
    *,
    scan_record: dict[str, Any],
    approved_files: list[str],
    approver: str,
    reason: str,
    ttl_minutes: int,
    created_at: datetime,
) -> dict[str, Any]:
    return {
        "approval_id": make_approval_id(),
        "scan_id": scan_record["scan_id"],
        "task_id": scan_record.get("task_id"),
        "approved_files": approved_files,
        "approver": approver,
        "reason": reason,
        "expires_at": build_approval_expiry(
            created_at=created_at,
            ttl_minutes=ttl_minutes,
        ),
        "created_at": format_utc_timestamp(created_at),
    }


def scan_has_blocking_decision(scan_record: dict[str, Any]) -> bool:
    for changed_file in scan_record.get("changed_files", []):
        if changed_file.get("decision") == "BLOCK":
            return True

    return False


def has_valid_approval_for_scan(
    *,
    approvals_path: Path,
    scans_path: Path,
    scan_record: dict[str, Any],
    now: datetime,
) -> bool:
    required_files = approval_required_files(scan_record)

    if not required_files:
        return True

    approvals = load_approvals(approvals_path)

    for approval in approvals:
        if is_approval_expired(approval, now=now):
            continue

        approved_files = approval.get("approved_files", [])
        if sorted(approved_files) != sorted(required_files):
            continue

        approved_scan_id = approval.get("scan_id")
        if not approved_scan_id:
            continue

        approved_scan = find_scan_record(scans_path, approved_scan_id)
        if approved_scan is None:
            continue

        if scan_has_blocking_decision(approved_scan):
            continue

        approved_required_files = approval_required_files(approved_scan)
        if sorted(approved_required_files) == sorted(required_files):
            return True

    return False