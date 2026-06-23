from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from datetime import UTC, datetime
from uuid import uuid4

from intentguard.models import ScanResult


def append_audit_event(audit_path: Path, event: dict[str, Any]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    with audit_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, sort_keys=True))
        file.write("\n")



def make_event_id() -> str:
    return f"evt_{uuid4().hex}"


def make_scan_id() -> str:
    return f"scan_{uuid4().hex}"


def utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_audit_event(
    *,
    task_id: str | None,
    scan_id: str | None,
    agent: str | None,
    action: str,
    target: str,
    risk: str,
    decision: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "event_id": make_event_id(),
        "task_id": task_id,
        "scan_id": scan_id,
        "agent": agent,
        "action": action,
        "target": target,
        "risk": risk,
        "decision": decision,
        "reason": reason,
        "timestamp": utc_timestamp(),
    }


def append_scan_record(records_path: Path, scan_result: ScanResult) -> None:
    records_path.parent.mkdir(parents=True, exist_ok=True)

    with records_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(scan_result.model_dump(mode="json"), sort_keys=True))
        file.write("\n")


def find_scan_record(records_path: Path, scan_id: str) -> dict[str, Any] | None:
    if not records_path.exists():
        return None

    for line in records_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        payload = json.loads(line)
        if payload.get("scan_id") == scan_id:
            return payload

    return None
