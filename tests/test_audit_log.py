from __future__ import annotations

import json

from intentguard.audit.log import (
    append_audit_event,
    build_audit_event,
    make_event_id,
    make_scan_id,
    utc_timestamp,
)


def test_append_audit_event_writes_jsonl_line(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"

    append_audit_event(
        audit_path=audit_path,
        event={
            "event_id": "evt_001",
            "task_id": None,
            "scan_id": "scan_001",
            "agent": None,
            "action": "scan_completed",
            "target": "scan",
            "risk": "low",
            "decision": "allow_with_audit",
            "reason": "Scan completed.",
            "timestamp": "2026-05-25T04:12:30Z",
        },
    )

    lines = audit_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["event_id"] == "evt_001"
    assert payload["scan_id"] == "scan_001"
    assert payload["action"] == "scan_completed"


def test_append_audit_event_appends_without_overwriting(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"

    append_audit_event(
        audit_path=audit_path,
        event={
            "event_id": "evt_001",
            "task_id": None,
            "scan_id": "scan_001",
            "agent": None,
            "action": "scan_started",
            "target": "scan",
            "risk": "low",
            "decision": "allow_with_audit",
            "reason": "Scan started.",
            "timestamp": "2026-05-25T04:12:30Z",
        },
    )

    append_audit_event(
        audit_path=audit_path,
        event={
            "event_id": "evt_002",
            "task_id": None,
            "scan_id": "scan_001",
            "agent": None,
            "action": "scan_completed",
            "target": "scan",
            "risk": "low",
            "decision": "allow_with_audit",
            "reason": "Scan completed.",
            "timestamp": "2026-05-25T04:12:31Z",
        },
    )

    lines = audit_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0])["event_id"] == "evt_001"
    assert json.loads(lines[1])["event_id"] == "evt_002"


def test_make_event_id_uses_evt_prefix() -> None:
    event_id = make_event_id()

    assert event_id.startswith("evt_")
    assert len(event_id) > len("evt_")


def test_make_scan_id_uses_scan_prefix() -> None:
    scan_id = make_scan_id()

    assert scan_id.startswith("scan_")
    assert len(scan_id) > len("scan_")


def test_utc_timestamp_uses_timezone_explicit_z_suffix() -> None:
    timestamp = utc_timestamp()

    assert timestamp.endswith("Z")
    assert "T" in timestamp


def test_build_audit_event_includes_required_fields() -> None:
    event = build_audit_event(
        task_id=None,
        scan_id="scan_001",
        agent=None,
        action="scan_completed",
        target="scan",
        risk="high",
        decision="block",
        reason="Blocked by policy.",
    )

    assert event["event_id"].startswith("evt_")
    assert event["task_id"] is None
    assert event["scan_id"] == "scan_001"
    assert event["agent"] is None
    assert event["action"] == "scan_completed"
    assert event["target"] == "scan"
    assert event["risk"] == "high"
    assert event["decision"] == "block"
    assert event["reason"] == "Blocked by policy."
    assert event["timestamp"].endswith("Z")
