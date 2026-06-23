from __future__ import annotations

import json

from intentguard.models import ChangeType, ChangedFile, Decision, RiskLevel, ScanResult
from intentguard.audit.log import append_scan_record, find_scan_record


def test_append_scan_record_writes_jsonl_line(tmp_path) -> None:
    records_path = tmp_path / "scans.jsonl"
    scan = ScanResult(
        scan_id="scan_001",
        task_id="task_001",
        repo_path="/tmp/repo",
        changed_files=[
            ChangedFile(
                path="README.md",
                change_type=ChangeType.MODIFIED,
                risk=RiskLevel.LOW,
                decision=Decision.ALLOW_WITH_AUDIT,
                reason="Allowed by default policy.",
            )
        ],
    )

    append_scan_record(records_path=records_path, scan_result=scan)

    lines = records_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    payload = json.loads(lines[0])
    assert payload["scan_id"] == "scan_001"
    assert payload["task_id"] == "task_001"
    assert payload["changed_files"][0]["path"] == "README.md"


def test_find_scan_record_returns_matching_scan_by_id(tmp_path) -> None:
    records_path = tmp_path / "scans.jsonl"

    first = ScanResult(
        scan_id="scan_001",
        task_id=None,
        repo_path="/tmp/repo",
    )
    second = ScanResult(
        scan_id="scan_002",
        task_id=None,
        repo_path="/tmp/repo",
    )

    append_scan_record(records_path=records_path, scan_result=first)
    append_scan_record(records_path=records_path, scan_result=second)

    found = find_scan_record(records_path=records_path, scan_id="scan_002")

    assert found is not None
    assert found["scan_id"] == "scan_002"


def test_find_scan_record_returns_none_when_missing(tmp_path) -> None:
    records_path = tmp_path / "scans.jsonl"

    found = find_scan_record(records_path=records_path, scan_id="scan_missing")

    assert found is None