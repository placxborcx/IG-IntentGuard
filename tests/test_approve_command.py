from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from intentguard.cli import app
from intentguard.policy import write_default_policy


def test_approve_command_stores_scan_level_approval(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()

        write_default_policy(intentguard_dir / "policy.yaml")
        (intentguard_dir / "approvals.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan = {
            "scan_id": "scan_001",
            "task_id": "task_001",
            "repo_path": str(cwd),
            "changed_files": [
                {
                    "path": ".github/workflows/deploy.yml",
                    "change_type": "modified",
                    "risk": "high",
                    "decision": "REQUIRE_APPROVAL",
                    "reason": "Path requires approval by policy.",
                }
            ],
            "overall_risk": "high",
            "final_decision": "REQUIRE_APPROVAL",
            "created_at": "2026-05-26T10:00:00Z",
        }

        (intentguard_dir / "scans.jsonl").write_text(
            json.dumps(scan) + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["approve", "scan_001"])

        assert result.exit_code == 0
        assert "approved scan scan_001" in result.output
        assert "approved files:" in result.output
        assert "- .github/workflows/deploy.yml" in result.output

        approvals = json.loads(
            (intentguard_dir / "approvals.json").read_text(encoding="utf-8")
        )

        assert len(approvals) == 1
        assert approvals[0]["approval_id"].startswith("apr_")
        assert approvals[0]["scan_id"] == "scan_001"
        assert approvals[0]["task_id"] == "task_001"
        assert approvals[0]["approved_files"] == [".github/workflows/deploy.yml"]
        assert approvals[0]["approver"] == "human"
        assert approvals[0]["reason"] == "Manual review approved."
        assert approvals[0]["created_at"].endswith("Z")
        assert approvals[0]["expires_at"].endswith("Z")

        audit_lines = (intentguard_dir / "audit.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        assert len(audit_lines) == 1

        audit_event = json.loads(audit_lines[0])
        assert audit_event["event_id"].startswith("evt_")
        assert audit_event["action"] == "approval_created"
        assert audit_event["decision"] == "approved"
        assert audit_event["scan_id"] == "scan_001"
        assert audit_event["task_id"] == "task_001"
        assert audit_event["target"] == "scan_001"
        assert audit_event["reason"] == "Manual review approved."
        assert audit_event["timestamp"].endswith("Z")


def test_approve_command_fails_for_unknown_scan(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()

        write_default_policy(intentguard_dir / "policy.yaml")
        (intentguard_dir / "approvals.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")
        (intentguard_dir / "scans.jsonl").write_text("", encoding="utf-8")

        result = runner.invoke(app, ["approve", "scan_missing"])

        assert result.exit_code != 0
        assert "Scan 'scan_missing' was not found." in result.output

        approvals = json.loads(
            (intentguard_dir / "approvals.json").read_text(encoding="utf-8")
        )
        assert approvals == []


def test_approve_command_fails_for_blocked_scan(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()

        write_default_policy(intentguard_dir / "policy.yaml")
        (intentguard_dir / "approvals.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan = {
            "scan_id": "scan_001",
            "task_id": "task_001",
            "repo_path": str(cwd),
            "changed_files": [
                {
                    "path": ".env",
                    "change_type": "modified",
                    "risk": "high",
                    "decision": "BLOCK",
                    "reason": "Path is blocked by policy: .env",
                },
                {
                    "path": ".github/workflows/deploy.yml",
                    "change_type": "modified",
                    "risk": "high",
                    "decision": "REQUIRE_APPROVAL",
                    "reason": "Path requires approval by policy.",
                },
            ],
            "overall_risk": "high",
            "final_decision": "BLOCK",
            "created_at": "2026-05-26T10:00:00Z",
        }

        (intentguard_dir / "scans.jsonl").write_text(
            json.dumps(scan) + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["approve", "scan_001"])

        assert result.exit_code != 0
        assert "This scan contains blocked files and cannot be approved." in result.output

        approvals = json.loads(
            (intentguard_dir / "approvals.json").read_text(encoding="utf-8")
        )
        assert approvals == []


def test_approve_command_fails_when_scan_has_no_approval_required_files(
    tmp_path,
) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()

        write_default_policy(intentguard_dir / "policy.yaml")
        (intentguard_dir / "approvals.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan = {
            "scan_id": "scan_001",
            "task_id": "task_001",
            "repo_path": str(cwd),
            "changed_files": [
                {
                    "path": "README.md",
                    "change_type": "modified",
                    "risk": "low",
                    "decision": "ALLOW_WITH_AUDIT",
                    "reason": "Allowed by default policy.",
                },
            ],
            "overall_risk": "low",
            "final_decision": "ALLOW_WITH_AUDIT",
            "created_at": "2026-05-26T10:00:00Z",
        }

        (intentguard_dir / "scans.jsonl").write_text(
            json.dumps(scan) + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["approve", "scan_001"])

        assert result.exit_code != 0
        assert (
            "This scan does not contain files that require approval."
            in result.output
        )

        approvals = json.loads(
            (intentguard_dir / "approvals.json").read_text(encoding="utf-8")
        )
        assert approvals == []


def test_approve_command_accepts_custom_reason(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()

        write_default_policy(intentguard_dir / "policy.yaml")
        (intentguard_dir / "approvals.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan = {
            "scan_id": "scan_001",
            "task_id": "task_001",
            "repo_path": str(cwd),
            "changed_files": [
                {
                    "path": ".github/workflows/deploy.yml",
                    "change_type": "modified",
                    "risk": "high",
                    "decision": "REQUIRE_APPROVAL",
                    "reason": "Path requires approval by policy.",
                }
            ],
            "overall_risk": "high",
            "final_decision": "REQUIRE_APPROVAL",
            "created_at": "2026-05-26T10:00:00Z",
        }

        (intentguard_dir / "scans.jsonl").write_text(
            json.dumps(scan) + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(
            app,
            [
                "approve",
                "scan_001",
                "--reason",
                "Manual review: CI/CD change is intentional.",
            ],
        )

        assert result.exit_code == 0

        approvals = json.loads(
            (intentguard_dir / "approvals.json").read_text(encoding="utf-8")
        )

        assert (
            approvals[0]["reason"]
            == "Manual review: CI/CD change is intentional."
        )
