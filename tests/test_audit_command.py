from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from intentguard.cli import app


def test_audit_command_prints_local_audit_events(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()

        event = {
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
        }

        (intentguard_dir / "audit.jsonl").write_text(
            json.dumps(event) + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["audit"])

        assert result.exit_code == 0
        assert "evt_001" in result.output
        assert "scan_completed" in result.output
        assert "allow_with_audit" in result.output
        assert "Scan completed." in result.output


def test_audit_command_handles_empty_audit_log(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        result = runner.invoke(app, ["audit"])

        assert result.exit_code == 0
        assert "No audit events found." in result.output