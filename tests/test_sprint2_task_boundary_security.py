from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from intentguard.cli import app
from intentguard.models import TaskSession
from intentguard.tasks import create_task_session, get_active_task


def test_sprint2_task_records_keep_minimum_audit_metadata(tmp_path: Path) -> None:
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text("[]\n", encoding="utf-8")

    create_task_session(
        tasks_path=tasks_path,
        intent="Fix login bug",
        allowed_paths=["src/auth/**", "tests/**"],
        agent="codex",
    )

    records = json.loads(tasks_path.read_text(encoding="utf-8"))
    assert len(records) == 1

    required_fields = {
        "task_id",
        "intent",
        "agent",
        "allowed_paths",
        "blocked_paths",
        "allowed_deploy_target",
        "status",
        "created_at",
    }
    assert required_fields <= set(records[0])
    assert records[0]["task_id"].startswith("task_")
    assert records[0]["status"] == "active"


def test_sprint2_task_records_do_not_store_source_or_secret_material(
    tmp_path: Path,
) -> None:
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text("[]\n", encoding="utf-8")

    create_task_session(
        tasks_path=tasks_path,
        intent="Update auth tests",
        allowed_paths=["tests/**"],
        agent=None,
    )

    records = json.loads(tasks_path.read_text(encoding="utf-8"))
    forbidden_fields = {
        "diff",
        "patch",
        "content",
        "file_contents",
        "source",
        "raw_output",
        "secret",
        "password",
        "token",
        "api_key",
    }

    for record in records:
        assert forbidden_fields.isdisjoint(record)


def test_sprint2_new_task_archives_previous_active_task_for_clear_scope(
    tmp_path: Path,
) -> None:
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text("[]\n", encoding="utf-8")

    create_task_session(
        tasks_path=tasks_path,
        intent="Fix login bug",
        allowed_paths=["src/auth/**"],
    )
    create_task_session(
        tasks_path=tasks_path,
        intent="Update login tests",
        allowed_paths=["tests/**"],
    )

    records = json.loads(tasks_path.read_text(encoding="utf-8"))
    assert records[0]["status"] == "archived"
    assert records[1]["status"] == "active"

    active_task = get_active_task(tasks_path)
    assert active_task is not None
    assert active_task.task_id == records[1]["task_id"]
    assert active_task.allowed_paths == ["tests/**"]


def test_sprint2_task_session_has_no_authorization_bypass_fields() -> None:
    task = TaskSession(
        task_id="task_001",
        intent="Touch a sensitive path as part of a later scan",
        allowed_paths=[".env"],
    )

    for forbidden_attr in ("allow", "approved", "permitted", "bypass", "grant"):
        assert not hasattr(task, forbidden_attr)


def test_sprint2_create_task_output_uses_creation_not_enforcement_language(
    tmp_path: Path,
) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        init_result = runner.invoke(app, ["init"])
        assert init_result.exit_code == 0

        result = runner.invoke(
            app,
            [
                "create-task",
                "Fix login bug",
                "--allow",
                "src/auth/**",
            ],
        )

    assert result.exit_code == 0
    output = result.output.lower()
    for word in ("blocked", "rejected", "denied", "prevented", "stopped", "aborted"):
        assert word not in output
