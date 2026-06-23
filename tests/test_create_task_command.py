from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from intentguard.cli import app
from intentguard.tasks import get_active_task


def test_create_task_writes_active_task_to_tasks_json(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()

        init_result = runner.invoke(app, ["init"])
        assert init_result.exit_code == 0

        result = runner.invoke(
            app,
            [
                "create-task",
                "Fix login bug",
                "--allow",
                "src/auth/**",
                "--allow",
                "tests/**",
                "--agent",
                "codex",
            ],
        )

        assert result.exit_code == 0

        tasks_path = cwd / ".intentguard" / "tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))

        assert len(tasks) == 1

        task = tasks[0]
        assert task["task_id"] == "task_001"
        assert task["intent"] == "Fix login bug"
        assert task["agent"] == "codex"
        assert task["allowed_paths"] == ["src/auth/**", "tests/**"]
        assert task["blocked_paths"] == []
        assert task["allowed_deploy_target"] == "none"
        assert task["status"] == "active"
        assert "created_at" in task


def test_create_task_archives_previous_active_task(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()

        init_result = runner.invoke(app, ["init"])
        assert init_result.exit_code == 0

        first_result = runner.invoke(
            app,
            [
                "create-task",
                "Fix login bug",
                "--allow",
                "src/auth/**",
            ],
        )
        assert first_result.exit_code == 0

        second_result = runner.invoke(
            app,
            [
                "create-task",
                "Update login tests",
                "--allow",
                "tests/**",
            ],
        )
        assert second_result.exit_code == 0

        tasks_path = cwd / ".intentguard" / "tasks.json"
        tasks = json.loads(tasks_path.read_text(encoding="utf-8"))

        assert len(tasks) == 2
        assert tasks[0]["task_id"] == "task_001"
        assert tasks[0]["status"] == "archived"
        assert tasks[1]["task_id"] == "task_002"
        assert tasks[1]["status"] == "active"


def test_create_task_requires_init_first(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(
            app,
            [
                "create-task",
                "Fix login bug",
                "--allow",
                "src/auth/**",
            ],
        )

        assert result.exit_code != 0
        assert "IntentGuard is not initialized" in result.output


def test_get_active_task_returns_current_active_task(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()

        init_result = runner.invoke(app, ["init"])
        assert init_result.exit_code == 0

        first_result = runner.invoke(
            app,
            [
                "create-task",
                "Fix login bug",
                "--allow",
                "src/auth/**",
            ],
        )
        assert first_result.exit_code == 0

        second_result = runner.invoke(
            app,
            [
                "create-task",
                "Update login tests",
                "--allow",
                "tests/**",
            ],
        )
        assert second_result.exit_code == 0

        active_task = get_active_task(cwd / ".intentguard" / "tasks.json")

        assert active_task is not None
        assert active_task.task_id == "task_002"
        assert active_task.intent == "Update login tests"
        assert active_task.allowed_paths == ["tests/**"]
        assert active_task.status == "active"
