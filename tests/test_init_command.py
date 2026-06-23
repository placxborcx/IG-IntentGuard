from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from intentguard.cli import app
from intentguard.policy import load_policy


def test_init_writes_default_policy_and_state_files(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        policy_path = cwd / ".intentguard" / "policy.yaml"
        assert policy_path.exists()
        assert (cwd / ".intentguard" / "tasks.json").read_text(encoding="utf-8") == "[]\n"
        assert (cwd / ".intentguard" / "approvals.json").read_text(encoding="utf-8") == "[]\n"
        assert (cwd / ".intentguard" / "audit.jsonl").read_text(encoding="utf-8") == ""

        policy = load_policy(policy_path)
        assert ".env" in policy.blocked_paths
        assert "docker-compose.yml" in policy.approval_required_paths


def test_init_does_not_overwrite_existing_policy_without_force(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        policy_dir = cwd / ".intentguard"
        policy_dir.mkdir()
        policy_path = policy_dir / "policy.yaml"
        policy_path.write_text("custom: true\n", encoding="utf-8")

        result = runner.invoke(app, ["init"])

        assert result.exit_code == 0
        assert policy_path.read_text(encoding="utf-8") == "custom: true\n"


def test_init_force_overwrites_existing_policy(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        policy_dir = cwd / ".intentguard"
        policy_dir.mkdir()
        policy_path = policy_dir / "policy.yaml"
        policy_path.write_text("custom: true\n", encoding="utf-8")

        result = runner.invoke(app, ["init", "--force"])

        assert result.exit_code == 0
        assert policy_path.read_text(encoding="utf-8") != "custom: true\n"

        policy = load_policy(policy_path)
        assert policy.default_decision == "ALLOW_WITH_AUDIT"
        assert policy.secret_detection.decision == "BLOCK"
