from __future__ import annotations

import os
from pathlib import Path

from intentguard.hooks import install_pre_commit_hook
from typer.testing import CliRunner
from unittest.mock import patch

from intentguard.cli import app


def test_install_pre_commit_hook_creates_executable_hook(tmp_path) -> None:
    git_root = tmp_path
    hooks_dir = git_root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)

    hook_path = install_pre_commit_hook(git_root=git_root)

    assert hook_path == hooks_dir / "pre-commit"
    assert hook_path.exists()
    assert hook_path.read_text(encoding="utf-8") == (
        "#!/bin/sh\n"
        "intentguard scan-diff --staged --enforce\n"
    )
    assert os.access(hook_path, os.X_OK)


def test_install_pre_commit_hook_does_not_overwrite_existing_hook_without_force(
    tmp_path,
) -> None:
    git_root = tmp_path
    hooks_dir = git_root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")

    result = install_pre_commit_hook(git_root=git_root)

    assert result == hook_path
    assert hook_path.read_text(encoding="utf-8") == "#!/bin/sh\necho existing\n"


def test_install_pre_commit_hook_overwrites_existing_hook_with_force(tmp_path) -> None:
    git_root = tmp_path
    hooks_dir = git_root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")

    install_pre_commit_hook(git_root=git_root, force=True)

    assert hook_path.read_text(encoding="utf-8") == (
        "#!/bin/sh\n"
        "intentguard scan-diff --staged --enforce\n"
    )


def test_install_hooks_command_installs_pre_commit_hook(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        hooks_dir = cwd / ".git" / "hooks"
        hooks_dir.mkdir(parents=True)

        with patch("intentguard.cli.find_git_root", return_value=cwd):
            result = runner.invoke(app, ["install-hooks"])

        assert result.exit_code == 0
        assert (hooks_dir / "pre-commit").exists()
        assert "installed .git/hooks/pre-commit" in result.output


def test_install_hooks_command_fails_outside_git_repo(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        with patch("intentguard.cli.find_git_root", return_value=None):
            result = runner.invoke(app, ["install-hooks"])

        assert result.exit_code != 0
        assert "Not a Git repository" in result.output
