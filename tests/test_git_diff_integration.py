from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from intentguard.models import FileChangeType
from intentguard.scanner.git_diff import run_diff


def git_available() -> bool:
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not git_available(), reason="git is not installed")


def init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@intentguard.local"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "IntentGuard Test"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    (path / "README.md").write_text("# test\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=path,
        capture_output=True,
        check=True,
    )


def test_run_diff_reports_unstaged_modified_file(tmp_path: Path) -> None:
    init_git_repo(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text("# changed\n", encoding="utf-8")

    result = run_diff(staged=False, repo_root=tmp_path)

    assert not result.has_error
    assert result.is_staged is False
    assert result.git_root == str(tmp_path)
    assert len(result.changed_files) == 1
    assert result.changed_files[0].path == "README.md"
    assert result.changed_files[0].change_type == FileChangeType.MODIFIED


def test_run_diff_staged_scan_excludes_unstaged_changes(tmp_path: Path) -> None:
    init_git_repo(tmp_path)

    staged_file = tmp_path / "staged.txt"
    staged_file.write_text("staged\n", encoding="utf-8")
    subprocess.run(["git", "add", "staged.txt"], cwd=tmp_path, capture_output=True, check=True)

    unstaged_file = tmp_path / "README.md"
    unstaged_file.write_text("# unstaged\n", encoding="utf-8")

    result = run_diff(staged=True, repo_root=tmp_path)

    assert not result.has_error
    assert result.is_staged is True
    assert [file.path for file in result.changed_files] == ["staged.txt"]
    assert result.changed_files[0].change_type == FileChangeType.ADDED


def test_run_diff_reports_untracked_env_file_as_added(tmp_path: Path) -> None:
    init_git_repo(tmp_path)

    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=value\n", encoding="utf-8")

    result = run_diff(staged=False, repo_root=tmp_path)

    assert not result.has_error
    assert result.is_staged is False

    env_changes = [file for file in result.changed_files if file.path == ".env"]
    assert len(env_changes) == 1
    assert env_changes[0].change_type == FileChangeType.ADDED


def test_run_diff_reports_deleted_env_file(tmp_path: Path) -> None:
    init_git_repo(tmp_path)

    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=value\n", encoding="utf-8")
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add env"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )

    env_file.unlink()

    result = run_diff(staged=False, repo_root=tmp_path)

    assert not result.has_error
    deleted_env = [file for file in result.changed_files if file.path == ".env"]
    assert len(deleted_env) == 1
    assert deleted_env[0].change_type == FileChangeType.DELETED


def test_run_diff_preserves_old_path_for_renamed_env_file(tmp_path: Path) -> None:
    init_git_repo(tmp_path)

    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=value\n", encoding="utf-8")
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add env"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    subprocess.run(
        ["git", "mv", ".env", "config/example.env"],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )

    result = run_diff(staged=True, repo_root=tmp_path)

    assert not result.has_error
    assert result.is_staged is True
    renamed = [file for file in result.changed_files if file.path == "config/example.env"]
    assert len(renamed) == 1
    assert renamed[0].change_type == FileChangeType.RENAMED
    assert renamed[0].old_path == ".env"