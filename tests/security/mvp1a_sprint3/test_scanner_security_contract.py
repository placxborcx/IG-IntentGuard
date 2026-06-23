from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def git_available() -> bool:
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


skip_without_git = pytest.mark.skipif(not git_available(), reason="git is not installed")


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


def test_parser_preserves_deleted_sensitive_files() -> None:
    from intentguard.models import FileChangeType
    from intentguard.scanner.git_diff import DiffParser

    files = DiffParser().parse_name_status("D\t.env\n", staged=False)

    assert len(files) == 1
    assert files[0].path == ".env"
    assert files[0].change_type == FileChangeType.DELETED


def test_parser_preserves_old_path_for_sensitive_renames() -> None:
    from intentguard.models import FileChangeType
    from intentguard.scanner.git_diff import DiffParser

    files = DiffParser().parse_name_status("R100\t.env\tconfig/example.env\n", staged=True)

    assert len(files) == 1
    assert files[0].old_path == ".env"
    assert files[0].path == "config/example.env"
    assert files[0].change_type == FileChangeType.RENAMED
    assert files[0].is_staged is True


def test_scan_result_json_contains_no_content_fields() -> None:
    from intentguard.models import DiffScanResult, FileChangeType, ScannedFile

    result = DiffScanResult(
        scan_id="scan_001",
        is_staged=False,
        changed_files=[
            ScannedFile(
                path="src/auth/login.py",
                change_type=FileChangeType.MODIFIED,
                is_staged=False,
            )
        ],
        git_root="/tmp/repo",
    )
    payload = result.model_dump()
    file_payload = payload["changed_files"][0]

    forbidden = {"diff", "patch", "content", "file_contents", "source", "secret"}
    assert forbidden.isdisjoint(payload)
    assert forbidden.isdisjoint(file_payload)


@skip_without_git
def test_run_diff_reports_deleted_env_file(tmp_path: Path) -> None:
    from intentguard.models import FileChangeType
    from intentguard.scanner.git_diff import run_diff

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
    deleted_env = [f for f in result.changed_files if f.path == ".env"]
    assert deleted_env
    assert deleted_env[0].change_type == FileChangeType.DELETED


@skip_without_git
def test_run_diff_does_not_report_file_contents(tmp_path: Path) -> None:
    from intentguard.scanner.git_diff import run_diff

    init_git_repo(tmp_path)
    secret_file = tmp_path / "app.py"
    secret_file.write_text("API_KEY='should-not-appear'\n", encoding="utf-8")

    result = run_diff(staged=False, repo_root=tmp_path)
    dumped = result.model_dump_json()

    assert "should-not-appear" not in dumped
    assert "API_KEY" not in dumped


@skip_without_git
def test_run_diff_returns_structured_error_outside_git_repo(tmp_path: Path) -> None:
    from intentguard.scanner.git_diff import run_diff

    result = run_diff(staged=False, repo_root=tmp_path)

    assert result.has_error
    assert result.error
    assert result.changed_files == []
