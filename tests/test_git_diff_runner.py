from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

from intentguard.models import FileChangeType
from intentguard.scanner.git_diff import GitDiffRunner, find_git_root, run_diff


def test_git_diff_runner_builds_unstaged_diff_command() -> None:
    runner = GitDiffRunner()

    command = runner.build_diff_command(staged=False)

    assert command == [
        "git",
        "diff",
        "--name-status",
        "--diff-filter=AMDRCTU",
        "-M",
        "-C",
    ]


def test_git_diff_runner_builds_staged_diff_command() -> None:
    runner = GitDiffRunner()

    command = runner.build_diff_command(staged=True)

    assert command == [
        "git",
        "diff",
        "--staged",
        "--name-status",
        "--diff-filter=AMDRCTU",
        "-M",
        "-C",
    ]


def test_git_diff_runner_builds_status_command() -> None:
    runner = GitDiffRunner()

    command = runner.build_status_command()

    assert command == [
        "git",
        "status",
        "--porcelain",
    ]


def test_git_diff_runner_builds_git_root_command() -> None:
    runner = GitDiffRunner()

    command = runner.build_git_root_command()

    assert command == [
        "git",
        "rev-parse",
        "--show-toplevel",
    ]


def test_git_diff_runner_runs_command_with_shell_disabled() -> None:
    runner = GitDiffRunner()
    completed = Mock(returncode=0, stdout="M\tREADME.md\n", stderr="")

    with patch("intentguard.scanner.git_diff.subprocess.run", return_value=completed) as run:
        result = runner.run_diff_command(Path("/tmp/repo"), staged=False)

    run.assert_called_once_with(
        [
            "git",
            "diff",
            "--name-status",
            "--diff-filter=AMDRCTU",
            "-M",
            "-C",
        ],
        cwd=Path("/tmp/repo"),
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )

    assert result.returncode == 0
    assert result.stdout == "M\tREADME.md\n"
    assert result.stderr == ""


def test_git_diff_runner_runs_status_command_with_shell_disabled() -> None:
    runner = GitDiffRunner()
    completed = Mock(returncode=0, stdout="?? .env\n", stderr="")

    with patch("intentguard.scanner.git_diff.subprocess.run", return_value=completed) as run:
        result = runner.run_status_command(Path("/tmp/repo"))

    run.assert_called_once_with(
        [
            "git",
            "status",
            "--porcelain",
        ],
        cwd=Path("/tmp/repo"),
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )

    assert result.returncode == 0
    assert result.stdout == "?? .env\n"
    assert result.stderr == ""


def test_git_diff_runner_runs_git_root_command_with_shell_disabled() -> None:
    runner = GitDiffRunner()
    completed = Mock(returncode=0, stdout="/tmp/repo\n", stderr="")

    with patch("intentguard.scanner.git_diff.subprocess.run", return_value=completed) as run:
        result = runner.run_git_root_command(Path("/tmp/repo/subdir"))

    run.assert_called_once_with(
        [
            "git",
            "rev-parse",
            "--show-toplevel",
        ],
        cwd=Path("/tmp/repo/subdir"),
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )

    assert result.returncode == 0
    assert result.stdout == "/tmp/repo\n"
    assert result.stderr == ""


def test_run_diff_returns_diff_scan_result_from_git_metadata() -> None:
    completed = Mock(returncode=0, stdout="M\tREADME.md\n", stderr="")
    content_completed = Mock(returncode=0, stdout="", stderr="")
    status_completed = Mock(returncode=0, stdout="", stderr="")

    with (
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_diff_command",
            return_value=completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_content_diff_command",
            return_value=content_completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_status_command",
            return_value=status_completed,
        ),
    ):
        result = run_diff(staged=False, repo_root=Path("/tmp/repo"))

    assert result.has_error is False
    assert result.is_staged is False
    assert result.git_root == "/tmp/repo"
    assert len(result.changed_files) == 1
    assert result.changed_files[0].path == "README.md"
    assert result.changed_files[0].change_type == FileChangeType.MODIFIED


def test_run_diff_returns_structured_error_when_git_fails() -> None:
    completed = Mock(returncode=128, stdout="", stderr="fatal: not a git repository")

    with patch(
        "intentguard.scanner.git_diff.GitDiffRunner.run_diff_command",
        return_value=completed,
    ):
        result = run_diff(staged=False, repo_root=Path("/tmp/not-repo"))

    assert result.has_error is True
    assert result.is_staged is False
    assert result.git_root == "/tmp/not-repo"
    assert result.changed_files == []
    assert result.error == "fatal: not a git repository"


def test_run_diff_includes_untracked_files_for_unstaged_scan() -> None:
    diff_completed = Mock(returncode=0, stdout="M\tREADME.md\n", stderr="")
    content_completed = Mock(returncode=0, stdout="", stderr="")
    status_completed = Mock(returncode=0, stdout="?? .env\n", stderr="")

    with (
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_diff_command",
            return_value=diff_completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_content_diff_command",
            return_value=content_completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_status_command",
            return_value=status_completed,
        ),
    ):
        result = run_diff(staged=False, repo_root=Path("/tmp/repo"))

    assert result.has_error is False
    assert [file.path for file in result.changed_files] == ["README.md", ".env"]
    assert [file.change_type for file in result.changed_files] == [
        FileChangeType.MODIFIED,
        FileChangeType.ADDED,
    ]


def test_run_diff_does_not_include_untracked_files_for_staged_scan() -> None:
    completed = Mock(returncode=0, stdout="A\tREADME.md\n", stderr="")
    content_completed = Mock(returncode=0, stdout="", stderr="")

    with (
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_diff_command",
            return_value=completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_content_diff_command",
            return_value=content_completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_status_command",
        ) as status_command,
    ):
        result = run_diff(staged=True, repo_root=Path("/tmp/repo"))

    status_command.assert_not_called()
    assert result.has_error is False
    assert result.is_staged is True
    assert [file.path for file in result.changed_files] == ["README.md"]
    assert result.changed_files[0].change_type == FileChangeType.ADDED


def test_find_git_root_returns_path_from_git_command() -> None:
    completed = Mock(returncode=0, stdout="/tmp/repo\n", stderr="")

    with patch(
        "intentguard.scanner.git_diff.GitDiffRunner.run_git_root_command",
        return_value=completed,
    ):
        root = find_git_root(Path("/tmp/repo/subdir"))

    assert root == Path("/tmp/repo")


def test_find_git_root_returns_none_when_git_command_fails() -> None:
    completed = Mock(returncode=128, stdout="", stderr="fatal: not a git repository")

    with patch(
        "intentguard.scanner.git_diff.GitDiffRunner.run_git_root_command",
        return_value=completed,
    ):
        root = find_git_root(Path("/tmp/not-repo"))

    assert root is None


def test_run_diff_attaches_secret_findings_from_content_diff() -> None:
    metadata_completed = Mock(
        returncode=0,
        stdout="M\tsrc/settings.py\n",
        stderr="",
    )
    content_completed = Mock(
        returncode=0,
        stdout='''diff --git a/src/settings.py b/src/settings.py
--- a/src/settings.py
+++ b/src/settings.py
@@ -0,0 +1 @@
+OPENAI_API_KEY = "sk-live-raw-secret-value"
''',
        stderr="",
    )
    status_completed = Mock(returncode=0, stdout="", stderr="")

    with (
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_diff_command",
            return_value=metadata_completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_content_diff_command",
            return_value=content_completed,
        ),
        patch(
            "intentguard.scanner.git_diff.GitDiffRunner.run_status_command",
            return_value=status_completed,
        ),
    ):
        result = run_diff(staged=False, repo_root=Path("/tmp/repo"))

    assert len(result.changed_files) == 1
    assert result.changed_files[0].path == "src/settings.py"
    assert len(result.changed_files[0].secret_findings) == 1
    assert result.changed_files[0].secret_findings[0]["pattern_id"] == "generic_api_key"
    assert (
        result.changed_files[0].secret_findings[0]["redacted_sample"]
        == "api_key=<redacted>"
    )
    assert "sk-live-raw-secret-value" not in str(result.changed_files[0].secret_findings)
