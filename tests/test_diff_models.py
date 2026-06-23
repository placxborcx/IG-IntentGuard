from __future__ import annotations

from intentguard.models import DiffScanResult, FileChangeType, ScannedFile


def test_scanned_file_can_represent_deleted_file() -> None:
    file = ScannedFile(
        path=".env",
        change_type=FileChangeType.DELETED,
        is_staged=False,
    )

    assert file.path == ".env"
    assert file.change_type == FileChangeType.DELETED
    assert file.is_staged is False


def test_scanned_file_preserves_old_path_for_rename() -> None:
    file = ScannedFile(
        path="config/example.env",
        old_path=".env",
        change_type=FileChangeType.RENAMED,
        is_staged=True,
    )

    assert file.path == "config/example.env"
    assert file.old_path == ".env"
    assert file.change_type == FileChangeType.RENAMED
    assert file.is_staged is True


def test_diff_scan_result_contains_metadata_only() -> None:
    result = DiffScanResult(
        scan_id="scan_001",
        task_id="task_001",
        is_staged=False,
        git_root="/tmp/repo",
        changed_files=[
            ScannedFile(
                path="src/auth/login.py",
                change_type=FileChangeType.MODIFIED,
                is_staged=False,
            )
        ],
    )

    payload = result.model_dump()
    file_payload = payload["changed_files"][0]

    forbidden_fields = {
        "diff",
        "patch",
        "content",
        "file_contents",
        "source",
        "secret",
    }

    assert forbidden_fields.isdisjoint(payload)
    assert forbidden_fields.isdisjoint(file_payload)
    assert result.has_error is False


def test_diff_scan_result_can_represent_structured_error() -> None:
    result = DiffScanResult(
        scan_id="scan_001",
        is_staged=False,
        changed_files=[],
        error="Not a Git repository",
    )

    assert result.has_error is True
    assert result.changed_files == []
    assert result.error == "Not a Git repository"