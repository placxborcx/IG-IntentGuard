from __future__ import annotations

from intentguard.models import FileChangeType
from intentguard.scanner.git_diff import DiffParser


def test_parse_name_status_detects_added_modified_and_deleted_files() -> None:
    files = DiffParser().parse_name_status(
        "A\tsrc/new.py\nM\tsrc/existing.py\nD\t.env\n",
        staged=False,
    )

    assert [file.path for file in files] == [
        "src/new.py",
        "src/existing.py",
        ".env",
    ]
    assert [file.change_type for file in files] == [
        FileChangeType.ADDED,
        FileChangeType.MODIFIED,
        FileChangeType.DELETED,
    ]
    assert all(file.is_staged is False for file in files)


def test_parse_name_status_preserves_old_path_for_renames() -> None:
    files = DiffParser().parse_name_status(
        "R100\t.env\tconfig/example.env\n",
        staged=True,
    )

    assert len(files) == 1
    assert files[0].path == "config/example.env"
    assert files[0].old_path == ".env"
    assert files[0].change_type == FileChangeType.RENAMED
    assert files[0].is_staged is True


def test_parse_name_status_preserves_old_path_for_copies() -> None:
    files = DiffParser().parse_name_status(
        "C100\tinfra/main.tf\tinfra/main.copy.tf\n",
        staged=False,
    )

    assert len(files) == 1
    assert files[0].path == "infra/main.copy.tf"
    assert files[0].old_path == "infra/main.tf"
    assert files[0].change_type == FileChangeType.COPIED


def test_parse_name_status_handles_type_changed_and_unmerged_files() -> None:
    files = DiffParser().parse_name_status(
        "T\tscript.sh\nU\tsrc/conflict.py\n",
        staged=True,
    )

    assert [file.change_type for file in files] == [
        FileChangeType.TYPE_CHANGED,
        FileChangeType.UNMERGED,
    ]
    assert all(file.is_staged is True for file in files)


def test_parse_name_status_ignores_blank_lines() -> None:
    files = DiffParser().parse_name_status("\nM\tREADME.md\n\n", staged=False)

    assert len(files) == 1
    assert files[0].path == "README.md"
    assert files[0].change_type == FileChangeType.MODIFIED


def test_parse_status_porcelain_detects_untracked_files() -> None:
    files = DiffParser().parse_status_porcelain(
        "?? .env\n?? secrets/local.key\n",
    )

    assert [file.path for file in files] == [".env", "secrets/local.key"]
    assert [file.change_type for file in files] == [
        FileChangeType.ADDED,
        FileChangeType.ADDED,
    ]
    assert all(file.is_staged is False for file in files)


def test_parse_secret_findings_from_diff_detects_added_secret_lines() -> None:
    diff_output = '''diff --git a/src/settings.py b/src/settings.py
--- a/src/settings.py
+++ b/src/settings.py
@@ -0,0 +1 @@
+OPENAI_API_KEY = "sk-live-raw-secret-value"
'''

    findings = DiffParser().parse_secret_findings_from_diff(diff_output)

    assert "src/settings.py" in findings
    assert len(findings["src/settings.py"]) == 1
    assert findings["src/settings.py"][0]["pattern_id"] == "generic_api_key"
    assert findings["src/settings.py"][0]["redacted_sample"] == "api_key=<redacted>"
    assert "sk-live-raw-secret-value" not in str(findings)
