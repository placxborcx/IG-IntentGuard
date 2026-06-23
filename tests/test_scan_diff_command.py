from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from intentguard.cli import app
from intentguard.models import DiffScanResult, FileChangeType, ScannedFile, TaskSession
from intentguard.policy import write_default_policy


def write_test_policy(intentguard_dir: Path) -> None:
    write_default_policy(intentguard_dir / "policy.yaml")


def test_scan_diff_requires_intentguard_init(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()

        with patch("intentguard.cli.find_git_root", return_value=cwd):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code != 0
        assert "IntentGuard is not initialized" in result.output


def test_scan_diff_prints_changed_file_metadata(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code == 0
        assert "IntentGuard Scan Result" in result.output
        assert "Risk: low" in result.output
        assert "Decision: ALLOW_WITH_AUDIT" in result.output
        assert "README.md modified low ALLOW_WITH_AUDIT" in result.output


def test_scan_diff_staged_passes_staged_flag_to_scanner(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result) as run_diff,
        ):
            result = runner.invoke(app, ["scan-diff", "--staged"])

        assert result.exit_code == 0
        run_diff.assert_called_once_with(staged=True, repo_root=cwd)


def test_scan_diff_json_outputs_structured_scan_result(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            task_id="task_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--format", "json"])

        assert result.exit_code == 0

        payload = json.loads(result.output)
        assert payload["scan_id"] == "scan_001"
        assert payload["task_id"] == "task_001"
        assert payload["repo_path"] == str(cwd)
        assert payload["overall_risk"] == "low"
        assert payload["final_decision"] == "ALLOW_WITH_AUDIT"
        assert payload["changed_files"][0]["path"] == "README.md"
        assert payload["changed_files"][0]["change_type"] == "modified"
        assert payload["changed_files"][0]["risk"] == "low"
        assert payload["changed_files"][0]["decision"] == "ALLOW_WITH_AUDIT"
        assert "reason" in payload["changed_files"][0]


def test_scan_diff_json_includes_policy_block_decision(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".env",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--format", "json"])

        assert result.exit_code == 0

        payload = json.loads(result.output)
        assert payload["overall_risk"] == "high"
        assert payload["final_decision"] == "BLOCK"
        assert payload["changed_files"][0]["path"] == ".env"
        assert payload["changed_files"][0]["risk"] == "high"
        assert payload["changed_files"][0]["decision"] == "BLOCK"
        assert "blocked" in payload["changed_files"][0]["reason"].lower()


def test_scan_diff_json_blocks_secret_findings_without_raw_secret(tmp_path) -> None:
    runner = CliRunner()
    raw_secret = "sk-live-raw-secret-value"

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="src/settings.py",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                    secret_findings=[
                        {
                            "path": "src/settings.py",
                            "line_number": 1,
                            "line_type": "added",
                            "pattern_id": "generic_api_key",
                            "redacted_sample": "api_key=<redacted>",
                        }
                    ],
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--format", "json"])

        assert result.exit_code == 0
        assert raw_secret not in result.output

        payload = json.loads(result.output)
        assert payload["overall_risk"] == "high"
        assert payload["final_decision"] == "BLOCK"
        assert payload["changed_files"][0]["path"] == "src/settings.py"
        assert payload["changed_files"][0]["risk"] == "high"
        assert payload["changed_files"][0]["decision"] == "BLOCK"
        assert raw_secret not in payload["changed_files"][0]["reason"]
        assert "generic_api_key" in payload["changed_files"][0]["reason"]


def test_scan_diff_sets_active_task_id_on_result(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[],
        )
        active_task = TaskSession(
            task_id="task_001",
            intent="Fix login bug",
            allowed_paths=["src/auth/**"],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
            patch("intentguard.cli.get_active_task", return_value=active_task),
        ):
            result = runner.invoke(app, ["scan-diff", "--format", "json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["task_id"] == "task_001"


def test_scan_diff_fails_outside_git_repo(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        with patch("intentguard.cli.find_git_root", return_value=None):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code != 0
        assert "Not a Git repository" in result.output


def test_scan_diff_fails_when_scanner_returns_error(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[],
            error="Git diff failed",
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code != 0
        assert "Git diff failed" in result.output


def test_scan_diff_writes_scan_completed_audit_event(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code == 0

        lines = (intentguard_dir / "audit.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        assert len(lines) == 2

        event = json.loads(lines[0])
        assert event["event_id"].startswith("evt_")
        assert event["scan_id"] == "scan_001"
        assert event["action"] == "scan_completed"
        assert event["target"] == "scan"
        assert event["risk"] == "low"
        assert event["decision"] == "allow_with_audit"
        assert event["timestamp"].endswith("Z")


def test_scan_diff_writes_file_decision_audit_events(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".env",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                ),
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                ),
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code == 0

        lines = (intentguard_dir / "audit.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        events = [json.loads(line) for line in lines]

        assert [event["action"] for event in events] == [
            "scan_completed",
            "file_decision",
            "file_decision",
        ]

        file_events = events[1:]
        assert file_events[0]["target"] == ".env"
        assert file_events[0]["risk"] == "high"
        assert file_events[0]["decision"] == "block"

        assert file_events[1]["target"] == "README.md"
        assert file_events[1]["risk"] == "low"
        assert file_events[1]["decision"] == "allow_with_audit"


def test_scan_diff_persists_scan_record(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "audit.jsonl").write_text("", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=False,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=False,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff"])

        assert result.exit_code == 0

        records_path = intentguard_dir / "scans.jsonl"
        lines = records_path.read_text(encoding="utf-8").splitlines()

        assert len(lines) == 1

        payload = json.loads(lines[0])
        assert payload["scan_id"] == "scan_001"
        assert payload["repo_path"] == str(cwd)
        assert payload["changed_files"][0]["path"] == "README.md"
        assert "reason" in payload["changed_files"][0]


def test_scan_diff_enforce_blocks_block_decision(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".env",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code != 0
        assert "IntentGuard blocked this Git operation." in result.output
        assert "intentguard scan-diff --staged" in result.output
        assert "intentguard approve <scan_id>" in result.output


def test_scan_diff_enforce_blocks_require_approval_without_approval(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".github/workflows/deploy.yml",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code != 0
        assert "Decision: REQUIRE_APPROVAL" in result.output
        assert "IntentGuard blocked this Git operation." in result.output
        assert "intentguard approve <scan_id>" in result.output


def test_scan_diff_enforce_allows_allow_with_audit(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code == 0
        assert "Decision: ALLOW_WITH_AUDIT" in result.output
        assert "IntentGuard blocked this Git operation." not in result.output


def test_scan_diff_enforce_allows_warn_out_of_scope(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)

        (intentguard_dir / "tasks.json").write_text(
            json.dumps(
                [
                    {
                        "task_id": "task_001",
                        "intent": "Fix auth bug",
                        "agent": "codex",
                        "allowed_paths": ["src/auth/**"],
                        "blocked_paths": [],
                        "allowed_deploy_target": "none",
                        "status": "active",
                        "created_at": "2026-05-26T00:00:00Z",
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        scan_result = DiffScanResult(
            scan_id="scan_current",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="README.md",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code == 0
        assert "Decision: ALLOW_WITH_AUDIT" in result.output
        assert "README.md modified medium WARN_OUT_OF_SCOPE" in result.output
        assert "IntentGuard blocked this Git operation." not in result.output


def test_scan_diff_enforce_allows_require_approval_with_valid_approval(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        approved_scan = {
            "scan_id": "scan_approved",
            "task_id": None,
            "repo_path": str(cwd),
            "changed_files": [
                {
                    "path": ".github/workflows/deploy.yml",
                    "change_type": "modified",
                    "risk": "high",
                    "decision": "REQUIRE_APPROVAL",
                    "reason": "Path requires approval by policy.",
                }
            ],
            "overall_risk": "high",
            "final_decision": "REQUIRE_APPROVAL",
            "created_at": "2026-05-26T00:00:00Z",
        }

        (intentguard_dir / "scans.jsonl").write_text(
            json.dumps(approved_scan) + "\n",
            encoding="utf-8",
        )
        (intentguard_dir / "approvals.json").write_text(
            json.dumps(
                [
                    {
                        "approval_id": "apr_001",
                        "scan_id": "scan_approved",
                        "task_id": None,
                        "approved_files": [".github/workflows/deploy.yml"],
                        "approver": "human",
                        "reason": "Manual review approved.",
                        "expires_at": "2999-01-01T00:00:00Z",
                        "created_at": "2026-05-26T00:00:00Z",
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".github/workflows/deploy.yml",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code == 0
        assert "Decision: REQUIRE_APPROVAL" in result.output
        assert "IntentGuard blocked this Git operation." not in result.output


def test_scan_diff_enforce_blocks_expired_approval(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "approvals.json").write_text(
            json.dumps(
                [
                    {
                        "approval_id": "apr_001",
                        "scan_id": "scan_001",
                        "task_id": None,
                        "approved_files": [".github/workflows/deploy.yml"],
                        "approver": "human",
                        "reason": "Manual review approved.",
                        "expires_at": "2000-01-01T00:00:00Z",
                        "created_at": "1999-01-01T00:00:00Z",
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        scan_result = DiffScanResult(
            scan_id="scan_current",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".github/workflows/deploy.yml",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code != 0
        assert "Decision: REQUIRE_APPROVAL" in result.output
        assert "IntentGuard blocked this Git operation." in result.output


def test_scan_diff_enforce_blocks_mismatched_approval_files(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "approvals.json").write_text(
            json.dumps(
                [
                    {
                        "approval_id": "apr_001",
                        "scan_id": "scan_001",
                        "task_id": None,
                        "approved_files": ["src/auth/login.py"],
                        "approver": "human",
                        "reason": "Manual review approved.",
                        "expires_at": "2999-01-01T00:00:00Z",
                        "created_at": "2026-05-26T00:00:00Z",
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".github/workflows/deploy.yml",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                )
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code != 0
        assert "Decision: REQUIRE_APPROVAL" in result.output
        assert "IntentGuard blocked this Git operation." in result.output


def test_scan_diff_enforce_blocks_block_even_with_valid_approval(tmp_path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)
        (intentguard_dir / "tasks.json").write_text("[]\n", encoding="utf-8")
        (intentguard_dir / "approvals.json").write_text(
            json.dumps(
                [
                    {
                        "approval_id": "apr_001",
                        "scan_id": "scan_001",
                        "task_id": None,
                        "approved_files": [".github/workflows/deploy.yml"],
                        "approver": "human",
                        "reason": "Manual review approved.",
                        "expires_at": "2999-01-01T00:00:00Z",
                        "created_at": "2026-05-26T00:00:00Z",
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path=".github/workflows/deploy.yml",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                ),
                ScannedFile(
                    path=".env",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                ),
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged", "--enforce"])

        assert result.exit_code != 0
        assert "Decision: BLOCK" in result.output
        assert "IntentGuard blocked this Git operation." in result.output


def test_scan_diff_demo_login_fix_with_workflow_change_requires_approval(
    tmp_path,
) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem(temp_dir=tmp_path):
        cwd = Path.cwd()
        intentguard_dir = cwd / ".intentguard"
        intentguard_dir.mkdir()
        write_test_policy(intentguard_dir)

        (intentguard_dir / "tasks.json").write_text(
            json.dumps(
                [
                    {
                        "task_id": "task_001",
                        "intent": "Fix login bug",
                        "agent": "codex",
                        "allowed_paths": ["src/auth/**", "tests/**"],
                        "blocked_paths": [],
                        "allowed_deploy_target": "none",
                        "status": "active",
                        "created_at": "2026-05-26T00:00:00Z",
                    }
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        scan_result = DiffScanResult(
            scan_id="scan_001",
            is_staged=True,
            git_root=str(cwd),
            changed_files=[
                ScannedFile(
                    path="src/auth/login.py",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                ),
                ScannedFile(
                    path=".github/workflows/deploy.yml",
                    change_type=FileChangeType.MODIFIED,
                    is_staged=True,
                ),
            ],
        )

        with (
            patch("intentguard.cli.find_git_root", return_value=cwd),
            patch("intentguard.cli.run_diff", return_value=scan_result),
        ):
            result = runner.invoke(app, ["scan-diff", "--staged"])

        assert result.exit_code == 0
        assert "src/auth/login.py modified high REQUIRE_APPROVAL" in result.output
        assert (
            ".github/workflows/deploy.yml modified high REQUIRE_APPROVAL"
            in result.output
        )
        assert "Decision: REQUIRE_APPROVAL" in result.output
