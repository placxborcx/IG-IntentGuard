from __future__ import annotations

from dataclasses import asdict
import subprocess
from pathlib import Path


from intentguard.audit.log import make_scan_id
from intentguard.models import DiffScanResult, FileChangeType, ScannedFile
from intentguard.secrets import detect_secrets_in_text


class DiffParser:
    """Parse safe Git diff metadata output."""

    def parse_name_status(self, output: str, staged: bool) -> list[ScannedFile]:
        files: list[ScannedFile] = []

        for line in output.splitlines():
            if not line.strip():
                continue

            parts = line.split("\t")
            status = parts[0]
            status_code = status[0]
            change_type = self._change_type_for_status(status_code)

            if change_type in {FileChangeType.RENAMED, FileChangeType.COPIED}:
                if len(parts) < 3:
                    files.append(
                        ScannedFile(
                            path=parts[-1],
                            change_type=FileChangeType.UNKNOWN,
                            is_staged=staged,
                        )
                    )
                    continue

                files.append(
                    ScannedFile(
                        path=parts[2],
                        old_path=parts[1],
                        change_type=change_type,
                        is_staged=staged,
                    )
                )
                continue

            if len(parts) < 2:
                continue

            files.append(
                ScannedFile(
                    path=parts[1],
                    change_type=change_type,
                    is_staged=staged,
                )
            )

        return files

    def parse_status_porcelain(self, output: str) -> list[ScannedFile]:
        files: list[ScannedFile] = []

        for line in output.splitlines():
            if not line.startswith("?? "):
                continue

            path = line[3:]
            if not path:
                continue

            files.append(
                ScannedFile(
                    path=path,
                    change_type=FileChangeType.ADDED,
                    is_staged=False,
                )
            )

        return files

    def parse_secret_findings_from_diff(self, output: str) -> dict[str, list[dict]]:
        findings_by_path: dict[str, list[dict]] = {}
        current_path: str | None = None

        for line in output.splitlines():
            if line.startswith("+++ b/"):
                current_path = line.removeprefix("+++ b/")
                continue

            if line.startswith("+++ /dev/null"):
                current_path = None
                continue

            if not current_path or not line.startswith("+") or line.startswith("+++"):
                continue

            added_line = line[1:]
            findings = detect_secrets_in_text(
                path=current_path,
                text=added_line,
            )

            if findings:
                findings_by_path.setdefault(current_path, []).extend(
                    asdict(finding) for finding in findings
                )

        return findings_by_path

    def _change_type_for_status(self, status_code: str) -> FileChangeType:
        status_map = {
            "A": FileChangeType.ADDED,
            "M": FileChangeType.MODIFIED,
            "D": FileChangeType.DELETED,
            "R": FileChangeType.RENAMED,
            "C": FileChangeType.COPIED,
            "T": FileChangeType.TYPE_CHANGED,
            "U": FileChangeType.UNMERGED,
        }
        return status_map.get(status_code, FileChangeType.UNKNOWN)


class GitDiffRunner:
    """Build safe Git commands for changed-file metadata scanning."""

    def build_diff_command(self, staged: bool) -> list[str]:
        command = ["git", "diff"]

        if staged:
            command.append("--staged")

        command.extend(
            [
                "--name-status",
                "--diff-filter=AMDRCTU",
                "-M",
                "-C",
            ]
        )

        return command

    def build_content_diff_command(self, staged: bool) -> list[str]:
        command = ["git", "diff"]

        if staged:
            command.append("--staged")

        command.extend(
            [
                "--unified=0",
                "--diff-filter=AMDRCTU",
                "-M",
                "-C",
            ]
        )

        return command

    def run_content_diff_command(
        self,
        repo_root: Path,
        staged: bool,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.build_content_diff_command(staged=staged),
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )

    def build_status_command(self) -> list[str]:
        return ["git", "status", "--porcelain"]

    def run_diff_command(
        self,
        repo_root: Path,
        staged: bool,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.build_diff_command(staged=staged),
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )

    def run_status_command(
        self,
        repo_root: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.build_status_command(),
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )

    def build_git_root_command(self) -> list[str]:
        return ["git", "rev-parse", "--show-toplevel"]

    def run_git_root_command(self, cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.build_git_root_command(),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )


def run_diff(staged: bool, repo_root: Path) -> DiffScanResult:
    runner = GitDiffRunner()
    parser = DiffParser()
    completed = runner.run_diff_command(repo_root=repo_root, staged=staged)

    if completed.returncode != 0:
        return DiffScanResult(
            scan_id=make_scan_id(),
            is_staged=staged,
            changed_files=[],
            git_root=str(repo_root),
            error=completed.stderr.strip() or "Git diff failed",
        )

    changed_files = parser.parse_name_status(completed.stdout, staged=staged)
    content_completed = runner.run_content_diff_command(
        repo_root=repo_root,
        staged=staged,
    )

    if content_completed.returncode == 0:
        findings_by_path = parser.parse_secret_findings_from_diff(
            content_completed.stdout
        )

        for changed_file in changed_files:
            changed_file.secret_findings = findings_by_path.get(
                changed_file.path,
                [],
            )

    if not staged:
        status_completed = runner.run_status_command(repo_root=repo_root)
        if status_completed.returncode != 0:
            return DiffScanResult(
                scan_id=make_scan_id(),
                is_staged=staged,
                changed_files=[],
                git_root=str(repo_root),
                error=status_completed.stderr.strip() or "Git status failed",
            )

        changed_files.extend(
            parser.parse_status_porcelain(status_completed.stdout)
        )

    return DiffScanResult(
        scan_id=make_scan_id(),
        is_staged=staged,
        changed_files=changed_files,
        git_root=str(repo_root),
    )


def find_git_root(cwd: Path) -> Path | None:
    completed = GitDiffRunner().run_git_root_command(cwd=cwd)

    if completed.returncode != 0:
        return None

    root = completed.stdout.strip()
    if not root:
        return None

    return Path(root)
