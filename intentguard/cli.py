from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

import typer

from intentguard.approvals import (
    append_approval,
    approval_required_files,
    build_approval_record,
    has_valid_approval_for_scan,
    scan_has_blocking_decision,
)
from intentguard.audit.log import (
    append_audit_event,
    append_scan_record,
    build_audit_event,
    find_scan_record,
)
from intentguard.hooks import install_pre_commit_hook
from intentguard.policy import load_policy, write_default_policy
from intentguard.policy.decision import decide_scan_result
from intentguard.scanner.git_diff import find_git_root, run_diff
from intentguard.tasks import create_task_session, get_active_task

app = typer.Typer(help="IntentGuard local-first security guard for AI coding agents.")


@app.callback()
def main() -> None:
    """IntentGuard command group."""


@app.command()
def init(
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing IntentGuard files. Use with care.",
    )
) -> None:
    """Initialize IntentGuard configuration in the current repository."""
    root = Path.cwd()
    intentguard_dir = root / ".intentguard"
    policy_path = intentguard_dir / "policy.yaml"
    tasks_path = intentguard_dir / "tasks.json"
    approvals_path = intentguard_dir / "approvals.json"
    audit_path = intentguard_dir / "audit.jsonl"

    intentguard_dir.mkdir(exist_ok=True)

    created: list[Path] = []
    skipped: list[Path] = []

    def write_text_once(path: Path, text: str) -> None:
        if path.exists() and not force:
            skipped.append(path)
            return
        path.write_text(text, encoding="utf-8")
        created.append(path)

    if policy_path.exists() and not force:
        skipped.append(policy_path)
    else:
        write_default_policy(policy_path)
        created.append(policy_path)

    write_text_once(tasks_path, "[]\n")
    write_text_once(approvals_path, "[]\n")
    write_text_once(audit_path, "")

    for path in created:
        typer.echo(f"created {path.relative_to(root)}")
    for path in skipped:
        typer.echo(f"exists  {path.relative_to(root)}")


@app.command("create-task")
def create_task(
    intent: str,
    allow: list[str] = typer.Option(
        [],
        "--allow",
        help="Allowed file path pattern. Can be used multiple times.",
    ),
    agent: Optional[str] = typer.Option(
        None,
        "--agent",
        help="Agent identifier.",
    ),
) -> None:
    """Create a new task boundary for AI agent changes."""
    root = Path.cwd()
    tasks_path = root / ".intentguard" / "tasks.json"

    if not tasks_path.exists():
        raise typer.BadParameter(
            "IntentGuard is not initialized. Run `intentguard init` first."
        )

    task = create_task_session(
        tasks_path=tasks_path,
        intent=intent,
        allowed_paths=allow,
        agent=agent,
    )

    typer.echo(f"created task {task.task_id}")


@app.command("install-hooks")
def install_hooks(
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing IntentGuard Git hooks.",
    ),
) -> None:
    """Install IntentGuard Git hooks."""
    root = Path.cwd()
    git_root = find_git_root(root)

    if git_root is None:
        typer.echo("Not a Git repository.", err=True)
        raise typer.Exit(code=1)

    hook_path = install_pre_commit_hook(
        git_root=git_root,
        force=force,
    )

    typer.echo(f"installed {hook_path.relative_to(git_root)}")


@app.command("approve")
def approve(
    scan_id: str,
    reason: str = typer.Option(
        "Manual review approved.",
        "--reason",
        help="Approval reason.",
    ),
) -> None:
    """Approve all approval-required files in a persisted scan."""
    root = Path.cwd()
    intentguard_dir = root / ".intentguard"

    scan_record = find_scan_record(intentguard_dir / "scans.jsonl", scan_id)
    if scan_record is None:
        typer.echo(f"Scan '{scan_id}' was not found.", err=True)
        raise typer.Exit(code=1)

    if scan_has_blocking_decision(scan_record):
        typer.echo(
            "This scan contains blocked files and cannot be approved.",
            err=True,
        )
        raise typer.Exit(code=1)

    approved_files = approval_required_files(scan_record)
    if not approved_files:
        typer.echo(
            "This scan does not contain files that require approval.",
            err=True,
        )
        raise typer.Exit(code=1)

    policy = load_policy(intentguard_dir / "policy.yaml")
    created_at = datetime.now(UTC).replace(microsecond=0)
    approval = build_approval_record(
        scan_record=scan_record,
        approved_files=approved_files,
        approver="human",
        reason=reason,
        ttl_minutes=policy.approval_ttl_minutes,
        created_at=created_at,
    )

    append_approval(intentguard_dir / "approvals.json", approval)
    append_audit_event(
        audit_path=intentguard_dir / "audit.jsonl",
        event=build_audit_event(
            task_id=approval["task_id"],
            scan_id=approval["scan_id"],
            agent=None,
            action="approval_created",
            target=approval["scan_id"],
            risk="medium",
            decision="approved",
            reason=approval["reason"],
        ),
    )

    typer.echo(f"approved scan {scan_id}")
    typer.echo(f"expires at {approval['expires_at']}")
    typer.echo("approved files:")
    for path in approved_files:
        typer.echo(f"- {path}")


@app.command("scan-diff")
def scan_diff(
    staged: bool = typer.Option(
        False,
        "--staged",
        help="Scan staged Git changes only.",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text or json.",
    ),
    enforce: bool = typer.Option(
        False,
        "--enforce",
        help="Exit non-zero when scan result blocks the Git operation.",
    ),
) -> None:
    """Scan Git changed-file metadata."""
    root = Path.cwd()
    git_root = find_git_root(root)

    if git_root is None:
        typer.echo("Not a Git repository.", err=True)
        raise typer.Exit(code=1)

    intentguard_dir = git_root / ".intentguard"
    if not (intentguard_dir / "policy.yaml").exists() or not (
        intentguard_dir / "tasks.json"
    ).exists():
        typer.echo(
            "IntentGuard is not initialized. Run `intentguard init` first.",
            err=True,
        )
        raise typer.Exit(code=1)

    result = run_diff(staged=staged, repo_root=git_root)
    if result.has_error:
        typer.echo(result.error or "Git diff scan failed.", err=True)
        raise typer.Exit(code=1)

    active_task = get_active_task(intentguard_dir / "tasks.json")
    if active_task is not None:
        result.task_id = active_task.task_id

    policy = load_policy(intentguard_dir / "policy.yaml")
    allowed_paths = active_task.allowed_paths if active_task is not None else []
    scan_result = decide_scan_result(
        diff_result=result,
        policy=policy,
        allowed_paths=allowed_paths,
    )
    append_scan_record(
        records_path=intentguard_dir / "scans.jsonl",
        scan_result=scan_result,
    )
    append_audit_event(
        audit_path=intentguard_dir / "audit.jsonl",
        event=build_audit_event(
            task_id=scan_result.task_id,
            scan_id=scan_result.scan_id,
            agent=active_task.agent if active_task is not None else None,
            action="scan_completed",
            target="scan",
            risk=scan_result.overall_risk.value,
            decision=scan_result.final_decision.value.lower(),
            reason="Scan completed.",
        ),
    )

    for changed_file in scan_result.changed_files:
        append_audit_event(
            audit_path=intentguard_dir / "audit.jsonl",
            event=build_audit_event(
                task_id=scan_result.task_id,
                scan_id=scan_result.scan_id,
                agent=active_task.agent if active_task is not None else None,
                action="file_decision",
                target=changed_file.path,
                risk=changed_file.risk.value,
                decision=changed_file.decision.value.lower(),
                reason=changed_file.reason,
            ),
        )

    if output_format == "json":
        typer.echo(json.dumps(scan_result.model_dump(mode="json")))
        return

    typer.echo("IntentGuard Scan Result")
    typer.echo(f"Risk: {scan_result.overall_risk.value}")
    typer.echo(f"Decision: {scan_result.final_decision.value}")

    for changed_file in scan_result.changed_files:
        typer.echo(
            f"{changed_file.path} "
            f"{changed_file.change_type.value} "
            f"{changed_file.risk.value} "
            f"{changed_file.decision.value} "
            f"{changed_file.reason}"
        )

    if enforce:
        scan_record = scan_result.model_dump(mode="json")
        has_valid_approval = has_valid_approval_for_scan(
            approvals_path=intentguard_dir / "approvals.json",
            scans_path=intentguard_dir / "scans.jsonl",
            scan_record=scan_record,
            now=datetime.now(UTC),
        )

        if scan_result.final_decision.value == "BLOCK" or (
            scan_result.final_decision.value == "REQUIRE_APPROVAL"
            and not has_valid_approval
        ):
            typer.echo("IntentGuard blocked this Git operation.", err=True)
            typer.echo(
                "Run `intentguard scan-diff --staged` to review the decision.",
                err=True,
            )
            typer.echo(
                "If the scan requires approval, run `intentguard approve <scan_id>` and retry.",
                err=True,
            )
            raise typer.Exit(code=1)


@app.command("audit")
def audit() -> None:
    """View local IntentGuard audit events."""
    root = Path.cwd()
    audit_path = root / ".intentguard" / "audit.jsonl"

    if not audit_path.exists():
        typer.echo(
            "IntentGuard audit log not found. Run `intentguard init` first.",
            err=True,
        )
        raise typer.Exit(code=1)

    lines = [
        line
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    if not lines:
        typer.echo("No audit events found.")
        return

    for line in lines:
        event = json.loads(line)
        typer.echo(
            f"{event['timestamp']} "
            f"{event['event_id']} "
            f"{event['action']} "
            f"{event['decision']} "
            f"{event['target']} "
            f"{event['reason']}"
        )


if __name__ == "__main__":
    app()
