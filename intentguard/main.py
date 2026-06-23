"""IntentGuard CLI entry point."""

import typer
from typing import List, Optional

app = typer.Typer(
    name="intentguard",
    help="Local-first security guard for autonomous AI coding agents",
)


@app.command()
def init() -> None:
    """Initialize IntentGuard in a Git repository."""
    typer.echo("✓ Initializing IntentGuard...")


@app.command()
def create_task(
    intent: str,
    allow: Optional[List[str]] = typer.Option(None, help="Allowed file paths"),
    agent: Optional[str] = typer.Option(None, help="Agent identifier"),
) -> None:
    """Create a new task boundary for AI agent changes."""
    typer.echo(f"✓ Creating task: {intent}")


@app.command()
def scan_diff(
    staged: bool = typer.Option(False, help="Scan staged changes only"),
    format: str = typer.Option("text", help="Output format: text or json"),
) -> None:
    """Scan Git diff for policy violations."""
    typer.echo("✓ Scanning diff...")


@app.command()
def install_hooks() -> None:
    """Install Git hooks for pre-commit/pre-push enforcement."""
    typer.echo("✓ Installing Git hooks...")


@app.command()
def approve(scan_id: str) -> None:
    """Approve a scan that requires human approval."""
    typer.echo(f"✓ Approving scan: {scan_id}")


@app.command()
def audit() -> None:
    """View local audit log."""
    typer.echo("✓ Audit log:")


if __name__ == "__main__":
    app()
