"""Smoke tests for IntentGuard CLI."""

import subprocess
import sys


def test_cli_help():
    """Test that intentguard --help works."""
    result = subprocess.run(
        [sys.executable, "-m", "intentguard.main", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "intentguard" in result.stdout.lower()
    assert "Usage" in result.stdout


def test_cli_init_command_exists():
    """Test that init command is available."""
    result = subprocess.run(
        [sys.executable, "-m", "intentguard.main", "init", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Initialize" in result.stdout or "Git repository" in result.stdout


def test_cli_create_task_command_exists():
    """Test that create-task command is available."""
    result = subprocess.run(
        [sys.executable, "-m", "intentguard.main", "create-task", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_scan_diff_command_exists():
    """Test that scan-diff command is available."""
    result = subprocess.run(
        [sys.executable, "-m", "intentguard.main", "scan-diff", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
