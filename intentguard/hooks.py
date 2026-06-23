from __future__ import annotations

import stat
from pathlib import Path


PRE_COMMIT_HOOK = """#!/bin/sh
intentguard scan-diff --staged --enforce
"""


def install_pre_commit_hook(
    *,
    git_root: Path,
    force: bool = False,
) -> Path:
    hook_path = git_root / ".git" / "hooks" / "pre-commit"

    if hook_path.exists() and not force:
        return hook_path

    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(PRE_COMMIT_HOOK, encoding="utf-8")

    current_mode = hook_path.stat().st_mode
    hook_path.chmod(current_mode | stat.S_IXUSR)

    return hook_path