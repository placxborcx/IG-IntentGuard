from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from intentguard.models import TaskSession


def load_tasks(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_tasks(path: Path, tasks: list[dict]) -> None:
    path.write_text(json.dumps(tasks, indent=2) + "\n", encoding="utf-8")


def create_task_session(
    tasks_path: Path,
    intent: str,
    allowed_paths: list[str],
    agent: str | None = None,
) -> TaskSession:
    tasks = load_tasks(tasks_path)

    for existing_task in tasks:
        if existing_task.get("status") == "active":
            existing_task["status"] = "archived"

    task = TaskSession(
        task_id=f"task_{len(tasks) + 1:03d}",
        intent=intent,
        agent=agent,
        allowed_paths=allowed_paths,
        status="active",
        created_at=datetime.utcnow(),
    )

    tasks.append(task.model_dump(mode="json"))
    save_tasks(tasks_path, tasks)

    return task


def get_active_task(tasks_path: Path) -> TaskSession | None:
    tasks = load_tasks(tasks_path)

    for task_data in reversed(tasks):
        if task_data.get("status") == "active":
            return TaskSession.model_validate(task_data)

    return None
