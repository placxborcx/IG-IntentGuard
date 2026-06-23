from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class PolicyValidationError(ValueError):
    """Raised when policy configuration violates IntentGuard security rules."""


class SecretDetectionPolicy(BaseModel):
    enabled: bool = True
    engine: str = "builtin"
    decision: str = "BLOCK"

    model_config = {"extra": "forbid"}

    @field_validator("engine")
    @classmethod
    def validate_engine(cls, value: str) -> str:
        if value != "builtin":
            raise ValueError('secret_detection.engine must be "builtin" for MVP1a')
        return value

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        if value != "BLOCK":
            raise ValueError('secret_detection.decision must be "BLOCK" for MVP1a')
        return value


class Policy(BaseModel):
    default_decision: str = "ALLOW_WITH_AUDIT"
    approval_ttl_minutes: int = Field(default=30, ge=1)
    blocked_paths: list[str]
    approval_required_paths: list[str]
    secret_detection: SecretDetectionPolicy = Field(default_factory=SecretDetectionPolicy)

    model_config = {"extra": "forbid"}

    @field_validator("default_decision")
    @classmethod
    def validate_default_decision(cls, value: str) -> str:
        if value != "ALLOW_WITH_AUDIT":
            raise ValueError('default_decision must be "ALLOW_WITH_AUDIT" for MVP1a')
        return value

    @field_validator("blocked_paths", "approval_required_paths")
    @classmethod
    def validate_path_patterns(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("path pattern lists must not be empty")
        seen: set[str] = set()
        for pattern in value:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError("path patterns must be non-empty strings")
            if pattern in seen:
                raise ValueError(f'duplicate path pattern "{pattern}"')
            seen.add(pattern)
        return value

    @model_validator(mode="after")
    def validate_mutually_exclusive_paths(self) -> Policy:
        conflicts = sorted(set(self.blocked_paths) & set(self.approval_required_paths))
        if conflicts:
            pattern = conflicts[0]
            raise ValueError(
                f'path pattern "{pattern}" appears in both blocked_paths and '
                "approval_required_paths. Blocked paths cannot be approval-unlockable."
            )
        return self


def default_policy_text() -> str:
    """Return the bundled default policy.yaml content."""
    return resources.files("intentguard.policies").joinpath("policy.yaml").read_text(
        encoding="utf-8"
    )


def default_policy() -> Policy:
    """Load and validate the bundled default policy."""
    return parse_policy(default_policy_text())


def parse_policy(text: str) -> Policy:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise PolicyValidationError("Invalid policy: policy.yaml must contain a YAML mapping.")
    return validate_policy(data)


def load_policy(path: Path) -> Policy:
    return parse_policy(path.read_text(encoding="utf-8"))


def validate_policy(data: dict[str, Any]) -> Policy:
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyValidationError(f"Invalid policy: {exc}") from exc


def write_default_policy(path: Path) -> None:
    path.write_text(default_policy_text(), encoding="utf-8")
