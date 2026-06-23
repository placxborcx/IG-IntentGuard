# IntentGuard MVP1a Preview

> Local-first security checks for AI-assisted coding workflows.

IntentGuard helps developers let AI coding agents move fast without giving them
unlimited trust. It scans Git diffs, applies deterministic policy decisions,
blocks selected sensitive changes, requires approval for high-risk engineering
paths, and writes local audit logs.

This repository is the **MVP1a public preview**: a CLI-first, local-only version
focused on Git diff scanning and pre-commit protection.

## Team

IntentGuard is a two-person project:

- **SWE:** Sylvia
- **Security:** Mike

The project is intentionally split between developer experience and security
decision design.

## Why It Exists

AI coding agents such as Claude Code, Codex, Cursor, and Copilot Agent can now
modify files, install packages, open PRs, and trigger workflows. That is useful,
but it creates a new problem:

> How do you let AI agents help with code without trusting every file change by
> default?

IntentGuard sits between AI-generated changes and your Git history. MVP1a does
not try to prove whether a human or an AI made a change. It treats all Git
working tree changes as untrusted and checks them against local policy.

## What MVP1a Can Do

- Initialize local `.intentguard/` policy and runtime files.
- Create task boundaries with manually allowed paths.
- Scan staged or unstaged Git diffs.
- Warn when changes are outside the active task scope.
- Block selected sensitive paths such as `.env` and IAM-like files.
- Block obvious secret-like values in added diff lines.
- Require approval for CI/CD, Terraform, infra, Docker, compose, and auth paths.
- Persist scan records and local JSONL audit events.
- Install a pre-commit hook that enforces staged scan decisions.

## Quick Start

Use Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
intentguard --help
```

Inside any Git repository:

```bash
intentguard init
intentguard create-task "Fix login bug" --allow "src/auth/**" --allow "tests/**"
```

After your AI coding agent or editor changes files:

```bash
intentguard scan-diff
intentguard scan-diff --staged
```

Install pre-commit enforcement:

```bash
intentguard install-hooks
git commit
```

If a staged scan requires approval:

```bash
intentguard scan-diff --staged
intentguard approve <scan_id> --reason "Reviewed intentional sensitive change."
git commit
```

Blocked changes, such as `.env` edits or detected secret-like values, cannot be
approved through in MVP1a.

## Commands

```bash
intentguard init
intentguard create-task "Fix login bug" --allow "src/auth/**" --allow "tests/**"
intentguard scan-diff
intentguard scan-diff --staged
intentguard scan-diff --format json
intentguard approve <scan_id>
intentguard audit
intentguard install-hooks
```

## Default Policy

Hard-blocked paths:

```yaml
blocked_paths:
  - ".env"
  - ".env.*"
  - "**/*secret*"
  - "**/*iam*.json"
```

Approval-required paths:

```yaml
approval_required_paths:
  - ".github/workflows/**"
  - "terraform/**"
  - "infra/**"
  - "Dockerfile"
  - "docker-compose.yml"
  - "src/auth/**"
```

Decision meanings:

| Decision | Meaning |
|---|---|
| `BLOCK` | Hard block. Normal approval cannot unlock this. |
| `REQUIRE_APPROVAL` | Requires human approval before enforcement can pass. |
| `WARN_OUT_OF_SCOPE` | Outside the declared task boundary. Advisory in MVP1a. |
| `ALLOW_WITH_AUDIT` | Allowed, but logged locally. |

## Current Limitations

This is a public preview, not a production-ready security platform.

- Secret detection is best-effort and pattern-based.
- Task boundaries are advisory in MVP1a.
- Local audit logs are useful for review but are not tamper-proof.
- Pre-push and ranged scanning are not complete yet.
- VS Code Extension and GitHub Action are planned for MVP1b.
- IntentGuard does not replace human code review.
- IntentGuard does not detect all malicious logic changes.
- The local approver value `human` is not verified identity.
- There is no cloud dashboard, SSO, SIEM, RBAC, or enterprise policy service.

See [docs/limitations.md](docs/limitations.md) and
[docs/public-preview-readiness.md](docs/public-preview-readiness.md).

## Roadmap

**MVP1a: Core local enforcement**

- CLI
- YAML policy
- Git diff scanner
- Built-in secret pattern checks
- JSONL audit log
- Scan-level approval with TTL
- Pre-commit hook enforcement

**MVP1b: Developer-facing surfaces**

- VS Code Extension
- GitHub Action
- Markdown / PR-friendly report output

**Future direction**

- Team policy management
- Dashboard
- Stronger CI/CD and deploy gates
- Enterprise controls
- SIEM or audit integrations

Future roadmap items are not implemented in this MVP1a preview.

## Test

```bash
pytest
```

## License

MIT
