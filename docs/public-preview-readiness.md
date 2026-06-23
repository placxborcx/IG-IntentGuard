# MVP1a Public Preview Readiness

This document defines what "public preview" means for IntentGuard MVP1a, what is
currently safe to publish, and what must be verified before creating a public
GitHub repository.

## What Public Preview Means

Public preview means the project is usable by early technical users for local
experimentation, feedback, demos, and code review.

It does not mean production-ready, enterprise-ready, complete, or guaranteed
secure. For IntentGuard MVP1a, public preview should be described as:

```text
An early local-first CLI preview for scanning Git changes, applying deterministic
security policy decisions, requiring approval for selected sensitive paths, and
recording local audit events.
```

Use this shorter public wording:

```text
IntentGuard detects selected high-risk paths and obvious secret patterns in Git
changes, then blocks or requires approval before those changes move through the
local workflow.
```

## Current Publicly Usable Content

The `Public Content/mvp1a` folder is designed to become the root of a new public
GitHub repository.

Included public files:

- `README.md`: public product overview, install commands, demo, limitations.
- `LICENSE`: MIT license placeholder for IntentGuard Team.
- `pyproject.toml`: Python packaging metadata and dependencies.
- `.gitignore`: Python build files and local IntentGuard runtime state.
- `.github/workflows/tests.yml`: GitHub Actions pytest workflow.
- `PUBLIC_MANIFEST.md`: public folder inventory and setup notes.
- `docs/limitations.md`: explicit MVP1a limitations.
- `docs/security-model.md`: current security model and decision order.
- `docs/public-preview-readiness.md`: this release-readiness document.
- `examples/demo-flow.md`: suggested demo script.
- `examples/demo-policy.yaml`: readable default policy copy.
- `intentguard/`: MVP1a CLI source code.
- `tests/`: MVP1a pytest test suite.

## Current MVP1a Functional Surface

Public users can try these commands:

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

Supported MVP1a behavior:

- Initialize `.intentguard/` local config and runtime files.
- Create one or more task sessions with manually supplied allowed paths.
- Scan unstaged or staged Git changes.
- Detect added, modified, deleted, renamed, and copied paths from Git metadata.
- Apply deterministic path policy decisions.
- Hard-block selected sensitive paths.
- Hard-block obvious secret-like values detected in added diff lines.
- Require approval for selected high-risk engineering paths.
- Persist scan records locally.
- Create scan-level approval records with TTL.
- Write local JSONL audit events.
- Install pre-commit enforcement for staged changes.

## Current Security Decision Rules

Decision precedence:

1. Detected secret or blocked path: `BLOCK`.
2. Approval-required path: `REQUIRE_APPROVAL`.
3. Outside active task boundary: `WARN_OUT_OF_SCOPE`.
4. Normal change: `ALLOW_WITH_AUDIT`.

Default hard-blocked paths:

```yaml
blocked_paths:
  - ".env"
  - ".env.*"
  - "**/*secret*"
  - "**/*iam*.json"
```

Default approval-required paths:

```yaml
approval_required_paths:
  - ".github/workflows/**"
  - "terraform/**"
  - "infra/**"
  - "Dockerfile"
  - "docker-compose.yml"
  - "src/auth/**"
```

Security invariants for public preview:

- Hard-blocked files cannot be approved through normal approval.
- Detected secret-like values should never be printed raw in CLI, JSON, or audit
  output.
- Approval should only unlock approval-required files, not blocked files.
- Approval is local and TTL-based.
- Task boundary warnings remain advisory in MVP1a.
- Local audit is append-oriented JSONL, but not tamper-proof.

## Public Architecture Specification

The public repo should keep this structure:

```text
.
├── README.md
├── LICENSE
├── pyproject.toml
├── .gitignore
├── PUBLIC_MANIFEST.md
├── .github/
│   └── workflows/
│       └── tests.yml
├── docs/
│   ├── limitations.md
│   ├── public-preview-readiness.md
│   └── security-model.md
├── examples/
│   ├── demo-flow.md
│   └── demo-policy.yaml
├── intentguard/
│   ├── cli.py
│   ├── models.py
│   ├── tasks.py
│   ├── approvals.py
│   ├── hooks.py
│   ├── secrets.py
│   ├── audit/
│   ├── policies/
│   ├── policy/
│   └── scanner/
└── tests/
```

Architecture rules:

- Keep MVP1a local-first. Do not add cloud login, source upload, dashboard,
  OAuth, SSO, SIEM, or RBAC dependencies.
- Keep policy deterministic. Do not add LLM inference to policy decisions in
  MVP1a.
- Keep CLI logic reusable by hooks and future integrations.
- Keep output useful for both humans and automation.
- Keep audit and scan records free of raw source patches and raw secret values.
- Keep README claims aligned with `docs/limitations.md`.
- Do not include private sprint handoffs or internal planning notes in the
  public repo.
- Do not include local runtime state such as `.intentguard/tasks.json`,
  `.intentguard/approvals.json`, `.intentguard/audit.jsonl`, or
  `.intentguard/scans.jsonl`.

## Claims That Are Safe

These claims are acceptable for public preview:

- Local-first Git diff scanning.
- Deterministic policy decisions.
- Selected sensitive path blocking.
- Best-effort obvious secret pattern blocking.
- Approval required for selected engineering paths.
- Local JSONL audit events.
- Pre-commit enforcement for staged changes.
- MVP1a preview for early feedback.

## Claims To Avoid

Do not claim:

- "Blocks all secrets."
- "Prevents malicious code."
- "Detects all high-risk changes."
- "Guarantees safe AI agent behavior."
- "Provides tamper-proof audit logs."
- "Verifies human identity."
- "Enterprise-ready."
- "Production-ready."
- "Full pre-push enforcement."
- "GitHub Action support is complete."
- "VS Code Extension support is complete."

## Release Checklist Before Publishing

Before uploading `Public Content/mvp1a` to a new public GitHub repo:

- Confirm `README.md` renders correctly on GitHub.
- Confirm `LICENSE` uses the intended copyright owner.
- Confirm no private planning notes are included.
- Confirm no `.intentguard/` runtime files are included.
- Confirm no `__pycache__/`, `.pytest_cache/`, `*.egg-info/`, `dist/`, or
  `build/` files are included.
- Create a clean virtual environment.
- Run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
intentguard --help
pytest
```

- Confirm GitHub Actions passes after the repo is created.
- Confirm the demo flow works in a temporary Git repo.
- Confirm `.env` changes are blocked.
- Confirm `.github/workflows/**` or `src/auth/**` changes require approval.
- Confirm `intentguard approve <scan_id>` does not approve blocked scans.
- Confirm `intentguard audit` shows useful decision reasons.
- Confirm README does not claim pre-push or ranged scanning is complete.

## Release Recommendation

If all checklist items pass, publish as:

```text
v0.1.0-mvp1a-preview
```

Recommended GitHub description:

```text
Local-first policy guard for AI coding agent Git changes.
```

Recommended pinned caveat:

```text
MVP1a public preview: local CLI, deterministic path policy, best-effort secret
checks, approval workflow, audit logs, and pre-commit enforcement. Not
production-ready.
```

## Final Safety Position

This public preview can be made responsible and useful, but it should not be
called "fail-proof" or "guaranteed secure." The safer standard is:

```text
Public preview is acceptable when the code, tests, docs, limitations, and claims
all match the actual MVP1a behavior.
```
