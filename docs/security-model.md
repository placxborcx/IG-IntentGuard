# Security Model

IntentGuard MVP1a assumes all working tree changes may have been created or
modified by an AI coding agent. It does not try to identify the author of each
change. Instead, it evaluates the Git diff against deterministic local policy.

## Invariants

- `.env`, `.env.*`, secret-like files, IAM-like JSON files, and detected
  obvious secrets are hard-blocked by default.
- Hard blocks cannot be unlocked with normal approval.
- Approval-required files need a valid, unexpired approval before pre-commit
  enforcement allows the Git operation.
- Task boundary warnings are advisory in MVP1a.
- Every scan writes local audit events and scan records.
- Scan and audit output should avoid raw secret values and full source patches.

## Decision Order

IntentGuard applies the strictest relevant decision:

1. Detected secret or blocked path: `BLOCK`.
2. Approval-required path: `REQUIRE_APPROVAL`.
3. File outside active task scope: `WARN_OUT_OF_SCOPE`.
4. Normal change: `ALLOW_WITH_AUDIT`.

The final scan decision is:

- `BLOCK` if any changed file is blocked;
- `REQUIRE_APPROVAL` if no files are blocked but at least one file requires
  approval;
- `ALLOW_WITH_AUDIT` otherwise.

## Default Risk Areas

MVP1a treats these as sensitive by default:

- environment files;
- secret-like filenames;
- IAM-like JSON files;
- CI/CD workflows;
- Terraform and infrastructure paths;
- Docker and compose files;
- authentication-related source paths;
- obvious secret-like values in added diff lines.

## Out Of Scope

- Cloud dashboard.
- Verified user identity.
- Tamper-proof logs.
- Enterprise policy administration.
- LLM-based semantic classification.
- Complete malware or malicious-code detection.
- Real-time terminal command interception.
