# MVP1a Limitations

IntentGuard MVP1a is an early local-first preview. It is designed to show the
core value of policy checks around AI coding agent file changes, not to provide
complete application security coverage.

## Security Scope

- Secret detection is best-effort and regex-based.
- It scans changed lines in Git diffs, not every historical or generated file.
- It does not detect every credential, token, or malicious pattern.
- It does not perform semantic code analysis.
- It does not replace human code review.

## Workflow Scope

- Task boundaries are advisory in MVP1a.
- Out-of-scope files can produce `WARN_OUT_OF_SCOPE`, but this is not a hard
  block unless another stricter rule applies.
- Pre-commit enforcement is available.
- Pre-push and ranged scanning are not complete yet.
- GitHub Action and VS Code Extension surfaces are future MVP1b work.

## Trust Model

- IntentGuard runs locally and does not upload source code by default.
- Local audit files are useful for review but are not tamper-proof.
- A compromised local environment can modify `.intentguard/` files.
- The approver value `human` is local context, not verified identity.
- There is no cloud identity, SSO, SIEM, RBAC, or enterprise policy service in
  this MVP1a preview.

## Safe Claims

Use this wording when describing the preview:

```text
IntentGuard detects selected high-risk paths and obvious secret patterns in Git
changes, then blocks or requires approval before those changes move through the
local workflow.
```

Avoid stronger claims such as:

- "blocks all secrets";
- "prevents malicious code";
- "detects all high-risk changes";
- "guarantees safe AI agent behavior";
- "provides tamper-proof audit logs";
- "verifies human identity".
