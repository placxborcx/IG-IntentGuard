# Demo Flow

This demo shows the local MVP1a value in a small Git repository.

## 1. Initialize

```bash
intentguard init
```

Expected local files:

```text
.intentguard/
  policy.yaml
  tasks.json
  approvals.json
  audit.jsonl
```

## 2. Create A Task Boundary

```bash
intentguard create-task "Fix login bug" --allow "src/auth/**" --allow "tests/**"
```

The task boundary is advisory in MVP1a. Out-of-scope files should be visible as
warnings, while blocked paths and secret findings remain hard blocks.

## 3. Allow A Scoped Change

Modify or stage a normal file under an allowed path, then run:

```bash
intentguard scan-diff --staged
```

Expected decision:

```text
ALLOW_WITH_AUDIT
```

## 4. Require Approval For Auth Or Workflow Changes

Modify or stage one of these paths:

```text
src/auth/login.py
.github/workflows/deploy.yml
```

Then run:

```bash
intentguard scan-diff --staged
```

Expected decision:

```text
REQUIRE_APPROVAL
```

Approve after human review:

```bash
intentguard approve <scan_id> --reason "Reviewed intentional sensitive change."
```

## 5. Block Sensitive Files

Create or modify a fake `.env` file:

```text
DEMO_TOKEN=fake-value-only
```

Run:

```bash
intentguard scan-diff --staged
```

Expected decision:

```text
BLOCK
```

The `.env` change cannot be approved through in MVP1a.

## 6. Install Pre-Commit Enforcement

```bash
intentguard install-hooks
```

The generated pre-commit hook runs:

```bash
intentguard scan-diff --staged --enforce
```

## 7. Review Audit Events

```bash
intentguard audit
```

Audit output should show scan decisions, approval events, targets, reasons, and
timestamps without raw source patches or raw secret values.
