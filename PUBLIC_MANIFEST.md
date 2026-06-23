# Public MVP1a Folder Manifest

This folder is prepared to become the root of a new public GitHub repository.

## Included

- `intentguard/`: MVP1a Python CLI implementation.
- `tests/`: MVP1a pytest coverage.
- `pyproject.toml`: package metadata and dependencies.
- `README.md`: public-facing overview, install, quick demo, and limitations.
- `README中文.md`: Traditional Chinese overview for MVP1a public preview.
- `LICENSE`: MIT license placeholder for IntentGuard Team.
- `.gitignore`: Python and local IntentGuard runtime ignores.
- `.github/workflows/tests.yml`: GitHub Actions pytest workflow.
- `docs/limitations.md`: honest MVP1a limitations.
- `docs/security-model.md`: local-first security model.
- `docs/public-preview-readiness.md`: public preview scope, architecture
  specification, claims guidance, and release checklist.
- `examples/demo-flow.md`: suggested public demo.
- `examples/demo-policy.yaml`: readable copy of the default policy.

## Excluded

- Private planning notes.
- Local `.intentguard/` runtime state.
- `intentguard.egg-info/`.
- Python `__pycache__/` files.
- Internal sprint handoff documents.

## Suggested Public Repo Setup

1. Create a new public GitHub repository.
2. Upload the contents of this folder as the repository root.
3. Confirm GitHub Actions runs successfully.
4. Create a release tag such as `v0.1.0-mvp1a-preview`.
5. Keep README claims aligned with the documented limitations.
