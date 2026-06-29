# IntentGuard MVP1a Public Preview

> 為 AI 輔助開發工作流設計的 local-first 安全檢查工具。

IntentGuard 的目標是讓 AI coding agents 可以加速開發，但不被無限制信任。
它會掃描 Git diff，依照本機 policy 做出 deterministic security decisions，阻擋特定敏感變更，對高風險工程路徑要求人工 approval，並寫入本機 audit log。

這個repository是 **MVP1a public preview**：以 CLI 為主、local-only、聚焦 Git diff scanning 和 pre-commit protection。

## 團隊
- **SWE:** Sylvia
- **Security:** Mike

## 為什麼需要 IntentGuard

Claude Code、Codex、Cursor、Copilot Agent 這類 AI coding agents 已經可以修改檔案、安裝套件、開 PR，甚至觸發 workflow。這很有用，但也帶來一個問題：
> 如何讓 AI agents 幫忙寫程式，但不預設信任它們修改的每一個檔案？

IntentGuard 站在 AI 產生的變更和 Git history 之間。MVP1a 不嘗試判斷變更到底是人類還是 AI 產生，而是把所有 Git working tree changes 都視為 untrusted (Zero-Trust)，並套用本機 policy 檢查。

## MVP1a 目前可以做什麼
- 初始化本機 `.intentguard/` policy 和 runtime files。
- 用手動 allowed paths 建立 task boundary。
- 掃描 staged 或 unstaged Git diffs。
- 對超出 task scope 的變更發出 warning。
- 阻擋 `.env`、IAM-like files 等敏感路徑。
- 阻擋新增 diff lines 裡明顯像 secret 的值。
- 對 CI/CD、Terraform、infra、Docker、compose、auth paths 要求 approval。
- 保存 scan records 和本機 JSONL audit events。
- 安裝 pre-commit hook，在 commit 前 enforce staged scan decisions。

## 快速開始
需要 Python 3.11 或更新版本。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
intentguard --help
```

在任何 Git repository 裡：

```bash
intentguard init
intentguard create-task "Fix login bug" --allow "src/auth/**" --allow "tests/**"
```

當 AI coding agent 或 editor 修改檔案後：

```bash
intentguard scan-diff
intentguard scan-diff --staged
```

安裝 pre-commit enforcement：

```bash
intentguard install-hooks
git commit
```

如果 staged scan 需要 approval：

```bash
intentguard scan-diff --staged
intentguard approve <scan_id> --reason "Reviewed intentional sensitive change."
git commit
```

被 hard-block 的變更，例如 `.env` edits 或偵測到 secret-like values，在 MVP1a 不能透過 approval 解鎖。

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

Hard-blocked paths：

```yaml
blocked_paths:
  - ".env"
  - ".env.*"
  - "**/*secret*"
  - "**/*iam*.json"
```

Approval-required paths：

```yaml
approval_required_paths:
  - ".github/workflows/**"
  - "terraform/**"
  - "infra/**"
  - "Dockerfile"
  - "docker-compose.yml"
  - "src/auth/**"
```

Decision meanings：

| Decision | 說明 |
|---|---|
| `BLOCK` | 硬阻擋，不能用一般 approval 解鎖。 |
| `REQUIRE_APPROVAL` | 需要人工 approval 後 enforcement 才能通過。 |
| `WARN_OUT_OF_SCOPE` | 超出 task boundary，MVP1a 中是 advisory warning。 |
| `ALLOW_WITH_AUDIT` | 允許，但會寫入本機 audit log。 |

## 目前限制

這是 public preview，不是 production-ready security platform。

- Secret detection 是 best-effort，且基於 pattern。
- Task boundary 在 MVP1a 是 advisory。
- 本機 audit logs 可用於 review，但不是 tamper-proof。
- Pre-push 和 ranged scanning 尚未完成。
- VS Code Extension 和 GitHub Action 是 MVP1b 計畫。
- IntentGuard 不能取代 human code review。
- IntentGuard 不會偵測所有 malicious logic changes。
- 本機 approver 值 `human` 不是 verified identity。
- 目前沒有 cloud dashboard、SSO、SIEM、RBAC 或 enterprise policy service。

請參考 [docs/limitations.md](docs/limitations.md) 和
[docs/public-preview-readiness.md](docs/public-preview-readiness.md)。

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
- 更強的 CI/CD 和 deploy gates
- Enterprise controls
- SIEM 或 audit integrations

Roadmap 裡的未來項目尚未在 MVP1a public preview 中實作。

## Test

```bash
pytest
```

## License

MIT
