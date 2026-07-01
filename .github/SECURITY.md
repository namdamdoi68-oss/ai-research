# 🔐 凭证安全指引

## 当前配置
本项目使用 GitHub Personal Access Token (PAT) 进行跨 Workflow 操作（读取脚本、触发 Workflow）。

## 安全建议

### 1. 使用 Fine-Grained PAT（推荐）
代替当前的全仓库权限 PAT，创建 Fine-Grained PAT 并限制：
- **仓库**: zhangjiayang6835-cyber/ai-research 仅此仓库
- **权限**:
  | 权限 | 级别 |
  |------|:----:|
  | Actions | Read |
  | Contents | Read & Write |
  | Issues | Read & Write |
  | Metadata | Read |
  | Pull Requests | Read & Write |
  | **Webhooks** | **❌ 不授权** |

### 2. 定期轮换
- 每 90 天轮换一次 GH_TOKEN
- 在 GitHub Secrets 中更新，无需修改代码

### 3. Secret 命名规范
| Secret | 用途 | 存储位置 |
|--------|------|---------|
| GH_TOKEN | 跨 Workflow 通信 | GitHub Secrets |
| DISCORD_WEBHOOK | 通知推送 | GitHub Secrets（可选）|

### 4. 审计
所有凭证操作通过 GitHub Actions 日志可追溯。
