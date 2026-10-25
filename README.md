# AI Ops Platform · AI 智能运维平台

**v0.7.0** · 默认 Web 端口 **8088**。平台负责 Zabbix 告警、飞书协作、AI 分析与报告，通过两个独立的 Streamable HTTP MCP 服务获取证据。

| 服务 | 职责 |
| --- | --- |
| AI Ops Platform | 登录与权限、告警、问答、分析编排、报告、审计和真实 Token 统计 |
| Zabbix MCP | 监控指标、历史趋势、事件与主机信息 |
| [SSH MCP Server](https://github.com/beijing10000-boop/ssh-mcp-server) | Linux 主机、SSH 凭据、跳板、公钥核验、实时诊断与动作授权 |

平台已删除内置 SSH MCP、Paramiko 执行器、公钥扫描、SSH 凭据与跳板接口、强制命令网关及相关部署。平台不保存 SSH 私钥，也不直接连接目标 SSH 端口。

![平台概览：隔离测试数据](docs/screenshots/overview-1440.png)

## Web 管理

- 两个 MCP 分开配置地址、令牌、开关和超时，分别验证连接；令牌加密保存。
- AI 模型、飞书、群、成员、Webhook、提示词均使用输入框或选项；分析预算使用数字输入表，工具权限使用勾选框。
- 提供符合 Zabbix + 飞书 + 独立 SSH MCP 场景的中文告警与问答默认提示词，支持编辑、校验和恢复默认。
- 初始化、配置、资产、Host ID 关联、诊断参数、主机组、成员、屏蔽规则和批量导入具有验证入口；验证不等同于生产联调。
- 批量导入支持粘贴 Excel 表格或 CSV，提供模板，无需编写 JSON。
- 保留分级告警、恢复关联、卡片 AI 分析、追问上下文、任务取消/重试、角色与审计、加密证据和桌面深浅色主题。

先查 Zabbix 历史，证据不足时才由固定剧本调用独立 SSH MCP。目标通过可信任务的 **Zabbix Host ID** 精确解析，固定远端主机 ID 和版本；映射失败或配置变化时停止补查，不按 IP/名称猜测，不切换到本地 SSH。快速模式只查监控，非 Linux 不使用 Linux 诊断。

## 安装

已安装 Docker Engine 与 Compose 插件的 Linux 服务器：

```bash
mkdir -p /data
cd /data
git clone https://github.com/beijing10000-boop/ai-ops-platform.git
cd ai-ops-platform
docker compose up -d --build
docker compose exec -T web python -m app.bootstrap
docker compose exec -T web cat /app/data/bootstrap.token
```

在受信任内网打开 `http://服务器IP:8088/setup`，输入一次性凭据和飞书应用、管理员 Open ID、实际外部地址，验证后保存。登录后在 Web 完成两个 MCP、AI 和飞书配置，无需创建业务 `.env`。

独立 SSH MCP 需为 **v0.2.0 或更新版本**，支持 `ssh_resolve_host` 与 `expected_revision`。在其 Web 登记主机并填写 Zabbix Host ID，为平台签发专用客户端令牌。

完成飞书配置并停止使用同一 App ID 的旧接收器后启动：

```bash
docker compose --profile feishu up -d feishu-receiver
```

现有整合版升级会删除旧平台 SSH 配置；请先备份数据库和配对主密钥，按 [升级说明](docs/UPGRADING.md) 操作。

| 文档 | 内容 |
| --- | --- |
| [安装部署](docs/INSTALLATION.md) | 首次部署、HTTP 内网访问、初始化与启动 |
| [升级与回滚](docs/UPGRADING.md) | 旧 SSH 配置清理、备份与恢复 |
| [Web 配置与验证](docs/CONFIGURATION.md) | 表单、验证按钮与默认提示词 |
| [架构](docs/ARCHITECTURE.md) / [SSH MCP 接入](docs/LINUX-DIAGNOSTICS.md) | 双 MCP、身份映射、预算与失败处理 |
| [Zabbix](docs/ZABBIX.md) / [飞书](docs/FEISHU.md) | 告警、恢复、群与卡片 |
| [安全](SECURITY.md) / [排障](docs/TROUBLESHOOTING.md) | 权限、密钥和常见问题 |
| [验证范围](docs/TEST-REPORT.md) / [真实验收](docs/ACCEPTANCE.md) | 自动回归与生产联调边界 |

开发验证：`python -m pip install -r requirements-dev.txt`，`python -m pytest -q`，`python -m ruff check --select F401,F811,F821,F841 app tests`，`python -m ruff format --check app tests`，`node --check web/assets/app.js`。浏览器回归使用 `python tests/browser_smoke.py`；临时 Redis 由测试自行启动，未安装 Redis 的相关测试会跳过。

来源记录见 [SOURCE-REVISIONS.json](docs/SOURCE-REVISIONS.json)，依赖说明见 [THIRD-PARTY-NOTICES.md](docs/THIRD-PARTY-NOTICES.md)。
