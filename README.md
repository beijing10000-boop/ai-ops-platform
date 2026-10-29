# AI Ops Platform · AI 智能运维平台

**v0.9.6** · 默认 Web 端口 **8088**。平台负责 Zabbix 告警、飞书协作、AI 分析与报告，通过两个独立的 Streamable HTTP MCP 服务获取证据。

| 服务 | 职责 |
| --- | --- |
| AI Ops Platform | 登录与权限、告警、问答、分析编排、报告、审计和真实 Token 统计 |
| Zabbix MCP | 监控指标、历史趋势、事件与主机信息 |
| [SSH MCP Server](https://github.com/beijing10000-boop/ssh-mcp-server) | Linux 主机、SSH 凭据、跳板、公钥核验、实时诊断与动作授权 |

平台已删除内置 SSH MCP、Paramiko 执行器、公钥扫描、SSH 凭据与跳板接口、强制命令网关及相关部署。平台不保存 SSH 私钥，也不直接连接目标 SSH 端口。

![平台概览：隔离测试数据](docs/screenshots/overview-1440.png)

## Web 管理

- 连接管理集中配置两个 MCP、分别验证连接，并查看诊断工具与标准流程；令牌加密保存。
- Skill 管理支持 Markdown/ZIP 上传、格式预览、编辑、启停、场景/服务范围、优先级、工具验证与导出；启用后由 Skill 决定查询来源和步骤，任务保存完整版本快照。内置 [双 MCP 运维模板与使用说明](docs/SKILLS.md)。
- 系统配置按基础设置、飞书配置、AI 配置、服务与维护分页签展示，各自验证和保存；切换分区与更新成员保留草稿，离开前提示未保存修改。
- AI 模型、飞书、群、成员、Webhook 使用输入框或选项；分析预算使用数字输入表，取消固定最大值；任务仍按保存的预算停止。工具权限使用勾选框。
- 诊断指引和报告策略统一由 Skill 管理，按场景启用；AI 配置不再提供告警/问答独立提示词。飞书 JSON 格式、只读授权与证据安全约束仍由平台强制执行。旧提示词数据库记录保留供回退，不再用于新分析。
- 初始化、配置、Host ID 关联、诊断参数、成员与屏蔽规则具有验证入口；验证不等同于生产联调。
- 不维护本地主机资产：可选择 Zabbix 主机；启用 Skill 后也可直接在问题中指定 SSH 服务已登记的 IP，无需先查询 Zabbix。
- 告警中心支持分页、关键词、级别和恢复状态筛选，关联最近分析；暂时屏蔽集中在告警中心，显示生效与到期记录。
- 诊断详情新增“与大模型交互记录”：按轮次展示输入/输出 Token、模型耗时、已授权工具、脱敏输入与模型输出、工具调用参数和错误类别。记录加密保存在任务数据库中；只有具备 logs.read 的管理员可查看正文，普通 reports.read 只能查看元数据。记录从 v0.9.6 新任务开始产生，不补录历史任务。
- 报告显示本次分析预算、实际用量与停止原因；飞书 Token 尾注展示实际分析模式（快速/标准/深度）及任务耗时，隐藏不必要的“需人工核验：是”重复行；完整 AI 诊断报告超过单卡容量按字节分段，保留全部正文和报告链接。
- 中文诊断报告的百分比统一保留两位小数，原 KiB 数值在显示时换算为 MiB/GiB（不更改原始采集证据）。对于 SSH MCP v0.4.2 的进程摘要，可使用识别到的 Java JAR 或 systemd 单元名标识进程；无法可靠识别则如实标记，不猜测业务归属。
- Skill 支持批量获取多个 MCP 工具 Schema，减少反复 list_tools；结构化历史指标发送模型时保留统计、样本和来源，完整原始证据仍保存在加密数据库中以供核验。
- Skill 模板对实时问题直接查询 SSH，对告警与历史指标查询 Zabbix；目录最多有界展开 5 层，注明实际范围。未启用 Skill 的场景保留原有兼容流程。
- 报告支持中文进度、自动刷新、可读结论、复制和下载；分析历史可搜索任务、事件与 Trace ID。服务检查显示各队列及 Worker 注册数量。
- 保留分级告警、恢复关联、卡片 AI 分析、追问上下文、任务取消/重试、角色与审计、加密证据和桌面深浅色主题。

启用 Skill 后，由指引决定查询服务、工具和顺序；分析模式决定预算，不强制查询 Zabbix。没有启用 Skill 的场景沿用兼容流程：标准与深度模式对精确关联的 Linux 主机按固定剧本采集 SSH 证据，快速模式只查监控。两种流程都核验目标和远端版本，保留授权与预算检查，不切换到本地 SSH。

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

使用内置 Skill 按 IP 直接查询时，独立 SSH MCP 需为 **v0.4.1 或更新版本**。在其 Web 登记主机、核验公钥、配置凭据，并为平台签发专用客户端令牌；实时 IP 查询无需填写 Zabbix Host ID。按 Zabbix Host ID 关联告警时仍需填写映射。

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
| [需求复核记录](docs/REQUIREMENTS-AUDIT.md) | 已实现功能、补充修复、验证结果与生产验收边界 |
| [架构](docs/ARCHITECTURE.md) / [SSH MCP 接入](docs/LINUX-DIAGNOSTICS.md) | 双 MCP、身份映射、预算与失败处理 |
| [Zabbix](docs/ZABBIX.md) / [飞书](docs/FEISHU.md) | 告警、恢复、群与卡片 |
| [安全](SECURITY.md) / [排障](docs/TROUBLESHOOTING.md) | 权限、密钥和常见问题 |
| [验证范围](docs/TEST-REPORT.md) / [真实验收](docs/ACCEPTANCE.md) | 自动回归与生产联调边界 |
| [v0.8 产品优化](docs/PRODUCT-REVIEW.md) | 运维流程、界面交互与可靠性改进 |

开发验证：`python -m pip install -r requirements-dev.txt`，`python -m pytest -q`，`python -m ruff check --select F401,F811,F821,F841 app tests`，`python -m ruff format --check app tests`，`node --check web/assets/app.js`。浏览器回归使用 `python tests/browser_smoke.py`；临时 Redis 由测试自行启动，未安装 Redis 的相关测试会跳过。

来源记录见 [SOURCE-REVISIONS.json](docs/SOURCE-REVISIONS.json)，依赖说明见 [THIRD-PARTY-NOTICES.md](docs/THIRD-PARTY-NOTICES.md)。
