# Zabbix AI Ops · AI Ops Platform

把 Zabbix 告警、飞书协作和 Linux SSH 诊断汇入同一个管理入口。新仓库承接两个自研项目的整合，默认端口 **8088**，initMAX Zabbix MCP 继续独立运行。

**当前为整合候选版本 0.6.0。代码和隔离测试已完成，真实 Zabbix / 飞书 / 目标 Linux 与 Rocky Docker 部署仍待用户环境验收。尚未发布生产版本。** 两个原仓库和原生产实例不修改。

![平台概览](docs/screenshots/overview-1440.png)

截图使用标明来源的隔离测试数据，数字不代表生产观测。

## 能做什么

- 保留告警 Webhook、分级卡片、告警恢复关联、自动及手动 AI 分析、飞书群问答、四次 AI 回复链和真实 Token 统计。
- 统一资产、多个主机组、设备类型、SSH 凭据、跳板和 Zabbix **Host ID** 映射。不根据消息里的 IP 猜测连接目标。
- 历史监控先行；AI 判断证据不足时，按登记范围补充 Linux 实时证据。支持 CPU、内存、磁盘、I/O、服务、网络、系统、不可达、瓶颈和日志十类诊断。
- 标准免 Agent 模式支持 root 和普通账号，不需要目标端 Python、网关、Sysmon 或 SysOM。管理员可选部署受限特权网关。
- 精确授权九个 Zabbix 只读工具；拒绝通用参数透传、写操作及敏感字段。支持按需发现和加载 Schema。
- task_id / trace_id、阶段、取消、重试、加密报告和证据、角色权限与审计。AI 推断与采集事实分开展示。
- 桌面统一控制台，深浅色主题；资产分页、连接测试、工具注册表、配置、历史、Token 汇总与原始日志授权。

Windows、VMware、网络设备可登记并使用 Zabbix 证据；本版本没有这些设备的实时执行适配器，绝不发送 Linux 命令。

## 启动测试实例

安装 Docker Engine 与 Compose 插件后：

```bash
git clone --branch integration/unified-platform https://github.com/beijing10000-boop/ai-ops-platform.git
cd ai-ops-platform
docker compose up -d --build
docker compose exec web python -m app.bootstrap
docker compose ps
curl -f http://127.0.0.1:8088/healthz
```

首次进入 `/setup`，在服务器本地读取初始化凭据并填入页面：

```bash
docker compose exec web cat /app/data/bootstrap.token
```

App ID、App Secret、管理员 Open ID、外部地址在初始化页填写；AI、MCP、飞书群、预算等都在 Web 设置。不需要把业务参数散落在 `.env`。默认只监听宿主机 loopback；远程访问和 OAuth 请按 [安装说明](docs/INSTALLATION.md) 配置访问链路。

复用旧飞书应用时，先停止旧接收器，再显式启用新接收器：

```bash
docker compose --profile feishu up -d feishu-receiver
```

请先完成 [真实环境验收](docs/ACCEPTANCE.md)，再决定切换生产。与现有实例同机测试时使用 `WEB_PORT=8089 docker compose up -d --build`，避免端口冲突。

## 文档

| 文档 | 内容 |
|---|---|
| [源码整合审计](docs/INTEGRATION-AUDIT.md) | 实际源码映射、问题、保留与移除决定 |
| [架构](docs/ARCHITECTURE.md) | 服务、数据流、授权、时间与预算 |
| [安装](docs/INSTALLATION.md) | Docker、首次初始化、访问、运行和备份 |
| [升级与迁移](docs/UPGRADING.md) | 两套旧数据导入、密钥、幂等、回滚 |
| [配置](docs/CONFIGURATION.md) | Web 参数、模式预算、角色 |
| [Linux 诊断](docs/LINUX-DIAGNOSTICS.md) | A/B 模式、账号、公钥、跳板、网关 |
| [Zabbix](docs/ZABBIX.md) / [飞书](docs/FEISHU.md) | 对接与恢复、回复链、卡片回调 |
| [验收](docs/ACCEPTANCE.md) / [测试报告](docs/TEST-REPORT.md) | 已验证范围和待真实验证项 |
| [排障](docs/TROUBLESHOOTING.md) / [安全](SECURITY.md) | 故障定位、凭据与权限边界 |

## 开发与验证

Python 3.11+。独立测试环境安装 `requirements-dev.txt`，准备本机 Redis 可执行文件：

```bash
python -m pip install -r requirements-dev.txt
AIOPS_REDIS_SERVER=/usr/bin/redis-server python -m pytest -q
python -m ruff check --select F821 app tests
python -m ruff format --check app tests
python -m playwright install --with-deps chromium
python tests/browser_smoke.py
```

Redis 集成测试自行启动随机端口的临时实例，不使用生产 Redis。浏览器回归只访问自建测试进程与临时数据库；测试文件不进入应用镜像。未安装 Redis 时相关用例会 skip，不能将 skip 计作通过。

来源版本见 [SOURCE-REVISIONS.json](docs/SOURCE-REVISIONS.json)。许可证与第三方边界见 [THIRD-PARTY-NOTICES.md](docs/THIRD-PARTY-NOTICES.md)。
