# 验证报告 · 2026-10-23

本报告区分真实协议隔离测试和真实业务环境验收。测试没有使用生产数据或凭据。

## 已执行

| 验证 | 实际结果/范围 |
|---|---|
| Python / pytest | Python 3.12，172 passed；真实临时 Redis 启用，未跳过该组 |
| 静态检查 | ruff F821、ruff format、JavaScript node --check 通过 |
| 桌面 Chromium | 37 项通过，1280 / 1440 / 1920，11 页面，JS 异常0、HTTP 5xx0 |
| 截图检查 | 中文字体正常，浅色概览/资产/报告与深色报告人工视觉检查 |

pytest 内容：旧功能回归、OAuth/CSRF/角色直连接口、1000资产分页/原子导入、加密凭据与轮换、并发同事件去重、取消/重试、真实数据库跨密钥迁移及失败回滚、主密钥持久化、全周期超过10000记录的 SQL 汇总、配置秘密模型输入/报告脱敏、设备类型闸门和固定目录上限。

真实协议夹具：Paramiko 本地 SSH 握手及固定 Host Key、超时/截断/脱敏/租约；MCP Python SDK stdio 握手/发现/调用；独立编译的 Redis 7.4.11 TCP + RQ 入队/去重/上下文；POSIX 网关拒绝注入/SCP/SFTP 等协议。本地回环放行只存在测试夹具，生产资产仍禁止 loopback。

模型/MCP 场景测试使用受控响应：CPU 历史先于 SSH、非Linux拒绝SSH、MCP或SSH故障降级、缺少工具/权限、快速模式、Token阈值、配置变更撤销等。这些验证编排逻辑，不证明第三方模型的分析质量或实际 initMAX 版本兼容性。

桌面包含资产创建与非法 root 编辑、组 CRUD、存储 HTML 转义、Web 屏蔽/解除、报告证据和主题切换。原始结果：[UI-TEST-RESULTS.json](UI-TEST-RESULTS.json)，截图位于 screenshots/。所有页面数据来自临时 SQLite API；没有产品静态演示计数。

## 复现

```bash
python -m pip install -r requirements-dev.txt
AIOPS_REDIS_SERVER=/path/to/redis-server python -m pytest -q
python -m ruff check --select F821 app tests
python -m ruff format --check app tests
node --check web/assets/app.js
node --check web/assets/setup.js
python -m playwright install --with-deps chromium
python tests/browser_smoke.py
```

Chromium 截图需测试机安装中文字体（例如 Noto CJK）；它不随产品镜像发货。Redis 路径不存在时集成用例会 skip，需明确报告。CI 配置覆盖 Python 3.11/3.12、Chromium、Compose 解析和 Docker 构建；本地环境没有 Docker，本报告不将“已配置 CI”当作已通过。

## 尚未执行

Rocky 9/10 Docker 启动、实际 initMAX 和 Zabbix 7.4、真实飞书 OAuth/长连接/卡片/恢复、真实单跳与目标 Linux 命令兼容性、真实 OpenSSH forced-command/from/restrict 模式B、真实旧库数据核对和维护窗口回滚。完整验收见 ACCEPTANCE.md。未达到真实环境门槛前保持候选版和未合并状态。
