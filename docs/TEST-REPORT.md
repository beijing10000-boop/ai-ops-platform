# 验证报告 · 2026-10-23

本报告区分真实协议隔离测试和真实业务环境验收。测试没有使用生产数据或凭据。

## 首次整合验证（172 项 pytest / 37 项浏览器检查）

| 验证 | 实际结果/范围 |
|---|---|
| Python / pytest | 本地 Python 3.12 与 GitHub Ubuntu Python 3.11/3.12 均为 172 passed；真实临时 Redis 启用，0 skipped |
| 静态检查 | ruff F821、ruff format、JavaScript node --check 通过 |
| 桌面 Chromium | 37 项通过，1280 / 1440 / 1920，11 页面，JS 异常0、HTTP 5xx0 |
| Docker / Compose | GitHub Ubuntu 干净构建、健康启动、UID 10001、0700/0600权限、重启后加密配置解密与数据库完整性检查通过 |
| 截图检查 | 中文字体正常，浅色概览/资产/报告与深色报告人工视觉检查 |

pytest 内容：旧功能回归、OAuth/CSRF/角色直连接口、1000资产分页/原子导入、加密凭据与轮换、并发同事件去重、取消/重试、真实数据库跨密钥迁移及失败回滚、主密钥持久化、全周期超过10000记录的 SQL 汇总、配置秘密模型输入/报告脱敏、设备类型闸门和固定目录上限。

真实协议夹具：Paramiko 本地 SSH 握手及固定 Host Key、超时/截断/脱敏/租约；MCP Python SDK stdio 握手/发现/调用；独立编译的 Redis 7.4.11 TCP + RQ 入队/去重/上下文；POSIX 网关拒绝注入/SCP/SFTP 等协议。本地回环放行只存在测试夹具，生产资产仍禁止 loopback。

模型/MCP 场景测试使用受控响应：CPU 历史先于 SSH、非Linux拒绝SSH、MCP或SSH故障降级、缺少工具/权限、快速模式、Token阈值、配置变更撤销等。这些验证编排逻辑，不证明第三方模型的分析质量或实际 initMAX 版本兼容性。

桌面包含资产创建与非法 root 编辑、组 CRUD、存储 HTML 转义、Web 屏蔽/解除、报告证据和主题切换。原始结果：[UI-TEST-RESULTS.json](UI-TEST-RESULTS.json)，截图位于 screenshots/。所有页面数据来自临时 SQLite API；没有产品静态演示计数。

## 后续代码审查与回归检查扩展

本轮修复包括：连接测试重试刷新资产版本并拒绝无效目标；MCP 错误与空模型结论标记为部分完成；任务失败、取消、超时后保留已返回的真实 Token；恢复事件按恢复时间查询历史；长篇及嵌套旧报告先解析 JSON 再脱敏，避免截断破坏迁移；导入历史禁止作为新任务重试。

桌面新增主机组勾选和筛选、资产/历史/审计分页边界、成员编辑、非 Linux 配置与状态提示、禁用资产隐藏诊断入口，以及导航离开问答页后正确处理延迟响应。保留已有弹窗内错误提示。静态检查增加未使用导入、变量及重复定义检查，并移除过期预算常量。

新增 API/编排/迁移回归用例，以及浏览器分页、分组保存和筛选、设备切换、成员调整、异步导航流程。浏览器使用临时数据库中的 30 台资产和 29 条任务验证多页数据。本轮本地执行环境不可用，完整测试由 GitHub Actions 执行；最新运行状态与日志见 [PR #1 的检查](https://github.com/beijing10000-boop/ai-ops-platform/pull/1/checks)。上方 172/37 与仓库内原截图为首次整合记录，最新浏览器截图和机器结果以对应 CI 的 desktop-results 附件为准。

Token 统计只累计模型实际返回的用量；未返回响应的失败请求无法计量，不按预算推算费用或 Token。

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

Chromium 截图需测试机安装中文字体（例如 Noto CJK）；它不随产品镜像发货。Redis 路径不存在时集成用例会 skip，需明确报告。CI 已实际通过 Python 3.11/3.12、Chromium、Compose 解析、Docker 构建、干净启动和重启持久化验证。验证代码 SHA 为 `11ac4b70850593213f4734268171af1c12fd511b`，见 [GitHub Actions 运行](https://github.com/beijing10000-boop/ai-ops-platform/actions/runs/39922888133) 与 [CI-RESULTS.json](CI-RESULTS.json)。容器运行验证发生在 GitHub Ubuntu runner，不能替代 Rocky 目标机验收。

## 尚未执行

Rocky 9/10 Docker 启动、实际 initMAX 和 Zabbix 7.4、真实飞书 OAuth/长连接/卡片/恢复、真实单跳与目标 Linux 命令兼容性、真实 OpenSSH forced-command/from/restrict 模式B、真实旧库数据核对和维护窗口回滚。完整验收见 ACCEPTANCE.md。未达到真实环境门槛前保持候选版和未合并状态。
