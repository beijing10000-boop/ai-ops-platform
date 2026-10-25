# v0.8.0 验证范围

本地回归：184 项 Python 测试通过；Chromium 桌面检查 37 项通过，无 JavaScript 异常及 HTTP 5xx。桌面结果见 [UI-TEST-RESULTS.json](UI-TEST-RESULTS.json)，截图使用隔离测试数据。合并前另由 GitHub Actions 执行下列 CI 检查，以对应提交的运行记录为准。

- Python：角色/CSRF、告警和回复链、实际 Token 统计、受限 Zabbix 查询、两个真实 HTTP MCP 测试会话、独立认证、Host ID 映射、expected_revision、失败与预算、脱敏和 SQLite v4 迁移；新增告警分页/恢复/筛选、字面量搜索、状态接口无日志泄露或审计刷屏、超时任务恢复、队列失败可重试、默认模式、告警提示词与未变更设置保留验证状态。
- Web：1280/1440/1920 桌面布局，四页签独立保存/验证、离开确认、成员更新保留草稿、角色权限、双 MCP 表单、令牌掩码、数字预算、工具勾选、默认提示词、实时主机选择、告警筛选及事件带入、暂时屏蔽、分析历史搜索、服务状态；报告内容转义/格式化/导出，真实定时轮询保持证据展开，深浅色主题和旧书签兼容。
- CI：Python 3.11/3.12、临时 Redis/RQ、Chromium、Compose 构建与非 root 启动、重启持久化与数据库版本 4。

真实飞书 OAuth/群权限、initMAX/Zabbix 数据、生产 SSH 主机和 Rocky 部署仍需按 [ACCEPTANCE.md](ACCEPTANCE.md) 联调。自动连接 fixture 不向真实主机执行 SSH，服务注册数量也不替代实际业务验收。
