# v0.7.1 验证范围

验证以本次GitHub Actions和本地回归实际结果为准，不沿用旧0.6版数字。

- Python：角色/CSRF、告警和回复链、实际Token统计、受限Zabbix查询、两个真实HTTP MCP会话、独立认证、Host ID映射、expected_revision、失败与预算、脱敏和SQLite v4迁移。
- Web：1280/1440/1920桌面页面，双MCP表单、令牌掩码、草稿验证不保存、预算数字表、工具勾选、默认提示词恢复、实时主机查询/选择、旧资产接口移除、成员和屏蔽、历史与主题。
- CI：Python3.11/3.12、临时Redis/RQ、Chromium、Compose构建与非root启动、重启持久化与数据库版本4。

真实飞书OAuth/群权限、initMAX/Zabbix数据、生产SSH主机和Rocky部署仍需按ACCEPTANCE.md联调。自动连接fixture不向真实主机执行SSH。
