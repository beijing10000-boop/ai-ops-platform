# AI Ops Platform · Zabbix AI Ops

统一 AI 智能运维诊断平台。基于已有 Zabbix AI Ops，迁入 Linux SSH 诊断、统一资产和凭据管理。

**当前处于独立分支整合验证阶段。尚未通过真实生产环境联调，不自动部署或迁移生产实例。**

代码位于 `integration/unified-platform`。源码审计见 [docs/INTEGRATION-AUDIT.md](docs/INTEGRATION-AUDIT.md)，输入版本见 [docs/SOURCE-REVISIONS.json](docs/SOURCE-REVISIONS.json)。

保留 Zabbix Webhook、飞书告警、自动/手动 AI 分析、四轮回复上下文和真实 Token 统计。新增平台只读工具策略、Host ID 资产绑定、低权限免 Agent SSH、可选受限特权模式、任务追踪和加密证据。默认端口 8088，现有 initMAX Zabbix MCP 继续外置。

完整部署与迁移说明、验收状态及测试报告随整合交付更新。两个旧仓库保持不变。
