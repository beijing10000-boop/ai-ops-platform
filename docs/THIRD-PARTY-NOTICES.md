# 来源与依赖

平台从自研zabbix-ai-ops演进，历史来源记录见SOURCE-REVISIONS.json。旧整合版曾含Linux SSH代码，v0.7.0移除其执行器、管理接口与网关。

initMAX/zabbix-mcp-server与beijing10000-boop/ssh-mcp-server作为独立服务，通过MCP协议调用。SSH客户端适配器参考同一用户自研SSH仓库的示例；不复制SSH执行器。外部服务部署、分发与修改应遵守各自许可证。

运行依赖见requirements.txt，已移除Paramiko；包各自版权/许可证随依赖分发。浏览器回归使用Playwright/Chromium和测试字体，不进入应用镜像。
