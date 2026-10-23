# 来源与第三方边界

整合输入 SHA 固定在 SOURCE-REVISIONS.json，功能映射见 INTEGRATION-AUDIT.md。

| 项目 | 本次使用方式 | 原仓库许可证观察 |
|---|---|---|
| beijing10000-boop/zabbix-ai-ops | 主项目演进，保留核心接口与功能 | 本次快照未见顶层 LICENSE |
| beijing10000-boop/linux-ai-diagnostic-mcp | 自研 SSH/资产/数据模型迁移，统一重构 | 本次快照未见顶层 LICENSE |
| initMAX/zabbix-mcp-server | 独立外部服务，经 MCP 协议调用 | AGPLv3 |
| SysOM sysom-ai | 阅读分类/任务/证据设计，未复制实现 | Apache-2.0 |
| microsoft/SysmonForLinux | 阅读事件关联设计，不部署组件 | 顶层 MIT，部分 eBPF 文件 GPLv2+ |
| classfang/ssh-mcp-server | 阅读连接/代理与超时设计，未复制实现 | ISC |

未因参考关系将上述第三方代码合入本仓库。外部服务的部署、分发及修改仍需遵循各自许可证。两个自研仓库未见许可证不等于无权利限制；本仓库不擅自新增开源授权，发布或再分发前由权利人确认。

Python 运行依赖列在 requirements.txt，其各自版权/许可证随依赖包提供。浏览器测试环境使用 Playwright/Chromium 和 Noto CJK 字体；字体仅为测试环境安装，不打包入产品。
