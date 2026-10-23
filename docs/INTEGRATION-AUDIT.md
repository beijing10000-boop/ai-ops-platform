# 新项目整合审计

审计日期：2026-10-23。新仓库 `beijing10000-boop/ai-ops-platform`，产品名 Zabbix AI Ops。两个原仓库和生产实例不修改。输入源码版本见 `SOURCE-REVISIONS.json`。

| 源码/能力 | 现状与整合决定 |
|---|---|
| 主项目 main.py | 保留 8088、Webhook、加密配置、数据库和初始化 API；增量迁移 |
| worker.py、alert_actions.py | 保留自动/手动分析、原始通知、恢复关联、分级卡片和应用级屏蔽 |
| qa_worker.py、conversation_context.py | 保留直接回复消息所属链、四轮限制、分析中拦截；加结构化事件关联 |
| mcp_runtime.py | 原实现暴露全部动态工具；重构为精确只读授权、参数约束、按需 Schema、任务预算和去重 |
| Linux diagnostics.py | 迁移固定公钥、Paramiko、跳板、输出和执行超时设计；不保留固定 root/Python 网关依赖 |
| Linux inventory.py/storage.py/security.py | 迁入统一资产、凭据、审计；旧 OAuth 和配置库不作为第二套运行系统 |
| Linux Web | 参考桌面导航、深浅色主题、密集表格和表单；重建单入口导航 |
| initMAX server.py 的 _make_tool_handler/_register_tools | 实际提供扁平参数、多服务器、Bearer 及读写工具；继续独立，通过协议接入 |
| SysOM sched_diag_mcp.py/diagnosis_helper.py | 借鉴问题分类、任务和标准结果；不复制代码、不引入云依赖 |
| Sysmon sysmonProcCreate.c/networkTracker.cpp | 借鉴进程生命周期与网络事件的时间关联；不部署采集组件 |
| classfang execute-command.ts/ssh-connection-manager.ts | 参考连接/代理与超时；不引入自由命令、文件传输、交互 Shell |

## 重复与迁移映射

OAuth、用户、初始化、Web 配置统一保留主项目实现并增加 RBAC。SSH 主机、组、跳板和凭据迁入 app/inventory/。任务和加密证据迁入 app/orchestrator/。两个数据源沿用同一 app.sqlite3 和统一主密钥。9099 独立 Web 不再需要。旧数据库通过离线工具显式导入，不在启动时猜测或覆盖生产数据。

## 问题优先级

| 等级 | 问题 | 处理方向 |
|---|---|---|
| P0 | 动态工具无平台白名单，安全交给 MCP 自述 | 精确授权，拒绝通用 params/raw API/写工具 |
| P0 | MCP 测试接口引用不存在的 ALLOWED_TOOLS | 使用统一工具策略 |
| P0 | Linux 旧方案固定 root、依赖 Python 强制网关 | A/B 模式隔离，A 禁止 UID 0，B 明确授权及网关标识 |
| P0 | 两个旧数据库密钥与表结构不兼容 | 安全解密重加密、事务、幂等导入、备份与回滚 |
| P1 | 无 Host ID 统一模型和设备类型闸门 | 注册资产精确绑定；禁止文本 IP 自动建连接 |
| P1 | 缺少统一任务、证据、追踪和取消 | task_id/trace_id、阶段、证据、取消与重试 |
| P1 | Web 用户无角色隔离 | 四角色、后端权限校验、原始日志独立授权 |
| P1 | 预算不可配置、重复工具调用 | Web 模式预算、任务内缓存、调用数和时间限制 |
| P2 | 两套 UI、默认生产 IP、缺少健康检查 | 单管理入口、独立部署卷、默认 loopback、健康检查 |

## 许可证

两个自研仓库本次快照无顶层 LICENSE；保留归属和版本记录，不擅自授予新的开源许可证。initMAX 为 AGPLv3，仅作为外部协议依赖；SysOM MCP 为 Apache-2.0；classfang 为 ISC；Sysmon 顶层 MIT、部分 eBPF 文件为 GPLv2+。本次不复制三个参考项目或 initMAX 的实现代码。

## 验证边界

代码审查不等于生产联调。未访问生产数据库、真实飞书租户、真实 SSH 主机或部署中的 MCP。必须分别记录自动化测试、本地协议联调和用户真实环境验收。
