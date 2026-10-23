# Web 配置与权限

除端口、挂载、Redis 地址、已有主密钥等部署基础参数外，业务配置均保存在 Web 后台。密钥读取只返回“已配置”，空值保存保留已有秘密，界面不会回显。

| 页面 | 主要设置 |
|---|---|
| AI 配置 | Responses API Base URL、模型、API Key、自动分析最低级别、独立告警/问答提示词、quick/standard/deep、dynamic/full 工具加载、预算 JSON |
| 飞书配置 | App ID / Secret、问答群白名单、告警目标群、启用发送、本地屏蔽及提前解除 |
| 系统配置 | 外部主机与协议、Zabbix 前端地址、Webhook Secret、SSH 总并发 1–16、单动作超时 3–30 秒 |
| 成员管理 | 超级管理员名单、ops_admin / operator / auditor 的启用及角色 |
| 工具注册表 | 授权工具、Schema、风险、设备范围、结果上限、连接发现 |

`full` 也只公开平台已授权工具，不扩大执行权限。`disabled_tools` 是九个 Zabbix 只读工具名称的 JSON 数组，仅超级管理员可改。普通模型提示词无法解锁工具。

预算示例：

```json
{"standard":{"rounds":4,"calls":8,"per_round":4,"seconds":110,"tokens":24000,"result_chars":4000}}
```

每项均校验范围，详见 `app/orchestrator/budgets.py` 和架构文档。预算在任务创建时快照保存；新配置只影响后续任务，资产/凭据变化则会撤销正在使用的 SSH 路径。

| 角色 | 读取概览/资产/报告 | 发起诊断 | 管理资产/凭据/设置 | 原始日志 | 审计 | 管理角色 |
|---|---|---|---|---|---|---|
| super_admin | 是 | 是 | 是 | 是 | 是 | 是 |
| ops_admin | 是 | 是 | 是 | 是 | 是 | 否 |
| operator | 是 | 是 | 否 | 否 | 否 | 否 |
| auditor | 是 | 否 | 否 | 否 | 是 | 否 |

超级管理员由初始化名单管理，成员 API 不能将普通成员升级为超级管理员。权限在后端每次请求重新计算；隐藏按钮并非授权控制。飞书 @ 和分析按钮也检查诊断权限，屏蔽按钮检查告警管理权限。禁用成员后既有会话不能继续执行被撤销操作。

运行时环境变量：DATA_DIR、REDIS_URL；Compose 可选 WEB_BIND_IP、WEB_PORT、APP_ENCRYPTION_KEY、ADMIN_API_TOKEN、ALLOW_LEGACY_ADMIN_TOKEN，以及紧急恢复用 FEISHU_ADMIN_OPEN_IDS。正常业务配置通过 Web 完成。若数据库已有管理员名单，环境变量不会覆盖它。legacy API Token 默认关闭，不是正常页面登录方式。

Token 汇总按选定日期/来源/模型在 SQL 中统计全量；详情记录有数量上限。提供商不返回完整 usage 的运行不加入总量，明确显示不可用，统计不包含价格估算。
