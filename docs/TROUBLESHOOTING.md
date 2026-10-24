# 排障

| 现象 | 首先检查 |
|---|---|
| 页面无法连接 | compose ps/health、绑定 127.0.0.1、端口冲突、SSH 隧道或代理 |
| 初始化 403/409 | 本机 bootstrap.token 或显式 ADMIN_API_TOKEN、是否已初始化；不要重置已存在密钥 |
| OAuth 失败 | Web 外部协议/主机、飞书完全一致的重定向、已发布应用、管理员/成员 Open ID、Cookie 协议 |
| API 401/403 | 会话、当前角色、写操作 CSRF；legacy Token 默认关闭 |
| MCP 发现为空 | URL / Token、Streamable HTTP 协议、分页、远端工具名、disabled_tools |
| MCP 存在但无证据 | 本账号主机范围、平台参数校验、item 归属、事件时间和历史保留、查看证据错误 |
| SSH Host Key 错误 | 先用独立可信渠道核验，不删除固定公钥来绕过校验 |
| SSH 失败或日志缺失 | 私网地址、网络 ACL、密钥/口令、用户名、UID、跳板权限、journal 权限和网关标识 |
| 磁盘无目录占用 | 默认不扫描目录，资产需预先登记允许路径；限时工具缺失或 3 秒预算用尽会明确缺失 |
| 任务一直排队 | diagnostic-worker 是否运行、Redis 健康与 noeviction 内存限制、队列状态 |
| Worker 异常退出 | 超过十分钟的 running 会标失败并保留证据，可人工重试；先核对外部通知是否已发送 |
| Token 显示 — | 提供商没有返回完整 usage，不代表消耗为零 |
| 飞书无消息/重复 | 发送开关、群 ID、应用权限及发布、重复接收器、Webhook 响应体与队列 |
| 回复丢上下文 | 是否直接回复该分支卡片、群 ID、Redis 上下文 TTL、是否已达到四次 AI 答复 |
| 导入失败 | 源库版本、对应原 Fernet 密钥及0600权限、新目标路径、离线状态；原库不会被写入 |
| 加密配置无法读取 | 主密钥是否与快照配对；不要重新生成密钥覆盖，恢复对应备份 |

```bash
docker compose ps
docker compose logs --tail=100 web alert-worker qa-worker diagnostic-worker
curl -f http://127.0.0.1:8088/healthz
```

错误报告请提供任务 trace_id、时间、脱敏错误类型与软件 SHA。不要附私钥、完整设置/数据库、OAuth code 或 Token。healthz 只表示应用存活；远端连接和数据准确性需单独验证。
