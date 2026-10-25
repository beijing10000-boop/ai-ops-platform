# 排障

| 现象 | 检查 |
| --- | --- |
| 初始化凭据错误 | 运行 `docker compose exec -T web cat /app/data/bootstrap.token`，使用原部署值；不要重建主密钥 |
| 页面无法访问 | `docker compose ps`、8088监听、宿主机防火墙与访问IP；默认发布宿主机8088 |
| MCP 无法连接 | 连接管理验证当前表单；容器里的127.0.0.1不是宿主机；分别使用正确服务令牌 |
| SSH MCP 发现失败 | 服务至少v0.2.0，地址为 /mcp，包含 ssh_resolve_host；令牌未过期/撤销 |
| 主机关联失败 | SSH MCP 中填写相同数字Zabbix Host ID，唯一、启用、绑定凭据且核验公钥，令牌覆盖主机组 |
| SSH MCP 动作失败 | 独立服务查看任务、授权动作、日志权限、跳板与主机公钥；平台无本地SSH兜底 |
| 仅有监控分析 | 快速模式、设备非Linux、SSH未开启、类型unknown、映射失败或预算不足都会限制实时补查 |
| 飞书应用验证通过但没消息 | 确认发送开关、群ID、机器人在群内、消息权限、接收器已启用；令牌验证不证明全部权限 |
| 飞书登录失败 | 外部主机/协议与开放平台OAuth回调一致；管理员Open ID属于该应用并获授权 |
| 配置变更后验证状态消失 | 重新验证已保存连接，旧配置检测结果不能代表新地址/令牌 |
| 修改飞书应用后长连接未切换 | `docker compose --profile feishu restart feishu-receiver` |
| 任务一直排队 | 系统设置查看服务与队列状态，确认diagnostic-worker/Redis健康 |
| 配置无法解密 | 保留旧APP_ENCRYPTION_KEY或原master.key，与对应数据库成对恢复 |

查看日志：`docker compose logs --tail=100 web alert-worker qa-worker diagnostic-worker`。日志/工具采集失败代表证据不足，不能推断主机正常或故障根因。
