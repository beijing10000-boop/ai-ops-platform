# Zabbix 对接

## 外部 MCP

沿用现有 initMAX Zabbix MCP Server 的 Streamable HTTP 地址和 Bearer Token，在 Web 系统/AI 配置填写。平台不自建第二套 Zabbix API 凭据库、不更改原 MCP 部署。通过“连接管理/工具发现”验证握手与授权工具；发现成功不证明 Zabbix API 账号只读。

在 Zabbix 为专用账号配置最小主机读取范围和 API 允许列表，拒绝写方法；实际 API 方法包括 host.get、hostgroup.get、hostinterface.get、event.get、problem.get、trigger.get、item.get、history.get、trend.get。由管理员在真实实例验证其有效权限，不用生产写入验证权限。平台也独立限制对应九个工具、字段和查询范围，不能因服务端多暴露工具而扩大权限。

官方参考：[Zabbix 用户角色和 API 访问控制](https://www.zabbix.com/documentation/7.4/en/manual/web_interface/frontend_sections/users/user_roles)。

## Webhook

`POST /zabbix`，Header 为 `Authorization: Bearer <Web 配置的密钥>`。最小示例：

```json
{"event_id":"123456","event_value":"1","event_source":"0","event_name":"Linux: CPU usage high","severity":"4","host_id":"123","host_name":"example-linux","host_ip":"192.168.10.20","trigger_id":"456","event_date":"2026.10.23","event_time":"10:00:00","message":""}
```

event_source=0，接受 event_value=1 的问题与 0 的恢复。**所有 0–5 级都可接收与通知**，ai_min_severity 只控制自动分析最低级别，低级别仍可人工触发。相同 event_id + event_value 在 Redis 去重 24 小时。202 的 queued 仅表示入队；duplicate/skipped 要看响应体，不代表已发飞书或完成分析。

恢复操作应保留原问题 event_id，并传递 recovery_value=`{EVENT.RECOVERY.VALUE}`、recovery_id=`{EVENT.RECOVERY.ID}`；其中有效恢复信息优先于原 `{EVENT.VALUE}`。问题与恢复共用事件关联，恢复不自动再发起 AI。完整宏表见 [7.4 告警恢复配置](ZABBIX-74-ALERT-RECOVERY.md)。

可选 event_detail=`{EVENT.OPDATA}`、latest_value=`{ITEM.LASTVALUE1}`。未展开宏和缺失数据不能当成数值；多监控项表达式的 LASTVALUE1 未必是用户期待的指标。

## 资产同步与诊断

按 Host ID 同步最多 1000 个可见主机和主机组，达到上限页面会提示；超出时应分批人工导入或收窄服务端读取范围。本地多个分组保留，Zabbix 同步分组按源维护。名称可重复，Host ID 唯一；同步不生成 SSH 地址或覆盖人工审核的 SSH 参数。

设备类型优先可信 tag `aiops.device_type`（linux/windows/vmware/network/other）或 inventory OS；无法判断为 unknown。已知非 Linux 不运行 Linux 实时检查。未登记 Linux 的告警仍可以基于历史证据形成“缺少实时检查”的报告。

告警分析由统一 runtime 先查主机/事件/指标和有限历史，必要时才让模型补充受限查询与 SSH。查询、调用、结果和 Token 的实际上限见 ARCHITECTURE.md，不再使用旧的双调查器。
