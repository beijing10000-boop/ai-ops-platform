# Zabbix 7.4 告警与恢复 → AI Ops → 飞书企业应用

## 配置位置

Zabbix 7.4：**告警 → 媒介类型 → Zabbix AI Analysis**，URL 保持 `http://172.20.200.93:8088/zabbix`。

请在媒介类型参数表中配置下列参数；其中 `event_id` 在恢复操作仍使用原故障事件 ID，便于在 AI Ops 中将恢复与告警关联。

| 参数 | 值 | 用途 |
|---|---|---|
| event_id | `{EVENT.ID}` | 原故障事件 ID |
| event_source | `{EVENT.SOURCE}` | 触发器事件来源，一般为 0 |
| event_value | `{EVENT.VALUE}` | 普通告警值通常是 1；恢复操作可能仍是原事件的 1 |
| recovery_value | `{EVENT.RECOVERY.VALUE}` | **恢复操作**解析为 0，AI Ops 优先识别此字段 |
| recovery_id | `{EVENT.RECOVERY.ID}` | 有效恢复事件 ID；用于可靠区分恢复 |
| severity | `{EVENT.NSEVERITY}` | 0–5 严重程度 |
| event_name | `{EVENT.NAME}` | 事件名称 |
| host_name | `{HOST.NAME}` | 主机名称 |
| host_ip | `{HOST.IP}` | 主机 IP |
| host_id | `{HOST.ID}` | Zabbix 主机 ID |
| host_groups | `{TRIGGER.HOSTGROUP.NAME}` | 多个主机组以逗号分隔 |
| event_date | `{EVENT.DATE}` | 原告警日期 |
| event_time | `{EVENT.TIME}` | 原告警时间 |
| recovery_date | `{EVENT.RECOVERY.DATE}` | 恢复日期 |
| recovery_time | `{EVENT.RECOVERY.TIME}` | 恢复时间 |
| event_duration | `{EVENT.DURATION}` | 持续时间（仅恢复后可准确获得） |
| trigger_id | `{TRIGGER.ID}` | 触发器 ID |
| url | `http://172.20.200.93:8088/zabbix` | 接收地址 |
| secret | Web 配置的 Zabbix Webhook 密钥 | HTTP Bearer 认证 |

**检查 Webhook JavaScript**：必须转发这些参数（可以使用整体 `JSON.stringify(params)`）；如果脚本仅发送手工定义的字段，要逐个加入新增参数。不要把 `secret` 放进日志或向外转发的事件正文。

## 必须开启恢复操作

Zabbix **告警 → 动作 → 触发器动作**：找到发送到 AI Ops 的动作，检查操作和**恢复操作**均配置发送消息、媒介类型是 `Zabbix AI Analysis`。检查动作的级别条件没有排除低优先级告警和恢复。

## 两次测试（建议专用测试主机）

1. 用测试 Trapper 监控项送入 `1`，确认 Webhook 的 `status=queued`、接收告警数增加和飞书收到对应级别卡片。
2. 送入 `0`，确认新恢复操作成功执行、恢复数增加、飞书收到绿色“告警恢复”卡片，包含恢复时间、所属分组、持续时间。

确认 `host_groups`、`event_date`、`event_time` 等宏由真实 Zabbix 动作展开；媒介类型的“测试”窗口可能原样传递宏。没有解析成功的宏不会显示在飞书卡片里。

**关于时区**：卡片采用 Zabbix 宏返回的当地时间。AI Ops 不额外偏移这些字符串时间，避免重复加八小时。

**安全**：收到 HTTP 202 只表示进入接口，可能是 skipped/duplicate；查看 Webhook 响应体、`alert_events` 和 `alert-worker` 日志判断是否真正发送成功。
