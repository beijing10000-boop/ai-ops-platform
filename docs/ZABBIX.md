# Zabbix Webhook 对接

项目开发版通过 `POST /zabbix` 接收 JSON 告警，使用 `Authorization: Bearer <secret>` 校验。

## 必要字段

```json
{
  "event_id": "123456",
  "event_value": "1",
  "event_source": "0",
  "event_name": "Linux: Zabbix agent is not available",
  "severity": "3",
  "host_id": "123",
  "host_name": "example-linux",
  "host_ip": "192.0.2.10",
  "trigger_id": "456",
  "subject": "Zabbix alert",
  "message": ""
}
```

Webhook Secret 必须在 Web 管理台设置。不要在任何公共渠道共享密钥。

## 过滤行为

当前预览版只接受触发器 Problem 事件：`event_source=0`、`event_value=1`。严重级别由 Web 的 `min_severity` 管控（0–5）。恢复事件默认跳过。成功排入队列返回 HTTP 202 + `status=queued`。重复 ID 则返回 `status=duplicate`，低等级或其他事件返回 `skipped`。

**注意：HTTP 202 并不保证任务成功执行；请检查 Worker 日志及 Redis 队列。**

## 常见诊断

- HTTP 401：Webhook Bearer 密钥错误。
- HTTP 422：事件 ID 缺失、级别值格式错误等。
- HTTP 202 `skipped`：确认事件类型和阈值。
- `duplicate`：24 小时内同一事件 ID 已接收过。
- Worker 没有处理：检查 `docker compose logs -f alert-worker`。

生产对接之前建议在隔离环境测试媒体类型和动作的具体 JSON 参数。


## 飞书卡片最新值

Webhook JSON 新增可选字段 `latest_value`，故障和恢复事件均可设置：

```json
{
  "event_id": "{EVENT.ID}",
  "event_value": "{EVENT.VALUE}",
  "trigger_id": "{TRIGGER.ID}",
  "latest_value": "{ITEM.LASTVALUE1}"
}
```

在 Zabbix 告警媒介类型的 Webhook 参数中添加 `latest_value`，值使用 `{ITEM.LASTVALUE1}`。注意它表示触发器表达式中的第一个监控项的最近值，单位应由发送方提供；多监控项表达式未必对应用户期望的指标。对于恢复事件，Zabbix 如提供合适的 `recovery_value` 可作为兜底，优先级仍是 `latest_value`。对于已有未包含此字段的事件，卡片显示“未提供”而不虚构数值。修改 webhook 参数后应分别触发新故障和恢复告警检查宏展开效果。

## 飞书卡片事件详情

在 Zabbix Webhook 参数里添加 `event_detail`，值设为 `{EVENT.OPDATA}`（触发器 Operational data），例如 `Current state: down (2)`。若触发器未设置 Operational data，请在触发器或触发器原型中配置，例如 `Current state: {ITEM.LASTVALUE1}`。需要确认故障和恢复通知均能展开宏；未提供 `event_detail` 时兼容使用原 `latest_value`（恢复还可回退 `recovery_value`）。


## AI 告警分析：MCP 多轮只读调查

自动 AI 分析和飞书按钮手动 AI 分析使用同一调查流程。首先读取 event_get、trigger_get、host_get 和 triggerids 定位的 item_get；模型可以继续请求以下受限工具：related_items、search_host_items（仅本告警 hostids）、item_history、item_trend（仅已验证 itemids）。

限制：最多 12 次 MCP 查询、4 轮模型工具交互、每监控项最多 120 个历史点、趋势 24 小时、最多 8 个关联 item ID、总时间预算约 70 秒。历史查询按告警发生时间或恢复时间回溯；对 1 小时以上的需求应控制采样开销。若 MCP 未配置、查询失败或超预算，AI 仍可报告证据不足，禁止编造数值。MCP 返回的不可信文本只作为数据。日志可检查 \`ALERT_MCP_COMPLETED\` 和 \`ALERT_MCP_QUERY_FAILED\`，不记录 token。

上线建议先运行 \`python3 -m compileall -q app\` 和 \`docker compose run --rm --no-deps alert-worker python -m pytest -q tests/test_alert_mcp_multiround.py\`（若镜像未安装 pytest，先在独立测试环境安装），再更新 alert-worker。监测 MCP 请求量、分析耗时及模型工具调用支持情况；部分兼容 OpenAI Responses API 的第三方模型不一定支持函数调用。


## 统一原生 MCP 工具调用

告警自动分析、卡片手动分析、飞书 AI 问答共用 `app/mcp_runtime.py`，直接向模型公开 MCP Server `list_tools` 返回的原生工具名称和输入参数 schema，不再使用客户端的工具白名单或中间封装。独立保留 `ai_alert_prompt`、`ai_qa_prompt`。每任务最多 6 轮、16 次 MCP 调用、单轮最多 8 次，单任务预算约 110 秒、每个响应正文最多约 14,000 字符。查看 `MCP_AGENT_TOOL`、`MCP_AGENT_DONE` 日志。

**上线门槛：** 此模式信任 MCP 服务端发布的全部工具，并不能保证工具只读。你之前列出的 MCP 工具包含 `configuration_importcompare`、`user_login`、`token_get` 等，需要先在 MCP Server 端验证这些工具的权限策略及所用 Zabbix 账号是否已严格只读、是否禁止读取敏感资料。否则模型可能调用这些工具。本项目客户端不再代替服务端进行授权。
