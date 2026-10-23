# 常见问题（FAQ）

## 群里 @ 机器人偶尔无响应

同一飞书应用的多个 WebSocket 长连接可能将事件分配给不同实例；检查重复部署，确保接收实例共享同一任务处理逻辑。先查看 `zabbix-ai-feishu` 日志是否有 `FEISHU_EVENT_RECEIVED`。

## `name 'log' is not defined`

如果在阻塞的 `lark.ws.Client(...).start()` **之后**声明 `log`，回调执行时该变量尚未初始化。应在启动长连接之前初始化日志对象。

## 收到飞书事件，但 AI Worker 不执行

确认 `feishu_bot.py` 的入队队列为 `ai-questions` 而不是 `ai-alerts`，检查 `ALLOWED_CHAT_IDS` 和 Redis 去重。用 `rq info --url redis://127.0.0.1:6379/0` 查看队列状态。

## `connected to wss://msg-frontier.feishu.cn` 但没有事件

长连接成功不等于一定收到 @ 消息。检查是否订阅 `im.message.receive_v1`、相关权限是否发布、机器人是否加入群聊、群里是否真正 @ 了应用机器人。

## API 正常但无告警任务

检查 Webhook 的 HTTP 返回体是否为 `queued`、`skipped` 或 `duplicate`；HTTP 202 本身不能说明任务已入队。

## 飞书 HTTP 200 但无回复

需要继续检查响应 JSON 的 `code == 0` 和目标群 ID；不能仅凭 HTTP 状态判断业务成功。
