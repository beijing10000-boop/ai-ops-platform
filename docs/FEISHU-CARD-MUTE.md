# 飞书卡片内直接屏蔽同类告警

本功能完全不依赖 Zabbix 写入 MCP，不修改监控项、触发器或维护周期，只过滤 AI Ops 服务器发往飞书的同类问题告警。恢复通知照常发送。

## 飞书开放平台必配

1. 打开企业自建应用 → **事件与回调 → 回调配置**（不是“事件配置”）。
2. 回调接收方式选择 **长连接**；与现有消息接收复用同一个 feishu-receiver。
3. 订阅 **卡片回传交互** `card.action.trigger`，保存并发布应用版本。
4. 应用必须有机器人及发送交互卡片的相关权限；群里使用该企业自建应用机器人。
5. 由于历史版 Python SDK 的 WebSocket CARD 帧处理问题，项目已将 `lark-oapi` 下限提高至 1.7.5。需要 **重新构建** feishu-receiver 镜像。

## 管理员控制

沿用飞书 Web 登录管理员的 Open ID 白名单，部署环境变量 `FEISHU_ADMIN_OPEN_IDS=ou_xxx,ou_yyy`。卡片按钮只允许列表内的人点击生效；未授权操作返回飞书错误提示。

按钮针对同一 `host_id` + `trigger_id`，可选 1/4/24/72/168 小时；回调采用签名校验防篡改。成功后飞书即时提示；不跳转 Web 页面。

**不要重新生成 APP_ENCRYPTION_KEY**：卡片签名使用现有部署密钥；Web 与 feishu-receiver、alert-worker 必须使用一致的密钥。

## 93 升级

```bash
cd /data/zabbix-ai-ops
git pull --ff-only
docker compose up -d --build --force-recreate --no-deps web alert-worker feishu-receiver
docker compose ps web alert-worker feishu-receiver
docker compose logs --since=5m --no-color feishu-receiver | grep 'FEISHU_MUTE_ACTION'
```

生成**新的真实告警**查看 5 个屏蔽时长按钮。只有飞书卡片按钮点击触发的 `card.action.trigger` 才会写入本地屏蔽记录；不会调用 Zabbix API 写方法。

验证：点击 1 小时 → 看到成功 toast → Web 后台可查看有效屏蔽；同一主机同一触发器的**后续新问题通知**不再推飞书；其他告警、恢复通知不受影响。可以从 Web 提前解除屏蔽。

若飞书提示 `200340` 或无反应，首先核对**回调配置**订阅/发布及 Python SDK 的版本，再查看 `feishu-receiver` 日志。
