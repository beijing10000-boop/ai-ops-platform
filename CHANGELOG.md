# Changelog

## Unreleased — P0 稳定性修复（2026-10-19）

- 修复飞书 Webhook 签名字符串中的换行符问题，抽出 `feishu_sign`。
- 将 AI 告警和主动问答提示词拆开，保留旧问答提示词兼容逻辑。
- 当告警 AI 分析不可用时，生成并尝试投递人工处理兜底卡片。
- 网络超时及飞书 5xx 采用最多三次有限重试；业务拒绝不自动重发。
- 修复模型单轮调用超过 8 个 MCP 工具时缺少对应工具输出的问题。
- 跳过 event_id/host_id 不合法的 MCP 调用。
- 修复审批回执和 README 字面换行；根据模拟开关显示审批标题。
- 增加飞书签名、提示词要求、告警降级通知的定向测试。

### 尚未完成

告警可靠持久化与可重试任务状态、回复告警与审批的生产联调、P1/P2/P3 后续安全及性能改造。仓库尚未作为正式生产版发布。

## Unreleased
- Initialized private development repository from available prior generated materials.
- Added Feishu QA progress-card adapter and initial operational documentation.
- No production release has been tagged.
