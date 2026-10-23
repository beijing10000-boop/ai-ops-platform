# MCP 双连接配置（只读 / 写入）

## 为什么是两套

只读连接专门提供给 Web AI 诊断、飞书问答与告警分析；写入连接专门用于独立 `change-worker` 在飞书管理员二次审批后执行受限操作。关闭写入开关不会解除 MCP 服务本身的 Zabbix 权限，请独立限制各连接的权限。

## Web「系统配置」中填写

| 字段 | 作用 | 怎么获取 |
|---|---|---|
| Zabbix MCP URL | AI 只读查询的 MCP 接口 | 在已部署的 MCP Server 配置中找到 Streamable HTTP 地址，例如 `http://MCP-SERVER:18080/mcp` |
| 只读 MCP Token | AI 查询连接的认证 | 在只读 MCP Server 的认证配置中创建或读取 Bearer Token；其背后的 Zabbix API 用户应只有读取权限 |
| 写入 MCP 地址 | 管理员已审批操作专用的 MCP 接口 | **独立运行**第二个 MCP Server 实例，配置具有最低必要写权限的 Zabbix API 身份，并取得该实例地址 |
| 写入 MCP Token | 写入 MCP 接口认证 | 从独立写入 MCP 的认证配置中获取 Bearer Token，不要复用只读 Token |
| 变更审批管理员 Open ID | 控制谁可以发起并确认变更 | 飞书开放平台通过用户身份接口获得用户 Open ID；请使用当前机器人应用对应的 Open ID |
| 受限写入开关 | 默认关闭，允许管理员确认事件 | 点击「开启受限写入」，系统检查写入 MCP 的 `event_acknowledge` 工具和参数后才保存开启状态 |

**注意：** MCP 的 Bearer Token 与 Zabbix API Token 是否相同取决于 MCP Server 的鉴权实现，不能直接假设二者相同。当前项目只识别 `event_acknowledge`，不能修改主机、模板、触发器或监控项。

## 实际开启流程

1. Web 登录后，填写两套 MCP 连接，点击保存；敏感 Token 在 Web 中只以掩码显示。
2. 先在「连接调试」验证只读 MCP。
3. 在「系统配置 → MCP 权限分离与写入控制」点击「开启受限写入」，系统只发现工具、不执行实际变更。
4. 飞书管理员使用 `@AI 确认告警 <事件ID>`，收到审批号后，由同一管理员在同群五分钟内发送 `@AI 确认执行 <审批号>`。
5. 需要停止时，点击「关闭写入」，待执行任务的执行器也会再次核对开关。

**当前限制：** 写入 MCP 的具体参数及用户权限必须在独立测试 Zabbix 核验；审批卡片按钮、执行结果飞书回填、执行后状态回查仍未完成。不要直接用生产事件做首次写入测试。

## 更新服务器

本次配置在现有 SQLite 数据库中新增键，不删除原配置；无需重置 `APP_ENCRYPTION_KEY`。Docker Compose 不需要配置独立的写入 MCP 环境变量，旧的 `ZABBIX_WRITE_MCP_URL/TOKEN` 配置不再作为新代码的读取来源。
