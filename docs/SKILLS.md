# 按 Skill 查询双 MCP

v0.9.0 增加“Skill 管理”。加载并启用后，平台把指引与任务问题交给模型，由模型选择服务、原生工具和查询顺序。Skill 模式不会预先执行固定 Zabbix 查询或 Linux 剧本。没有启用 Skill 的场景沿用旧流程。

## 使用内置模板

1. 先升级独立 SSH MCP 至 v0.4.1；在连接管理分别保存并验证现有 SSH、initMAX Zabbix MCP。
2. 进入“Skill 管理”，点击“下载运维模板 ZIP”。原样即可使用，也可解压后修改 SKILL.md 与 references 文本，再压缩上传。
3. 选择适用场景（飞书问答、Web 诊断、告警分析）与允许使用的后台服务，点击“验证并预览”。模板建议同时勾选两种服务。
4. 将启用状态设为“启用”，点击“导入 Skill”；已有同名包时明确勾选“更新同名 Skill”。点击“验证工具”检查实际目录。验证只初始化 MCP 和读取工具目录，不登录主机、不调用模型。
5. 在飞书或 Web 输入“查询 172.20.2.101 现在 CPU”或“查询 172.20.2.101 的 /data 目录占用，展开 3 层”。IP 必须已在 SSH 服务登记、核验公钥、绑定凭据，且在专用 Token 主机组/动作授权范围内。无需先选择 Zabbix 主机。

模板来源是 [SSH MCP Server](https://github.com/beijing10000-boop/ssh-mcp-server) 和 [initMAX Zabbix MCP Server](https://github.com/initMAX/zabbix-mcp-server)，只使用这两个服务的真实只读工具。实时问题通过 ssh_resolve_target 按已登记 IP 精确解析；历史告警用 Zabbix 查询。Zabbix 同 IP 多条 Host ID 只影响需要明确监控目标的历史查询，不影响独立 SSH 实时诊断。

## 包格式

可上传单个 UTF-8 Markdown，或 ZIP 内唯一 SKILL.md 与 references/ 下的 .md/.txt。文件最大 1 MB，解压总计最大 1 MB、最多 32 文件，每个文本最大 64 KB；不解压到磁盘，不加载脚本、可执行程序、链接或第三方依赖。

SKILL.md 使用如下元数据，正文写中文查询步骤：

```markdown
---
name: my-ops-skill
description: 描述能力及适用问题，例如查询实时 Linux 内存与进程占用。
---

按当前问题选择必要工具，使用 SSH MCP 查询实时内存与进程。
先核验已登记目标，使用实际返回的 host_id 和 revision；完整说明结果及不足。
```

名称用 1–64 位小写字母、数字、连字符。可创建多个 Skill，同一场景按优先级从高到低提供给模型；各 Skill 应说明自己的适用范围，减少冲突。启停、修改适用范围或正文都会产生新版本；修改参考资料时重新导入 ZIP。

## 平台如何执行

- list_mcp_tools：query 为空列工具名称，填完整工具名读取实际参数结构。
- call_mcp_tool：provider 为 ssh_mcp 或 zabbix_mcp，name 为原生工具名，arguments 为已发现结构的参数。
- read_skill_resource：按 Skill 名称与包内相对路径，读取对应参考资料。

两个 MCP 均按实际需求才连接；SSH 工具须有只读标记及受限参数，目标从授权资产目录精确核验，平台固定 expected_revision；不接受任意 Shell。Zabbix 仍限制为九种安全查询，适配 initMAX 的 output 字符串与 extra_params 差异，历史监控项需先经 item_get 返回。查询来源与先后次序写在 Skill 中，授权和参数边界保留在平台与 MCP 服务端。

每次 MCP 目录请求和原生调用计入采集预算，本地 Skill 参考资料读取不计采集次数；所有模型响应按实际返回记录 Token。多层目录分析需要多次工具调用，请在“系统配置 → AI 配置 → 分析预算”按需增加轮次、次数、时间及单次结果长度。快速模式原有小预算也适用于 Skill，因此复杂诊断宜选标准或深度模式并调整预算。Skill 不能越过预算、服务端路径白名单或 Token 授权。

报告显示创建时保存的 Skill 名称、版本、SHA256、目标 SSH 资产 ID、预算及来源证据。更新/停用/删除 Skill 不会更改已创建任务；重试创建新任务，加载当前启用版本。正文与包文件加密存储；加载版本保存在加密任务快照。日志原文继续受 logs.read 控制。AI 执行存在模型判断差异，以报告的实际工具执行记录核验；工具缺失或证据不足应如实说明，不能将失败解释为正常。
