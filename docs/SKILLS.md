# 按 Skill 查询双 MCP

Skill 是**唯一的 AI 诊断策略来源**：数据源选择、工具顺序、分析与报告要求都写在 Skill 中，平台不再有固定的兼容诊断流程。平台以不可编辑的代码约束只读安全边界、飞书告警 JSON 输出字段、授权、Token 预算和证据脱敏。

## 平台基础 Skill 与补充 Skill

- **平台基础 Skill（platform-base）**：随平台版本维护，升级后自动更新，默认对飞书问答、Web 诊断、告警分析三个场景启用。正文只读，不能删除；可以调整启用状态、适用场景与优先级（这些选择在升级时保留）。内容来源是 [SSH MCP Server](https://github.com/beijing10000-boop/ssh-mcp-server) 和 [initMAX Zabbix MCP Server](https://github.com/initMAX/zabbix-mcp-server) 的真实只读工具。
- **自定义 Skill** 导入时选择与基础 Skill 的关系：
  - **补充**（推荐）：与基础 Skill 一起加载，只写本环境特有的规则；平台升级时基础规则自动更新，不再需要手工合并模板。
  - **替代**：该场景不再加载基础 Skill，自定义 Skill 需自行维护全部规则。v1.0 之前导入的 Skill 升级后默认为“替代”，行为与升级前完全一致。
- 某个场景没有任何已启用的 Skill（例如停用了基础 Skill 且没有其他 Skill）时，该场景的诊断任务会直接失败并提示启用。

## 使用步骤

1. 在连接管理分别保存并验证 SSH MCP 与 initMAX Zabbix MCP。
2. 进入“Skill 管理”，确认 platform-base 已启用，点击“验证工具”检查实际目录。验证只初始化 MCP 和读取工具目录，不登录主机、不调用模型。
3. 需要本环境规则时，点击“下载补充 Skill 示例”，按需修改 SKILL.md 后上传，关系选“补充”，优先级高于基础 Skill（默认 100 > 50）。
4. 原来使用整份自定义 Skill（如 ops-mcp-readonly）的环境：可以继续以“替代”方式使用；也可以把其中的环境特有规则抽出来做成补充 Skill，然后停用原 Skill，以后随平台升级自动获得新的基础规则。
5. 在飞书或 Web 输入“查询 198.51.100.21 现在 CPU”或“查询 198.51.100.21 的 /data 目录占用，展开 3 层”。IP 必须已在 SSH 服务登记、核验公钥、绑定凭据，且在专用 Token 主机组/动作授权范围内。无需先选择 Zabbix 主机。

实时问题通过 ssh_resolve_target 按已登记 IP 精确解析；历史告警用 Zabbix 查询。Zabbix 同 IP 多条 Host ID 只影响需要明确监控目标的历史查询，不影响独立 SSH 实时诊断。

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

名称用 1–64 位小写字母、数字、连字符，platform-base 由平台保留。可创建多个 Skill，同一场景按优先级从高到低提供给模型；各 Skill 应说明自己的适用范围，减少冲突。启停、修改适用范围或正文都会产生新版本；修改参考资料时重新导入 ZIP。

## 平台如何执行

- list_mcp_tools：query 为空列工具名称，填完整工具名读取实际参数结构。
- call_mcp_tool：provider 为 ssh_mcp 或 zabbix_mcp，name 为原生工具名，arguments 为已发现结构的参数。
- read_skill_resource：按 Skill 名称与包内相对路径，读取对应参考资料。

两个 MCP 均按实际需求才连接；SSH 工具须有只读标记及受限参数，目标从授权资产目录精确核验，平台固定 expected_revision；不接受任意 Shell。Zabbix 仍限制为九种安全查询，适配 initMAX 的 output 字符串与 extra_params 差异，历史监控项需先经 item_get 返回。查询来源与先后次序写在 Skill 中，授权和参数边界保留在平台与 MCP 服务端。

每次 MCP 目录请求和原生调用计入采集预算，本地 Skill 参考资料读取不计采集次数；所有模型响应按实际返回记录 Token。多层目录分析需要多次工具调用，请在“系统配置 → AI 配置 → 分析预算”按需增加轮次、次数、时间及单次结果长度。快速模式原有小预算也适用于 Skill，因此复杂诊断宜选标准或深度模式并调整预算。Skill 不能越过预算、服务端路径白名单或 Token 授权。

报告显示创建时保存的 Skill 名称、版本、SHA256、目标 SSH 资产 ID、预算及来源证据。更新/停用/删除 Skill 不会更改已创建任务；重试创建新任务，加载当前启用版本。正文与包文件加密存储；加载版本保存在加密任务快照。日志原文继续受 logs.read 控制。AI 执行存在模型判断差异，以报告的实际工具执行记录核验；工具缺失或证据不足应如实说明，不能将失败解释为正常。
