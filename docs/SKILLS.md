# 按 Skill 查询双 MCP

Skill 是**唯一的 AI 诊断策略来源**：数据源选择、工具顺序、分析与报告要求都写在 Skill 中，平台不再有固定的兼容诊断流程。平台以不可编辑的代码约束只读安全边界、飞书告警 JSON 输出字段、授权、Token 预算和证据脱敏。

## 平台维护的 Skill 与补充 Skill

- **平台维护的 Skill**：随平台版本维护，升级后自动更新，默认对飞书问答、Web 诊断、告警分析三个场景启用。正文只读，不能删除；可以调整启用状态、适用场景与优先级（这些选择在升级时保留）。内容来源是 [SSH MCP Server](https://github.com/beijing10000-boop/ssh-mcp-server) 和 [initMAX Zabbix MCP Server](https://github.com/initMAX/zabbix-mcp-server) 的真实只读工具。v1.2 起共 8 个：

  | Skill | 适用范围（`devices` / `types`） | 内容 |
  | --- | --- | --- |
  | platform-base | 所有任务 | 四阶段诊断流程、证据深度、按设备类型选择数据源、报告分级 |
  | platform-linux | 设备：Linux、未识别 | CPU / 内存 / 磁盘 / I/O / 网络 / 系统 / 不可达告警的 Zabbix + SSH 取证 |
  | platform-windows | 设备：Windows | 只用 Zabbix 性能计数器、服务与可用性监控项 |
  | platform-network | 设备：网络设备 | SNMP 接口状态、错误与丢弃、带宽、CPU / 内存、ICMP、重启 |
  | platform-nginx | 类型：nginx | 访问日志与错误日志、502 / 504 / 499、上游定位 |
  | platform-java | 类型：java、memory | Java 进程、启动参数、堆与 cgroup 限制、GC、重启 |
  | platform-service | 类型：service、logs、system | systemd 状态、退出原因、重启记录、端口与进程映射 |
  | platform-syslog | 类型：logs、system、memory、io、unreachable；设备：Linux | journald / /var/log 的 OOM、I/O、链路、内核、登录失败 |

  任务创建时保存所有已启用 Skill 的快照；预采集判定设备类型（Zabbix 标签、资产 OS、关联模板、主机组、接口类型，SSH 解析结果可修正）与告警类型（告警文本 + 触发器监控项 key）后，平台只把适用的 Skill 交给模型，报告的“本次加载的 Skill”标出哪些已应用。
- **自定义 Skill** 导入时选择与基础 Skill 的关系：
  - **补充**（推荐）：与基础 Skill 一起加载，只写本环境特有的规则；平台升级时基础规则自动更新，不再需要手工合并模板。
  - **替代**：该场景不再加载基础 Skill，自定义 Skill 需自行维护全部规则。v1.0 之前导入的 Skill 升级后默认为“替代”，行为与升级前完全一致。
- 设备类与告警类平台 Skill 是基础 Skill 的延伸：停用 platform-base（或它不服务某个场景）时，其余平台 Skill 在该场景也不加载。某个场景没有任何已启用的 Skill（例如停用了基础 Skill 且没有自定义 Skill）时，该场景的诊断任务会直接失败并提示启用。

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

### 适用范围（types / devices，可选）

```yaml
types: [nginx]            # 只在这些诊断类型的任务中交给模型；省略表示全部
devices: [linux, unknown] # 只在这些设备类型的任务中交给模型（linux / windows / network / vmware / other / unknown）
```

自定义 Skill 通常不需要这两项；只有写给特定设备或告警类型的长篇指引才建议限定，以免每个任务都携带无关内容。

### 预采集（prefetch，可选）

元数据可以声明“开始分析前由平台先采集什么”，平台在第一轮模型请求之前并行执行，结果放进首条消息的 `evidence.prefetched`，省掉工具发现、目标解析和首轮采集的往返：

```yaml
prefetch:
- scopes: [alert]                 # alert / qa / web
  types: [cpu]                    # 诊断类型，或 * 表示全部
  ssh: [ssh_diagnose_cpu, ssh_diagnose_processes]   # SSH 诊断，最多 6 个
  zabbix_items: [system.cpu.load, system.cpu.util]  # 对任务主机按 key 片段执行 item_get
  history: ["system.cpu.load[all,avg5]", system.cpu.util]  # 在 item_get 结果里按精确 key 或 * 模式选项，预采集历史与趋势
  schemas: [history_get, trend_get]                 # 提前给模型的工具参数结构，最多 4 个
```

平台的执行顺序：

1. **阶段 A（Zabbix）**：有 Host ID 时并行执行 `host_get`（判定设备类型）、按告警触发器 ID 的 `item_get` 与近 24 小时 `event_get`。触发器监控项 key 会校正告警类型（例如文本像 CPU、key 是 `nginx.*`），也会推导 systemd 服务名（`systemd.unit.info["xxx.service",...]`）。
2. **阶段 B**：按设备类型与校正后的类型合并适用 Skill 的规则；并行执行 zabbix_items 的 `item_get`、同一对象的相关监控项（触发器 key 里的网口索引、文件系统、磁盘名），以及 SSH 资产解析（只对 Linux 或未识别设备；Windows / 网络设备不连接 SSH）。
3. **阶段 C**：SSH 诊断与历史并行。可以组合的固定诊断用 `ssh_collect` 在同一 SSH 会话执行；带时间窗口的日志类工具自动使用告警前后 15 分钟（since / until）；需要服务名的工具在推导不出服务名时跳过并写入 `coverage.skipped`；`busy` / `timeout` 自动重试一次。history 依次取触发器监控项、同一对象的相关监控项、再按声明顺序匹配（`*` 为通配，`[`、`,` 按原文匹配），最多 8 项：history_get 取告警时间前后各 30 分钟（超过 1000 行自动翻页），trend_get 取近 7 天小时趋势（跳过 `system.cpu.num` 等常量项）。发给模型的是统计值、告警前后分段（alert_split）与样本。

- zabbix_items 只在任务有 Zabbix Host ID 时执行；写 `"*"` 表示不按 key 过滤、取该主机的监控项（最多 60 个，含最近采集时间），平台据此在 signals 里给出 `collection_freshness`。
- 预采集计入采集次数，但模型始终保留 `follow_up_calls` 次补查（AI 配置 → 分析预算；保底次数不超过配置的采集次数）。预采集已解析的 SSH 目标、已取得的证据被模型再次请求时直接复用，不再调用。
- SSH 解析失败、设备不适用、SSH MCP 未启用或连接失败时，不视为诊断缺口，而是写入 `capabilities` 与报告“诊断范围 → 能力说明”；令牌未授权的工具写入 `capabilities.unauthorized_tools`。

名称用 1–64 位小写字母、数字、连字符，platform-base 由平台保留。可创建多个 Skill，同一场景按优先级从高到低提供给模型；各 Skill 应说明自己的适用范围，减少冲突。启停、修改适用范围或正文都会产生新版本；修改参考资料时重新导入 ZIP。

## 平台如何执行

- list_mcp_tools：query 为空列工具名称，填完整工具名读取实际参数结构。
- call_mcp_tool：provider 为 ssh_mcp 或 zabbix_mcp，name 为原生工具名，arguments 为已发现结构的参数。
- read_skill_resource：按 Skill 名称与包内相对路径，读取对应参考资料。

两个 MCP 均按实际需求才连接；SSH 工具须有只读标记及受限参数，目标从授权资产目录精确核验，平台固定 expected_revision；不接受任意 Shell。Zabbix 仍限制为九种安全查询，适配 initMAX 的 output 字符串与 extra_params 差异，历史监控项需先经 item_get 返回。查询来源与先后次序写在 Skill 中，授权和参数边界保留在平台与 MCP 服务端。

每次 MCP 原生调用（含预采集）计入采集预算；`list_mcp_tools` 只读取本任务已加载的工具目录，与本地 Skill 参考资料读取一样不计采集次数；所有模型响应按实际返回记录 Token。多层目录分析需要多次工具调用，请在“系统配置 → AI 配置 → 分析预算”按需增加轮次、次数、时间及单次结果长度。快速模式原有小预算也适用于 Skill，因此复杂诊断宜选标准或深度模式并调整预算。Skill 不能越过预算、服务端路径白名单或 Token 授权。

## 证据编号与引用核对

- 每条 MCP 工具结果（目录列表除外）带证据编号 `evidence_id`（E1、E2…），按采集先后编号；模型重复请求同一调用时（同一轮或跨轮）只执行一次并沿用原编号。任务详情的“证据与工具执行记录”在每条证据前显示编号与调用参数。
- 告警分析的 JSON 输出含 `evidence` 数组（每项 `{"id": "E2", "quote": "原样摘录的数值或原文"}`）与 `findings`（`confirmed` 已确认事实、`probable` 高可信推断、`hypotheses` 待验证假设，每项写 statement 与证据编号或验证方法）；问答与 Web 诊断在正文中写（E2）。
- 平台用代码核对引用：编号必须存在且对应成功的采集结果；quote 中的每个数字都要在对应证据的测量值里找到（按 quote 自身的小数位比较，如 12% 可对应 12.4；itemid、clock、pid 等标识字段不参与比对），没有数字时按至少 4 个字符的原文包含判断。核不上的引用会被剔除并列在报告中；没有有效引用的“已确认事实”自动降为推断。
- 依据可信度由核对结果决定，不由模型自评：至少 2 条有效引用且覆盖两类数据源（或 3 条以上覆盖不同查询）为“高”，有有效引用为“中”，没有为“低”。告警结论的有效引用少于 2 条或有被降级的事实时，平台会先要求模型补证一次。报告末尾的“证据核对”一节列出有效引用、被剔除的引用和三类陈述。
- 报告中的“诊断范围（平台生成）”列出目标、设备类型与诊断路径、采集时间、模型实际使用的 Zabbix 历史查询窗口、各数据源成功与失败的证据条数，以及不可用的能力与原因。模型正文不需要复述这些内容，也不必逐条罗列证据数值，只写结论、关键依据（注明编号）、建议和尚未证实的方向；告警的 `action` 为数组，由平台编号。自定义 Skill 若仍要求“写明目标和时间范围”，可以删去这一条。
- 预采集结果之外，平台会附带 `evidence.signals`：SSH MCP 返回的 warning/critical 发现；Zabbix 最新值中的负载 / CPU 背离、内存与文件系统利用率超过 90%；告警窗口均值与 7 天基线的倍数（alert_vs_baseline）、告警后相对告警前的升高（rise_at_alert）或告警前已偏高（elevated_before_alert）；以及触发器近 24 小时反复触发（recurrence）。每条都带来源证据编号，模型可直接引用。

报告显示创建时保存的 Skill 名称、版本、SHA256、目标 SSH 资产 ID、预算及来源证据。更新/停用/删除 Skill 不会更改已创建任务；重试创建新任务，加载当前启用版本。正文与包文件加密存储；加载版本保存在加密任务快照。日志原文继续受 logs.read 控制。AI 执行存在模型判断差异，以报告的实际工具执行记录核验；工具缺失或证据不足应如实说明，不能将失败解释为正常。
