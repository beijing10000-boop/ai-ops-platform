# 升级说明

## v1.1.0 → v1.2.0

没有数据库迁移。先升级 SSH MCP 到 v0.6.0，再升级平台；顺序反过来也能运行，只是新工具（Nginx、系统日志、Java、服务详情、单会话多项采集）在 SSH MCP 升级前不可用，报告的“证据覆盖”会把它们列为跳过项并注明原因。

### 1. SSH MCP 升级到 v0.6.0

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://服务器IP:9099/healthz
```

应返回 0.6.0（`WEB_BIND_IP` 设成服务器地址时 curl 用该地址）。启动时服务会给已持有 `logs` 动作的客户端令牌自动补上 nginx、nginx_access、syslog、java、service_detail，持有 `log_errors` 的补上 syslog，持有 `sockets` 或 `service` 的补上 service_map（写审计 `mcp_client_actions_extended`）；`ssh_collect` 只要令牌拥有任一可组合的固定动作就可用。`jvm`（jcmd/jstat，有安全点开销）需要在 SSH MCP Web → 系统配置 → MCP 接入里点“编辑权限”手动勾选。诊断账号要在 systemd-journal 或 adm 组（或使用 root）才能读到完整系统日志，否则报告会标注“日志访问受限”。

### 2. 平台升级到 v1.2.0

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://服务器IP:8088/healthz
```

healthz 应返回 version 1.2.0（未启用飞书接收器时去掉 `--profile feishu`）。第一次打开 Skill 管理页或创建任务时，platform-base 自动更新，并新增 platform-linux、platform-windows、platform-network、platform-nginx、platform-java、platform-service、platform-syslog 七个平台维护的 Skill（默认启用，可单独停用）。使用“替代”模式自定义 Skill 的场景仍然只加载自定义 Skill，行为不变。

预算：默认值调整为 quick 3 轮 / 8 次 / 90 秒、standard 5 轮 / 16 次 / 180 秒、deep 8 轮 / 24 次 / 300 秒，并新增 `follow_up_calls`（预采集之后模型至少还能补查的次数）与 `extension_rounds`（有采集失败时可追加的轮次）。在 AI 配置里自定义过预算的项保持原值、未填的项使用新默认值；如果 standard 的 `seconds` 仍是 110，建议改为 180。Token 预算口径不变（总量减缓存命中）；`list_mcp_tools` 取工具参数结构不再计入采集次数，预采集计入。

工具目录缓存：平台每个进程缓存 MCP 工具目录 60 秒。在 SSH MCP 里改了平台客户端的动作授权后，到平台 连接管理 → 工具注册表 点“刷新目录”，所有 worker 的下一个任务就会使用新授权。

### 3. 验收

- 对一条 Linux CPU 负载告警点“AI 分析”：详细报告第 1 轮请求快照的 `evidence.prefetched` 里应有 `ssh_collect`（cpu、processes、pressure 同一次会话）、触发器监控项的 `history_get`（含 `alert_split`）与 `trend_get`；报告“诊断范围”显示“设备类型与路径：Linux，Zabbix 历史 + SSH 实时联合分析”；飞书卡片出现“核心证据”一节且没有证据编号。
- 对一台 Windows 或网络设备的告警点“AI 分析”：SSH MCP 的审计里不应出现该任务的调用；报告写明“仅 Zabbix 监控数据”，本次加载的 Skill 中 platform-windows / platform-network 标记为已应用。
- 对一台未在 SSH MCP 登记的 Linux 主机告警点“AI 分析”：报告“能力说明”写明 SSH MCP 不可用的原因，任务状态不因此变为失败。
- 连接管理 → 工具注册表：SSH 表列出 v0.6.0 的新工具及本令牌是否已授权；“诊断测试”选一台已登记主机试跑 `ssh_diagnose_service_map`，应返回监听端口与进程的映射，SSH MCP 审计里出现对应记录，平台审计里有 `tool_probe`。
- 回滚：v1.1.0 只认识一个平台维护的 Skill，也不接受 `types` / `devices` 元数据，所以切回旧版本前要先删除 v1.2 新增的 7 个平台 Skill（自定义 Skill 与历史任务不受影响），再切换提交并重新构建：

```bash
docker compose exec -T web python -c "import sqlite3; db=sqlite3.connect('/app/data/app.sqlite3'); print(db.execute(\"DELETE FROM platform_skills WHERE managed=1 AND name!='platform-base'\").rowcount); db.commit()"
git switch --detach <v1.1.0 的提交>
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
```

  v1.2 创建的任务报告在旧版本中仍可打开，新增字段会被忽略。

## v1.0.x → v1.1.0

v1.0.1 到 v1.1.0 都没有数据库迁移，从 v1.0.0 或任一 v1.0.x 升级都按“v1.0.0 → v1.0.1”一节的命令执行一次，healthz 应返回 version 1.1.0。升级后到 系统配置 → AI 配置，把“深度思考”改为“关闭”，先点“验证模型连接”确认返回“AI连接成功”，再保存；之后的分析每轮明显变快。升级后第一次打开 Skill 管理页或创建任务时 platform-base 自动更新（版本号 +1）。

验收：

- 对一条告警（Linux 或网络设备都可以）点“AI 分析”，飞书卡片显示诊断结论、处理建议和分析与依据，1000 字内，没有 E2 之类的证据编号；点“查看完整诊断报告”在飞书内置浏览器中打开报告页（飞书客户端 7.5 及以上）。
- 详细报告里第 1 轮请求快照的 `prefetched` 应已包含按触发器查到的 `item_get`、`event_get`，以及 `history_get`、`trend_get`；典型情况下只有 1 轮模型请求。
- 系统配置 → AI 配置里如果自定义过 standard 预算而没有填 `seconds`，升级后默认变为 180 秒；带思考的模型建议 `rounds` 保持 4、“模型请求超时”设为 120。

## v1.0.0 → v1.0.1

没有数据库迁移，不改配置，不需要先备份（备份照常做也可以）。在平台部署目录执行：

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
```

healthz 应返回 version 1.0.1（`WEB_BIND_IP` 设成了服务器地址时 curl 用该地址）。未启用飞书接收器时去掉 `--profile feishu`。升级后第一次打开 Skill 管理页或创建诊断任务时，platform-base 自动更新到新版本（Skill 管理页里版本号 +1），管理员的启用、场景、优先级选择保留；自定义 Skill 不受影响。浏览器按 Ctrl+F5 刷新。

验收：对一条 Linux CPU 告警点“AI 分析”，下载详细报告检查：

- 第 1 轮请求快照的 `prefetched` 里已有 `history_get` 和 `trend_get`，典型情况下只有 1 轮模型请求；
- “诊断不足”里不再出现 “history window must be 1–86400 seconds” 或 sortfield 相关错误；
- 模型接口出错时（可临时填错 API Key 验证），飞书卡片显示“部分完成”和原因（如“AI 模型请求被拒绝”），而不是“分析失败，请稍后重试”。

使用带思考的模型（如 DeepSeek）时，建议在 AI 配置里把 standard 预算的 `seconds` 提高到 150–180、`rounds` 保持 4，“模型请求超时”设为 120。

## v0.9.9 → v1.0.0

本次有两次数据库迁移（v7、v8，启动时自动执行，只新增表和列），不改变飞书卡片签名，也不需要重新配置 MCP、AI 或飞书。按以下顺序操作。

### 1. 先升级独立 SSH MCP 到 v0.5.0（推荐）

平台兼容 v0.4.1 及以上版本，但负载/CPU 背离、D 状态进程、1 秒 CPU 增量、失败原因代码，以及“只向模型展示令牌有权执行的工具”都依赖 v0.5.0。在 SSH MCP 的部署目录执行（备份方法见该项目的 v0.4 发布说明）：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

应返回 0.5.0。原客户端令牌、主机与动作授权都不用改。

### 2. 备份并升级平台

v1.0 新建的任务按新格式保存 Skill 快照，旧版本读不了，所以这次一定要先备份（命令见下方“已部署 ai-ops-platform”一节，含停止服务、复制数据卷、记录当前提交）。然后在平台部署目录执行：

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
```

healthz 应返回 version 1.0.0。未启用飞书接收器时去掉 `--profile feishu`；不要执行 `down -v`。浏览器按 Ctrl+F5 刷新。如果 `WEB_BIND_IP` 设成了服务器地址，curl 要用该地址，127.0.0.1 访问不到。

**构建时 pip 下载超时**（`ReadTimeoutError: HTTPSConnectionPool(host='files.pythonhosted.org'...)`）：v1.0 升级了依赖，第一次构建要重新下载全部 Python 包。构建失败时 compose 不会替换正在运行的容器，旧版本照常运行，数据库也没有变化。

Dockerfile 已加长超时并自动重试。如果访问 PyPI 仍然很慢，在部署目录的 `.env` 中加一行镜像源，例如：

```bash
PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple
```

然后重新执行上面的 `docker compose ... up -d --build`。镜像源地址会写进镜像构建记录，不要使用带账号密码的地址。

### 3. 处理原有 Skill（必须看）

升级后“Skill 管理”里会多出平台维护的 `platform-base`，默认对告警分析、飞书问答、Web 诊断三个场景启用，只读，以后随平台版本自动更新。

原有 Skill（例如 `ops-mcp-readonly`）升级后是“替代”模式：在它启用的场景里，platform-base 不会加载，行为与 v0.9.9 一样。但这样也用不到 v1.0 的预采集、7 天基线和新的报告规则。建议改成：

1. 在“Skill 管理”导出原 Skill 备份。
2. 原 Skill 若是平台模板、没有本地修改：直接停用它，由 platform-base 接管。
3. 有本地规则（如 IP 网段约定、主机组习惯、报告要求）：点“下载补充 Skill 示例”，只把本地规则写进去，导入后关系选“补充”并启用，然后停用原 Skill。补充 Skill 不要再抄写基础规则，否则两份规则会一起发给模型。

改完后在“Skill 管理”点“验证工具”。新任务才使用新规则，已有任务不受影响。

### 4. 确认新配置项

| 位置（系统配置） | 配置 | 默认值 | 说明 |
| --- | --- | --- | --- |
| 飞书配置 | 复用同一触发器近期分析 | **2 小时** | 同一主机、同一触发器 2 小时内已分析过，新告警只发通知，卡片注明上次分析的时间、报告链接和 24 小时告警次数。手动“AI分析”不受影响。设为 0 关闭 |
| 飞书配置 | 按告警级别使用快速分析 | 不按级别降档 | 可选“警告及以下”或“一般严重及以下”，这些告警自动分析用快速模式 |
| 飞书配置 | 使用快速分析的主机组关键字 | 空 | 主机组包含任一关键字（英文逗号分隔，如“测试环境”）的告警用快速模式 |
| 飞书配置 | 自动分析每日 Token 上限 | 0（不限） | 按北京时间自然日统计自动告警分析，达到后只发通知；手动分析不计入 |
| AI 配置 | 诊断明细保留天数 | 0（永久） | 超过天数的已结束任务删除 MCP 证据和逐轮交互明细，结论、状态和 Token 统计保留；页面建议 180 |

注意“复用近期分析”默认开启，升级后同一触发器反复告警时不会每次都分析。

另外：
- “监控工具加载方式”设置已删除。
- 兼容诊断流程已退役：某个场景没有任何启用的 Skill 时，任务会直接失败并提示启用（NoSkillEnabled）。platform-base 默认全部启用，所以一般不会遇到。
- 清理过期明细后，SQLite 文件不会立刻变小，空出的空间由后续写入复用。

### 5. 验收

找一条已在 SSH MCP 登记映射的 Linux 主机 CPU 告警，在飞书卡片上点击“AI分析”（或等它自动分析），然后在“诊断详情”检查：

- 首轮之前已完成 SSH 目标解析和预采集，逐轮交互里不再出现工具发现、目标解析的轮次（预采集只用于告警；问答和 Web 诊断仍按问题选择数据源）；
- 证据列表每条前有 E1、E2… 编号；报告末尾有“诊断范围（平台生成）”和“证据核对”两节，后者写明依据可信度；
- 处理建议是编号列表；模型网关支持提示词缓存时，飞书 Token 尾注会显示“其中缓存命中”；
- 服务状态页 5 个队列正常，“手动告警分析”和“自动告警分析”各有 2 个 Worker。

### 回滚

回滚目标是 v0.9.9（提交 `3fcdd13`）。只切回旧代码不行：v1.0 新建的任务按新格式保存 Skill 快照，旧版本重试这些任务会失败；旧版本也不认识 platform-base，会把它和原 Skill 一起加载。

按下方“回滚”一节恢复升级前的数据卷备份和主密钥，再执行 `git switch --detach 3fcdd13` 并重新 `docker compose ... up -d --build --remove-orphans`。升级后新产生的告警分析、问答和配置修改会随备份恢复而丢失，回滚前可先下载需要保留的详细报告。SSH MCP v0.5.0 不需要回滚，旧平台照常可用。


## v0.9.8 → v0.9.9：告警通知与 AI 分析拆分队列

本次没有数据库迁移，无需更新 Skill、独立 SSH MCP 或 Zabbix MCP，飞书卡片签名也不变。变化如下：

- `alert-worker` 只负责发送告警和恢复卡片。
- 新服务 `alert-analysis-worker` 执行告警 AI 分析：先处理手动点击的“AI分析”，再处理自动分析。默认 2 个副本，即最多同时进行 2 次告警分析。

升级前先备份数据库与配套主密钥（命令见下方“已部署 ai-ops-platform”一节）。然后在原部署目录执行：

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
docker compose ps alert-worker alert-analysis-worker
```

healthz 应返回 version 0.9.9；`docker compose ps` 应看到 1 个 `alert-worker` 和 2 个 `alert-analysis-worker`。未启用飞书接收器时去掉 `--profile feishu`；不要执行 `down -v`。

在 Web 中打开“系统配置 → 服务与维护 → 查看服务与队列状态”，应看到 5 个队列；“手动告警分析”和“自动告警分析”各显示 2 个已注册 Worker。

**调整并发数**：每次分析都会同时调用模型和两个 MCP。如果模型网关或 SSH MCP 有并发或频率限制，在部署目录的 `.env` 中设置 `AI_ALERT_ANALYSIS_WORKERS=1`（或其他正整数），然后重新执行上面的 `docker compose ... up -d`。设为 1 时分析会依次进行，但告警通知仍然不会等待分析。

**升级前已在队列中的任务**：照常执行。旧格式的手动分析任务仍在 `ai-alerts` 队列里，由 `alert-worker` 按旧方式执行。

**回滚**：本次没有数据库变更。回滚前先在服务状态页确认“手动告警分析”和“自动告警分析”的排队数都为 0，然后在部署目录执行 `git switch --detach 627a54a`，再执行同一条 `docker compose ... up -d --build --remove-orphans`（会移除 `alert-analysis-worker`）。如果回滚时这两个队列里还有任务，它们不会再被执行，对应事件会一直停在“排队中”，旧版本也无法再次分析这些事件。


## v0.9.7 → v0.9.8：Skill 工具结果完整送达模型、预算如实记录

本次无数据库迁移，不改变飞书卡片签名，无需更新 Skill、独立 SSH MCP 或 Zabbix MCP，也不用重新导入 Skill。升级前先备份数据库与配套主密钥（命令见下方“已部署 ai-ops-platform”一节），然后在原部署目录更新 main 并重建全部容器：

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
```

healthz 应返回 version 0.9.8。未启用飞书接收器时去掉 `--profile feishu`；不要执行 `down -v`。新逻辑只对升级后创建的任务生效：发起一次 Linux 主机 CPU 诊断，然后在“诊断详情 → 下载详细报告”中检查：

- 预算部分出现 `limits_hit`，写明触发强制总结的上限，以及 Token 是否超出预算；
- 逐轮交互中，同一工具的参数结构不再重复查询，历史查询结果中不再出现 `...[truncated]...`；
- 告警任务首轮输入只有一份告警，并且不含 `{EVENT.RECOVERY.*}` 等未展开的宏。

`budget_exhausted` 现在只要触达任一预算上限就为真。这只是预算说明，不计入诊断不足，也不改变任务状态。

回滚：本次无数据库变更，在部署目录切回 v0.9.7 的提交（`git switch --detach 4905e21`）后重新执行上面的 `docker compose ... up -d --build` 即可。新任务报告里多出的 `limits_hit` 字段，旧版本会直接忽略。


## v0.9.6 → v0.9.7：下载详细报告

本次不改变数据库结构，无需更新 SSH MCP 或 Skill。升级前备份数据库和主密钥，拉取 main 并重建 Web/诊断 Worker。进入“AI 诊断 → 诊断详情”：原“下载报告”仍生成简版 Markdown；有 reports.read + logs.read 权限的超级管理员或运维管理员额外看到“下载详细报告”，导出全部已保存 MCP 原始证据、任务与 Skill 快照、时间线，以及模型交互预览。该下载在服务端重新验权、脱敏并审计，浏览器不需要打开“读取日志证据”。模型交互本就限长，旧任务未保存的内容不可恢复；内部资料请按敏感运维资料保管。


## v0.9.5 → v0.9.6：显示与 AI 模型的交互记录

本版本自动执行一次新增 `model_interactions` 数据表的迁移。升级前备份当前数据库及配套主密钥，重建 Web、告警 Worker、QA Worker、诊断 Worker；不需要更新独立 SSH MCP 或 Skill。打开 Web → AI 诊断 → 诊断详情，查看“与大模型交互记录”。具有 logs.read 权限的管理员可展开每轮输入、输出、工具调用与脱敏错误；只有 reports.read 权限的角色只能看到模型、用量和耗时。交互记录加密，按轮次保存限长预览，不代表完整原始请求，更不会提供模型内部隐藏推理内容；升级前旧任务没有日志，需创建新任务。不要通过 `down -v` 清空数据库。


## v0.9.4 → v0.9.5：报告可读性和 Java 应用名

升级平台不会自动升级独立 SSH MCP 或数据库中的现有 Skill。v0.9.5 去掉报告正文的“需人工核验：是”，飞书底部统一展示 Token、实际分析模式、执行耗时。百分比统一显示 2 位小数，KiB 数据仅在报告展示时换算为 MiB/GiB。原始采集证据不改变。

如果希望 Java RSS TOP 列表自动出现 JAR/服务名称，还需要将 `ssh-mcp-server` 独立服务升级到 v0.4.2，随后在平台“连接管理”验证 SSH MCP 连接。该增强只读取固定 `/proc` 文件并仅返回经过校验的身份摘要，不能保证所有 Java 进程均可识别应用名称。

已安装 `ops-mcp-readonly` 不会被模板自动覆盖：先导出已有 Skill，然后从“Skill 管理”下载新版模板，将自定义 IP 匹配、Linux/网络设备规则合并，再选择更新同名 Skill。新任务才采用新版本快照。飞书卡片不涉及签名变更；不需要清空数据库或重新配置凭据。


## v0.9.3 → v0.9.4：分析模式与工具调用效率

本次无数据库迁移。飞书 Token 行增加实际分析档位；Skill 模式支持一次读取多个工具的 Schema，并向模型提供带显式“仅为样本”标记的历史数值摘要，原始完整 MCP 证据仍保留在加密报告中。升级前备份数据库与主密钥，按原有 Docker Compose 步骤从 main 更新并重建容器。内置模板已更新；旧版自定义 Skill 不会自动更新，请先导出原包备份，然后在“Skill 管理”下载新版模板，合并自定义查询规则后导入“更新同名 Skill”并勾选所需场景。不要为了降 Token 直接删除原本必要的查询字段；实际结果以诊断证据为准。


## v0.9.2 → v0.9.3：Skill 统一诊断策略

升级前备份数据库、配套主密钥和已导入的 Skill ZIP。新版本取消 Web 中的两项提示词输入及恢复按钮，旧的数据库配置值保留供回滚，但不再用于新任务。飞书 JSON 卡片字段、安全和授权规则仍由平台校验。未启用对应场景 Skill 时，会显示提示并使用内置只读兼容流程。

在原部署目录运行 `git fetch origin`、`git switch main`、`git pull --ff-only origin main`，再执行 `docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180`。使用 `curl -fsS http://127.0.0.1:8088/healthz` 检查版本应为 0.9.3。未启用飞书接收器时去掉 `--profile feishu`；不要执行 `down -v`。

升级后在 Skill 管理先导出旧 Skill 备份，然后下载新版运维模板 ZIP。若原 Skill 有自定义规则，手动合并后再上传，选择“更新同名 Skill”，勾选所需的告警分析、飞书问答和 Web 诊断场景并启用、验证工具。旧 Skill 不会自动被模板覆盖；既有任务仍使用创建时的 Skill 快照。浏览器 Ctrl+F5 强制刷新，在系统配置 → AI 配置确认已无两项提示词，发起新任务进行验证。


## v0.9.1 → v0.9.2

升级前备份数据库与配套主密钥；本版本无数据库迁移，不修改飞书卡片签名校验。新增 AI 单次请求超时（默认 90 秒），最大允许 180 秒；重试复用已取得的 MCP 证据。修正 problem.get 的排序参数；模型失败后优先输出证据型部分报告。安全起见，未删除旧兼容任务需要的执行入口。

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
```

请先确认原始旧平台的飞书接收器已停用；如本部署没有启用飞书接收器，去掉 `--profile feishu`。登录 Web 的系统配置 → AI 配置，检查单次请求超时和现有任务预算，修改仅适用于新任务。重新运行此前超时失败的分析，核对模型异常降级、Zabbix 工具参数和飞书报告。保留旧数据卷与 `master.key`，不得使用 `down -v`。


## v0.9.0 → v0.9.1

本次只升级平台，无数据库迁移；保留已导入 Skill、配置、历史与密钥。SSH MCP 已是 v0.4.1 时无需再升级，initMAX 和原 Skill ZIP 均无需修改。先按下方备份流程保存数据与配对密钥，再在原部署目录执行：

```bash
cd /data/ai-ops-platform
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
```

没有启用飞书接收器时去掉 `--profile feishu`。Ctrl+F5 刷新，确认版本为 v0.9.1；曾因工具参数、截断或超时失败的任务需要重新发起。原模板需在目标场景保持启用；验收问题见 [需求复核记录](REQUIREMENTS-AUDIT.md)。

## v0.8.2 → v0.9.0

新增 Skill 驱动的双 MCP 查询。数据库自动升级至 v5，只增加 Skill 表；保留原有设置、告警、主密钥、历史与报告。升级前按下方备份流程保存完整数据卷与配对密钥。

先在独立 SSH MCP 的原项目目录升级，保留原部署参数：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

再升级 AI 平台：

```bash
cd /data/ai-ops-platform
git fetch origin
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180
curl -fsS http://127.0.0.1:8088/healthz
```

浏览器 Ctrl+F5 刷新，应显示平台 v0.9.0、SSH 服务 v0.4.1。initMAX 服务不需要为此功能修改。未启用飞书接收器时去掉 --profile feishu；部署目录不同则使用原目录。

在“Skill 管理”下载模板 ZIP，验证并导入，选择场景与 MCP 服务后启用，再点击“验证工具”。实时问题将按模板直接查询已登记 SSH 资产；历史告警查询 Zabbix。不启用 Skill 的场景保留旧流程。已有自定义提示词保留，Skill 执行模式优先采用 Skill 的查询指引，并保持入口的输出格式。复杂查询可在 AI 配置提高对应模式预算。详见 [Skill 使用说明](SKILLS.md)。

## v0.8.1 → v0.8.2

修复 initMAX 不接受 `host_get filter.ip` 导致 IP 问答定位失败，改为先查接口再按 Host ID 查询主机。取消六项预算的固定最大值，联动修复长任务的 RQ 超时和失联清理。飞书完整展示报告，超出约 30 KB 的消息容量自动分段，不裁剪正文；分段均可继续追问。无数据库迁移。

先备份，再在原目录拉取 main，并执行 `docker compose --profile feishu up -d --build --remove-orphans --wait --wait-timeout 180`，浏览器 Ctrl+F5 刷新。预算页可直接保存 16 轮、每轮 16 次、16000 字符等设置；已有预算继续生效，修改用于新任务或重试。之前主机定位失败的任务需要重新运行。

已有提示词保留。需要取消提示词中的旧限字要求时，在系统配置 → AI 配置编辑，或恢复新版默认提示词并保存。

## v0.8.0 → v0.8.1

修复飞书摘要无提示截断、日志隐藏掩盖失败原因、采集预算耗尽伪装 SSH 失败、问答查到主机却未继续诊断的问题。接入有界目录占用扫描，统一“正在查询后台MCP服务并进行分析……”提示，无数据库迁移。

先按下方流程备份，再在原目录运行：

```bash
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans
docker compose ps
```

未运行飞书接收器时去掉 `--profile feishu`。浏览器 Ctrl+F5 刷新。进入“系统配置 → AI 配置 → 分析预算”，检查当前模式；标准模式新默认值为 12 次采集，已有自定义 8 次仍保留，需要手动修改后保存。报告显示本次保存的上限，历史记录不会重新运行；重试创建新任务并采用新预算。

目录查询要求 SSH MCP 提供 `ssh_diagnose_directory_usage`，且平台专用令牌允许 `directory` 动作和目标主机组。使用连接管理的“检测 MCP 工具”确认工具存在。已有自定义提示词保留；需要新版问答引导时在 AI 配置恢复默认并保存。

## v0.7.2 → v0.8.0

告警筛选、配置页签、草稿保护、诊断报告与服务状态整体优化。保留现有双 MCP、飞书、AI、成员、屏蔽、历史与密钥；数据库仍为 v4，无新增迁移。按下方备份流程保存当前数据后，在原项目目录执行：

```bash
cd /data/ai-ops-platform
git switch main
git pull --ff-only origin main
docker compose --profile feishu up -d --build --remove-orphans
docker compose ps
curl -f http://127.0.0.1:8088/healthz
```

未启用飞书接收器的环境去掉 `--profile feishu`。浏览器按 Ctrl+F5 强制刷新，确认侧栏版本为 v0.8.0。系统配置切换页签保留当前草稿，各区仍需分别保存；暂时屏蔽位于“告警中心”。在“系统配置 → 服务与维护”检查队列和 Worker，在“连接管理”分别验证两个 MCP。

已有自定义提示词不会被覆盖；需要采用新版项目提示词时，在“系统配置 → AI 配置”点击“恢复默认提示词”，验证并保存。标准/深度模式对可信绑定的 Linux 主机自动采集首轮 SSH 证据，快速模式只查监控；SSH 关联、权限与预算限制继续生效。

## v0.7.1 → v0.7.2

系统设置、飞书管理与 AI 配置合为“系统配置”，诊断工具并入“连接管理”。已有设置、密钥、提示词和权限继续生效，无数据库迁移。更新代码后运行 `docker compose --profile feishu up -d --build --remove-orphans`，强制刷新浏览器即可；旧页面书签自动转到对应分区。

## v0.7.0 → v0.7.1

移除平台“主机资产”菜单、登记/编辑/同步/导入/分组接口，诊断直接从 Zabbix MCP 查询主机并关联 SSH MCP。已有告警和历史报告保留，旧资产记录仅供历史报告读取，不再参与目标选择。无新增数据库版本迁移。更新代码后运行 `docker compose --profile feishu up -d --build --remove-orphans`，刷新浏览器即可。

## 更早整合版 → 双 MCP

v0.7.0 启动时执行数据库 v4 迁移：保留告警、问答、成员、监控资产、分组、任务、报告、证据和审计；删除旧 SSH 凭据/跳板/公钥扫描表、资产 SSH 字段和旧 SSH 并发/超时设置。历史 SSH 证据仍可查看，未完成的旧本地 SSH 任务标记失败，不能重试为本地执行。

主机、SSH 私钥、公钥、跳板和动作权限应先在独立 SSH MCP 登记，填写同一 Zabbix Host ID 并签发平台专用令牌。本平台不再导入 Linux 旧项目私钥或执行器。不要把平台数据卷挂载到独立 SSH MCP。

## 已部署 ai-ops-platform

在原项目目录执行，保留原 Compose 项目名、数据卷和加密密钥。先停止本项目各服务，备份整个数据卷与当前部署参数，然后更新代码：

```bash
cd /data/ai-ops-platform
docker compose --profile feishu stop
mkdir -p backup-before-upgrade
docker compose run --rm --no-deps -v "$PWD/backup-before-upgrade:/backup" --user 0 web sh -c 'cp -a /app/data/. /backup/'
git rev-parse HEAD > backup-before-upgrade/source-revision.txt
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --remove-orphans
docker compose exec -T web python -m app.bootstrap
docker compose ps
curl -f http://127.0.0.1:8088/healthz
```

备份目录包含敏感加密数据库与密钥，限制权限并移至受控备份系统；若以前使用 `.env` 中的 `APP_ENCRYPTION_KEY`，同时保留原部署参数。备份不要放入 Git。`--remove-orphans` 清理已移除的 host-key-worker 容器，不删除数据卷。升级过程不会更改独立 SSH MCP 或 Zabbix MCP。

登录 Web，进入连接管理，保留原 Zabbix MCP，配置并验证 SSH MCP；复查系统配置中的 AI 模型、预算、默认提示词和飞书参数。旧自定义提示词保留；需要新默认词时在系统配置 → AI 配置点击“恢复默认提示词”后保存。

验证通过后启动飞书：

```bash
docker compose --profile feishu up -d feishu-receiver
```

曾在整合分支部署且工作区有本地修改时，先保留修改；`git pull --ff-only` 失败不要直接 reset。需保留原数据卷名称；若旧部署使用自定义项目名，继续使用相同项目名。

## 回滚

停止所有本项目容器，保存当前故障数据，再整体恢复升级前数据卷备份和原加密密钥，切回备份记录的旧代码版本并构建启动。v4 已删除 SSH 配置，不能只回退代码而继续使用新数据库。恢复前确认没有应用进程正在写 SQLite，配对恢复数据库、WAL/SHM 和密钥。禁止 `down -v`。

## 从原 zabbix-ai-ops 导入

仅为旧版 Zabbix 平台提供离线 `python -m app.migrate import-zabbix`。源数据库只读打开，重加密 settings 并撤销旧会话；目标必须是新文件。先停止源/目标写入并保存原主密钥及一致性快照，在独立空卷验证后再切换。已是统一平台的数据库不得使用此工具重新加密，应整体备份恢复。命令参数见 `python -m app.migrate import-zabbix --help`。
