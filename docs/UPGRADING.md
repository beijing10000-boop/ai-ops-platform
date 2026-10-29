# 升级说明

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
