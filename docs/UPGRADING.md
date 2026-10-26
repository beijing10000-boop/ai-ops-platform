# 升级说明

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
