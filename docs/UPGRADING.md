# 升级说明

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
mkdir -p backup-v070
docker compose run --rm --no-deps -v "$PWD/backup-v070:/backup" --user 0 web sh -c 'cp -a /app/data/. /backup/'
git rev-parse HEAD > backup-v070/source-revision.txt
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --remove-orphans
docker compose exec -T web python -m app.bootstrap
docker compose ps
curl -f http://127.0.0.1:8088/healthz
```

备份目录包含敏感加密数据库与密钥，限制权限并移至受控备份系统；若以前使用 `.env` 中的 `APP_ENCRYPTION_KEY`，同时保留原部署参数。备份不要放入 Git。`--remove-orphans` 清理已移除的 host-key-worker 容器，不删除数据卷。升级过程不会更改独立 SSH MCP 或 Zabbix MCP。

登录 Web，进入连接管理，保留原 Zabbix MCP，配置并验证 SSH MCP；复查 AI 模型、预算、默认提示词和飞书参数。旧自定义提示词保留；需要新默认词时在 AI 配置点击“恢复默认提示词”后保存。

验证通过后启动飞书：

```bash
docker compose --profile feishu up -d feishu-receiver
```

曾在整合分支部署且工作区有本地修改时，先保留修改；`git pull --ff-only` 失败不要直接 reset。需保留原数据卷名称；若旧部署使用自定义项目名，继续使用相同项目名。

## 回滚

停止所有本项目容器，保存当前故障数据，再整体恢复升级前数据卷备份和原加密密钥，切回备份记录的旧代码版本并构建启动。v4 已删除 SSH 配置，不能只回退代码而继续使用新数据库。恢复前确认没有应用进程正在写 SQLite，配对恢复数据库、WAL/SHM 和密钥。禁止 `down -v`。

## 从原 zabbix-ai-ops 导入

仅为旧版 Zabbix 平台提供离线 `python -m app.migrate import-zabbix`。源数据库只读打开，重加密 settings 并撤销旧会话；目标必须是新文件。先停止源/目标写入并保存原主密钥及一致性快照，在独立空卷验证后再切换。已是统一平台的数据库不得使用此工具重新加密，应整体备份恢复。命令参数见 `python -m app.migrate import-zabbix --help`。
