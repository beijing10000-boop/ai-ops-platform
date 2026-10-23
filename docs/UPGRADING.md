# 离线迁移、升级与回滚

迁移在**新平台的独立数据卷**完成，不把新应用指向原生产库。两个旧源库只读打开；不改原 schema、不就地替换主密钥。以下命令由操作者在测试机器执行，本次未访问真实旧库。

## 准备

1. 固定目标代码 SHA、保存 Compose 与部署参数。两套旧实例分别制作 SQLite 一致性备份，保留各自原 Fernet 主密钥及原代码。不要仅在运行中复制 `.sqlite3` 而遗漏 WAL。
2. 在受控测试目录 `migration-input/` 放入 `zabbix.sqlite3`、`zabbix.key`、`linux.sqlite3`、`linux.key`。这里均为备份副本；密钥文件只包含对应 Fernet 值，chmod 600，目录 chmod 700。不要上传 GitHub、发送到聊天或在终端日志打印密钥。
3. 新仓库先 `docker compose build`，停止所有新应用服务和新接收器，确认没有 worker/stdin MCP 使用目标数据库。不要停止原生产服务，除非已进入批准的切换窗口。不要执行 `down -v`。
4. 以下流程用于空白目标卷，`.env` 的 APP_ENCRYPTION_KEY 留空，采用新 `/app/data/master.key`。若目标已有任何真实新平台数据，应先单独完整备份并另建空白测试卷；不要删除它来绕过“目标已存在”的保护。

## 导入原 Zabbix 主平台

在空白目标卷只创建主密钥，暂不创建数据库：

```bash
docker compose run --rm --no-deps --user 0 web python -c 'from app.bootstrap import persistent_secret; from cryptography.fernet import Fernet; persistent_secret("/app/data/master.key", Fernet.generate_key)'
docker compose run --rm --no-deps --user 0 -v "$PWD/migration-input:/migration-input:ro" web python -m app.migrate import-zabbix --source /migration-input/zabbix.sqlite3 --source-key-file /migration-input/zabbix.key --destination /app/data/app.sqlite3 --target-key-file /app/data/master.key
```

该步骤一致性复制旧库、解密并用新密钥重加密 settings，保留告警和历史，撤销旧 OAuth 会话。目标已存在或源已是统一平台时拒绝操作。失败不会发布半个目标库，源库不变。迁移文件不能自动恢复已丢失的原密钥。

## 导入 Linux 旧项目

```bash
docker compose run --rm --no-deps --user 0 -v "$PWD/migration-input:/migration-input:ro" web python -m app.migrate import-linux --source /migration-input/linux.sqlite3 --source-key-file /migration-input/linux.key --offline-ack
```

CLI 自动在目标旁生成 pre-linux-import 备份。先对源只读快照完整解密，再在事务内导入组、跳板、共享 SSH 凭据、主机、历史和审计，统一用目标主密钥加密。相同源快照指纹重复执行返回 already_imported，不重复写入。任一步失败回滚目标事务。

所有迁入主机默认**禁用、模式 B 未批准**；不猜测 Host ID、不因旧 IP 相同自动关联。管理员需逐台核验 Host ID、设备类型、私网地址、主机公钥、账号、凭据和模式后再启用。已有目标设置优先，旧管理员不会覆盖现有超级管理员名单；应在新 Web 人工复核并授权需要的旧管理员。

处理目标卷的运行权限并初始化增量 schema：

```bash
docker compose run --rm --no-deps --user 0 web sh -c 'chown -R 10001:10001 /app/data && chmod 700 /app/data'
docker compose run --rm --no-deps web python -m app.bootstrap
docker compose up -d
```

这里只调整本新 Compose 项目的 appdata 卷；不要将命令套到原生产目录。SELinux 下若挂载被拒绝，对**备份副本目录**按本机策略设置标签，不关闭整个 SELinux。

## 迁移后核验

核对旧告警数、Token 历史、组/主机/历史数量、导入指纹、凭据能否解密及权限状态。旧会话重新登录。新平台的本地 SSH 默认模式不等于旧 Linux root 网关模式；未经复核不能启用。先完成 docs/ACCEPTANCE.md 的测试矩阵，再安排接收器、Webhook 与用户入口切换；不会自动迁移两个 Redis 的进行中任务或去重状态。

## 后续统一平台升级

停止新平台接收器和 worker、排空队列，备份数据库和同版本主密钥、记录当前 SHA，更新至已验收 SHA 后重新构建。启动时执行 additive schema 迁移。不可用旧版 legacy import-zabbix 对统一平台库重新加密；统一平台恢复必须使用对应原密钥与兼容代码。

## 回滚

- 迁移失败：源实例无需恢复，因为未写入源。保留失败日志类型和原备份，修正原因后在空目标重试或恢复目标 pre-import 快照。
- 验收失败：先停止新接收器与新 Webhook 路由，再恢复旧入口和旧接收器。不得让两个独立接收器同时处理相同 App ID。旧 Redis 的队列继续由旧版本处理。
- 目标库恢复：停止**所有新平台**进程，保存故障库与 WAL/SHM 供排查，用一致性备份恢复 `/app/data/app.sqlite3`；仅在进程全部停止且故障文件已保存后移除对应旧 WAL/SHM。配对恢复该快照的 master.key/旧环境密钥并设置 UID 10001、0600，再使用对应代码版本启动。不要把新 schema 库直接交给旧二进制猜测兼容性。

仓库不包含生产自动迁移或自动切换脚本。
