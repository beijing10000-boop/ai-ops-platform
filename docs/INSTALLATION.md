# 安装与运行

此文针对新仓库的独立测试部署。当前执行环境无法运行 Docker；Rocky Linux 9/10 与真实业务联调尚未验收。不要将新服务直接挂载旧生产数据卷。

## Docker 准备

使用组织批准的软件源和版本。Docker 官方 CentOS 文档提供下列仓库与插件安装方式，Rocky 的兼容性需在实际目标版本验证：

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
docker compose version
```

已有 Docker 的服务器无需重复安装。不要在现有业务机盲目替换容器运行时。

## 独立启动

```bash
git clone --branch integration/unified-platform https://github.com/beijing10000-boop/ai-ops-platform.git
cd ai-ops-platform
docker compose up -d --build
docker compose exec web python -m app.bootstrap
docker compose ps
curl -f http://127.0.0.1:8088/healthz
```

私有仓库需使用你自己的 GitHub 授权，不把访问 Token 写入脚本。Compose 项目名 `ai-ops-platform`，数据卷 `appdata` 和 `redisdata` 独立于两个旧项目；同机测试用 `WEB_PORT=8089`。默认绑定 127.0.0.1，Redis 不发布宿主机端口。命名数据卷首次创建由镜像准备 UID 10001 写权限；如果改成 bind mount，需自行设置目录所有权与 SELinux 标签，不能直接复用旧路径。

## 访问和初始化

- 本机访问 `http://127.0.0.1:8088/setup`。远程先用 SSH 隧道访问初始化页面：`ssh -L 8088:127.0.0.1:8088 user@server`。
- 在服务器自己的终端运行 `docker compose exec web cat /app/data/bootstrap.token`，将结果输入初始化页。若显式设置 ADMIN_API_TOKEN，则使用该值。凭据只用于尚未完成的初始化。
- 填写外部主机名/端口、协议、飞书 App ID / Secret、超级管理员 Open ID。应用生成并持久保存 `master.key` 与 `bootstrap.token`，不在日志打印。
- 飞书网页授权重定向地址必须与 `协议://外部主机/api/v1/auth/callback` 一致。HTTPS 由可信反向代理提供；页面选择 https 不会自动签发证书。HTTP 仅适合受控测试。
- 初始化后通过飞书登录，在 Web 配置 AI、MCP、Webhook 密钥、群白名单及业务参数，然后逐项测试。

APP_ENCRYPTION_KEY 可用于保留旧实例密钥；新安装可留空。密钥一旦写入数据，不可随意更换。缺失已加密实例的主密钥会拒绝启动解密，不能靠新生成密钥修复。

## 启用飞书与切换

默认不启动接收器。复用相同 App ID 时，只有在停止旧接收器后才执行：

```bash
docker compose --profile feishu up -d feishu-receiver
docker compose logs --since=5m feishu-receiver qa-worker alert-worker
```

外部 Zabbix Webhook 地址与旧平台保持原样，直到专门验收通过后再由操作者切换。测试实例和生产实例的 Redis 去重状态互不共享。

## 运行与备份

```bash
docker compose logs --tail=100 web diagnostic-worker
docker compose exec web python -m app.migrate backup --source /app/data/app.sqlite3 --destination /app/data/manual-snapshot.bak
docker compose cp web:/app/data/manual-snapshot.bak ./manual-snapshot.bak
```

备份还必须包括对应 master.key（或既有 APP_ENCRYPTION_KEY）与部署参数，保存在访问受控的备份系统。备份数据库文件和密钥分别管理；数据库单独丢失密钥无法恢复。定期将历史证据归档；本版不自动清理诊断历史，需监控数据卷大小。Redis 满内存时会拒绝入队，应观察内存与磁盘。

Compose 对应用和 Redis 配置日志轮转、重启策略和健康检查；healthz 是存活检查，不证明远端业务可用。连接页需另做 MCP、AI 和 SSH 实际测试。

参考：[Docker 官方 CentOS 安装文档](https://docs.docker.com/engine/install/centos/)。
