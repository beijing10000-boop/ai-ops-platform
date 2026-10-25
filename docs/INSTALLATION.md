# 安装部署 v0.7.2

默认端口 8088，默认向宿主机网卡发布，供受信任内网访问；Redis 不发布端口。公网入口应由 HTTPS 反向代理和访问控制保护。HTTP 内网不需要配置证书。镜像内应用以 UID 10001 运行，配置与主密钥存放在本项目独立数据卷。

## 1. 启动平台

已有 Docker Engine 与 Compose 插件无需重装。未安装可参考 [Docker 官方安装文档](https://docs.docker.com/engine/install/centos/)，Rocky 请先确认所用版本兼容。

```bash
mkdir -p /data
cd /data
git clone https://github.com/beijing10000-boop/ai-ops-platform.git
cd ai-ops-platform
docker compose up -d --build
docker compose exec -T web python -m app.bootstrap
docker compose ps
curl -f http://127.0.0.1:8088/healthz
docker compose exec -T web cat /app/data/bootstrap.token
```

无需手写业务 `.env`。首次凭据只在服务器终端读取并填入初始化页，不要发送到聊天、工单或日志。端口占用时可使用 `WEB_PORT=8089 docker compose up -d --build` 选择宿主机发布端口；这是 Docker 启动参数，业务配置仍全部在 Web。

## 2. Web 初始化与飞书登录

1. 打开 `http://服务器IP:8088/setup`。
2. 填写一次性初始化凭据、协议 HTTP、实际外部访问主机（例如 `172.20.200.94:8088`）、飞书 App ID、App Secret 和超级管理员 Open ID。
3. 点击“验证初始化信息”，核对展示的回调地址，再保存。
4. 在飞书开放平台配置相同的 OAuth 回调地址，如 `http://172.20.200.94:8088/api/v1/auth/callback`。使用飞书登录平台。

初始化完成后入口关闭；飞书登录、角色权限和 CSRF 保护诊断/配置接口。选择 HTTPS 仅表示外部入口采用 HTTPS，不会自动签发证书或改变 Docker 端口。

## 3. Web 配置两个 MCP

| 入口 | 填写内容 | 验证 |
| --- | --- | --- |
| 连接管理 → Zabbix MCP | 现有服务的 Streamable HTTP 地址和令牌 | 验证填写内容 → 验证连接 → 保存连接 |
| 连接管理 → SSH MCP | 开启、`http://SSH服务IP:9099/mcp`、专用客户端令牌、超时（默认90秒） | 验证填写内容 → 验证连接 → 保存连接 |
| 连接管理 → 诊断工具 | 查看工具注册表与标准诊断流程 | 检测 MCP 工具（使用已保存连接） |
| 系统配置 → 基础设置 | 外部访问地址、Webhook 密钥、Zabbix 前端、只读工具勾选 | 验证填写内容，再保存基础配置 |
| 系统配置 → 飞书配置 | 群 ID、发送开关、自动分析级别与授权成员 | 验证填写内容、验证飞书应用和群访问，再保存飞书配置 |
| 系统配置 → AI 配置 | Base URL、部署名、API Key；默认提示词、分析模式和数字预算 | 验证填写内容、验证模型连接，再保存 AI 配置 |

地址应从应用容器可达。同一宿主机的 MCP 不要填 `127.0.0.1`，应填服务器内网 IP 或可解析服务地址；两个 MCP 的令牌相互独立。SSH MCP 至少为 v0.2.0 并包含 `ssh_resolve_host`；主机、公钥、私钥和跳板在其 Web 完成。

验证连接使用当前表单，不要求先保存；配置修改后请重新检测。检测成功代表握手及工具目录有效，实际主机权限、SSH 可达性和飞书完整业务仍需诊断或真实事件核验。

## 4. 主机与业务联调

在 SSH MCP 中为目标主机填写正确 Zabbix Host ID，绑定凭据并核验主机公钥；给平台签发有相应主机组和动作权限的令牌。平台不登记或同步保存主机资产。AI 诊断页点击“查询 Zabbix 主机”，按名称或 Host ID 搜索后选择；告警分析使用事件中的 Host ID。Linux 类型通过 Zabbix inventory OS 或 aiops.device_type 标签确认，无法确认时只进行监控分析。

AI 诊断页点击“验证诊断参数与关联”核验监控主机及 SSH MCP 映射，不执行 SSH 或模型；再执行诊断并查看证据来源 `zabbix_mcp` / `ssh_mcp`。

在 Zabbix 对接 `http://平台IP:8088/zabbix` 和系统配置 → 基础设置中的 Webhook Bearer 密钥，参考 [Zabbix 说明](ZABBIX.md)。停止同一 App ID 的旧接收器后启动新的飞书长连接：

```bash
docker compose --profile feishu up -d feishu-receiver
docker compose logs --tail=80 feishu-receiver web alert-worker qa-worker diagnostic-worker
```

更换飞书 App ID/Secret 后，执行 `docker compose --profile feishu restart feishu-receiver` 让长连接重新认证；其余业务配置由各任务实时读取。

## 5. 备份

升级与备份见 [UPGRADING.md](UPGRADING.md)。数据库和配对主密钥必须一同保留，不能删除数据卷或执行 `docker compose down -v`。旧实例若使用 `APP_ENCRYPTION_KEY`，必须保留其原值；新实例自动生成持久化 `master.key`。
