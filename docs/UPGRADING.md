# 版本更新与备份

**当前开发版尚无一键更新/自动回滚功能**。建议在测试环境更新，不要直接覆盖现有生产系统。

## 开发环境备份

```bash
cd zabbix-ai-ops
docker compose ps
docker compose stop web alert-worker qa-worker feishu-receiver
# 为避免 SQLite WAL 文件不一致，停止所有访问数据库的服务后再备份
docker run --rm -v zabbix-ai-ops_appdata:/src:ro -v "$PWD":/backup alpine:3 \
    tar -czf /backup/appdata-backup.tgz -C /src .
docker compose start web alert-worker qa-worker feishu-receiver
```

Compose 卷名可能因项目目录不同而变化。先用 `docker volume ls` 检查，切勿假设示例卷名就是当前值。

## 升级规划

1. 查看 GitHub Release 及兼容性变更。
2. 导出数据库与配置（保留 `APP_ENCRYPTION_KEY`，丢失后加密密钥无法解密）。
3. 拉取指定发布标签而不是不确定的分支 HEAD。
4. 预检 API/数据库迁移、依赖和队列兼容性。
5. 维护窗口内滚动更新，恢复后检查 `/healthz`、MCP 和飞书消息。
6. 异常时恢复旧代码及匹配的数据库快照。

正式的发布制品校验和自动回滚脚本将在达到稳定版前实现。
