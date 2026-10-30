---
name: platform-service
description: 通用服务诊断（systemd 服务停止、启动失败、反复重启、端口不监听、进程数异常）：服务发现、状态与退出原因、启动命令、进程与端口映射、单元配置、相关日志与重启记录。告警类型为 service、logs 或 system 时加载。
types: [service, logs, system]
prefetch:
- scopes: [alert, web, qa]
  types: [service]
  ssh: [ssh_diagnose_service_detail, ssh_diagnose_failed_services, ssh_diagnose_service_map]
  zabbix_items: [proc.num, net.tcp.service, net.tcp.port, systemd.unit, service.info]
  history: ["proc.num*", "net.tcp.service*", "net.tcp.port*", "systemd.unit*", "service.info*"]
  schemas: [history_get, event_get]
---

# 通用服务诊断

## 确定服务

- 服务名来源依次为：Web 诊断表单的 service、告警触发器监控项（`systemd.unit.info["xxx.service",...]`）、告警标题。平台能推导出单元名时已预采集 `ssh_diagnose_service_detail`；推导不出时先用 `ssh_diagnose_failed_services`、`ssh_diagnose_service_map`（端口 → 进程 → 单元）和 `ssh_diagnose_service_inventory` 找到单元，再调用 `ssh_diagnose_service_detail`。
- `unit_not_found` 表示 systemd 中没有这个单元名，不等于服务已停止：核对名称（nginx / openresty、tomcat / app@1），或改用进程与端口证据。nohup、supervisor、容器方式运行的服务没有单元，用 service_map、`ssh_diagnose_containers` 与进程排行判断。

## 判断方法

- **状态与退出原因**：ActiveState / SubState / Result / ExecMainStatus：`exit-code` 看退出码与启动日志，`signal` 看被谁杀死（OOM、手动 kill），`timeout` 说明启动或停止超时，`start-limit-hit` 说明短时间内多次失败已被 systemd 停止重试（需要人工 reset-failed 后再启动）。
- **重启记录**：service_detail 的 history（近 24 小时 Started / Stopped / Failed / Scheduled restart）与 NRestarts 判断是否反复重启、首次失败时间是否与告警吻合；最近启动时间落在告警窗口内说明告警与重启相关。
- **启动命令与配置**：ExecStart、User、WorkingDirectory、LimitNOFILE、MemoryMax、Restart 策略来自单元文件；Environment 中的敏感值已脱敏。配置不合理（例如 Restart=always 掩盖持续崩溃、LimitNOFILE 过小）要给出依据。
- **端口与进程**：服务运行但端口未监听，或端口被其它进程占用（service_map 的 listeners），是常见的“服务正常但访问失败”原因。
- **日志**：service_detail 的 journal 只覆盖本单元；需要内核、OOM、依赖服务的记录时用 `ssh_diagnose_syslog`（unit、pid、keyword 过滤，since / until 取告警前后）。journal_access 为 limited 时诊断账号看不到系统日志，空结果不能视为没有错误。
- Zabbix 侧的 proc.num、net.tcp.service、service.info 历史给出故障开始与恢复的准确时间，与 SSH 当前状态分别说明。

## 报告要点

先写服务当前状态与直接原因（退出码、被 OOM 终止、依赖未就绪、配置错误等，注明证据），再写重启次数与时间线；只建议人工执行的操作（重启、reset-failed、修改配置）要写清楚前提与风险，平台不执行任何变更。
