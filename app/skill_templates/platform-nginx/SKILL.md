---
name: platform-nginx
description: Nginx / Web 告警诊断（502、504、499、5xx 错误率、上游超时、Nginx 进程或端口异常）：按告警时间窗口分析访问日志与错误日志，定位上游服务并交叉验证。告警类型为 nginx 时加载。
types: [nginx]
prefetch:
- scopes: [alert, web, qa]
  types: [nginx]
  ssh: [ssh_diagnose_nginx, ssh_diagnose_nginx_access, ssh_diagnose_service_map]
  zabbix_items: [nginx, web.page, net.tcp.service, proc.num]
  history: ["nginx.*", "web.page.*", "net.tcp.service*", "proc.num*"]
  schemas: [history_get, trend_get]
---

# Nginx / Web 告警诊断

预采集已在 Linux 主机上执行 `ssh_diagnose_nginx`（版本、配置摘要、upstream、进程、监听端口、窗口内 error.log 统计）、`ssh_diagnose_nginx_access`（告警时间前后 15 分钟的访问日志聚合）与 `ssh_diagnose_service_map`（端口与进程、单元的对应关系）。Windows 或未接入 SSH 的主机只能用 Zabbix 的 Nginx / Web 监控项。

## 判断顺序

1. **Nginx 自身**：配置测试是否通过（config.test）、master / worker 是否存在、systemd 重启次数、`worker_connections are not enough` 或 `Too many open files`（并发或文件句柄耗尽）。
2. **错误类型**（访问日志 codes 与 error.log 的 upstream_errors 一起看）：
   - **502**：上游拒绝连接、复位或提前关闭（`connect() failed`、`Connection refused`、`upstream prematurely closed`、`no live upstreams`）→ 上游进程不在、正在重启、端口未监听或连接数打满。
   - **504**：上游在 proxy_read_timeout 内没有响应（`upstream timed out`）→ 上游慢（应用线程池、数据库、外部依赖）。
   - **499**：客户端在响应前断开，通常也是上游慢的表现；结合 request_time 分布判断。
   - **5xx 由 Nginx 自身产生**（500 伴随 rewrite / 权限 / 磁盘错误）与上游返回的 5xx 要分开：upstream_response_time 为空（no_upstream）的 5xx 不是上游造成的。
3. **定位上游**：从 `errors.top_upstreams` 与 config.upstreams 得到上游地址；上游在本机时用 `ssh_diagnose_service_map` 找到监听该端口的进程与单元，再按 platform-service / platform-java 的方法查该服务（`ssh_diagnose_service_detail`、`ssh_diagnose_java`、`ssh_diagnose_syslog`）；上游在其它主机时写明地址，并建议对那台主机发起诊断，不猜测其状态。
4. **时间关联**：访问日志 timeline 中 5xx 何时开始、是否与上游服务重启（service_detail 的 history）、部署、流量突增（requests 曲线）同时发生；Zabbix 的 Web 场景或端口监控项历史用于确认持续时间。

## 报告要点

- 给出窗口内总请求数、5xx / 4xx / 499 的数量与占比、主要错误码、受影响最多的 URI 与客户端，以及上游错误分类计数（引用证据编号）。
- 访问日志只读取文件尾部有限字节、窗口被轮转切断时（window_not_covered）要写明统计覆盖范围；不能把样本当全量。
- 不建议直接重启 Nginx：先给出上游修复方向；需要调整 proxy_*_timeout、worker_connections、keepalive 时说明依据与风险。
