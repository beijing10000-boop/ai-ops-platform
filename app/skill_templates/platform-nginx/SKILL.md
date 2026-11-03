---
name: platform-nginx
description: Nginx / Web 告警诊断（502、504、499、5xx 错误率、上游超时、Nginx 进程或端口异常）：先读日志平台的 Nginx 专项报告（规则化结论与基线对比），再用 SSH 实时状态与 Zabbix 指标交叉验证，定位上游服务。告警类型为 nginx 时加载。
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

预采集已在 Linux 主机上执行 `ssh_diagnose_nginx`（版本、配置摘要、upstream、进程、监听端口、窗口内 error.log 统计）、`ssh_diagnose_nginx_access`（告警时间前后 15 分钟的访问日志尾部聚合）与 `ssh_diagnose_service_map`（端口与进程、单元的对应关系）；日志已接入日志平台时还有 `log_nginx_report`（告警前后全量访问日志与 error.log 的专项报告，读法见 platform-logs）。Windows 或未接入 SSH 的主机只能用 Zabbix 的 Nginx / Web 监控项与日志平台。

## 判断顺序

1. **先看专项报告的结论**：`health` 与 `findings`（异常 / 需关注 / 提示）给出 5xx、502/504、499、429、耗时、后端、流量、采集中断等规则化判断与证据数值，`coverage.gaps` 说明哪些结论因字段缺失无法给出。“持续存在”（与基线相近）的错误是常态，不能当作本次告警的原因；只在告警时段出现或明显高于基线的才是。
2. **Nginx 自身**：配置测试是否通过（config.test）、master / worker 是否存在、systemd 重启次数、`worker_connections are not enough` 或 `Too many open files`（并发或文件句柄耗尽）；SSH 报 `nginx_master_untrusted` 时进程列表中的 master 不可信，不据此判断二进制与配置。
3. **5xx 由谁产生**（专项报告的 `s5xx_origins` 与 `codes[].origins`，SSH 的 error.log 分类佐证）：
   - **后端返回**：后端已给出响应头，状态码来自后端应用，问题在后端服务。
   - **502 / 未收到后端响应**：上游拒绝连接、复位或提前关闭（`connect() failed`、`Connection refused`、`upstream prematurely closed`、`no live upstreams`）→ 上游进程不在、正在重启、端口未监听或连接数打满。
   - **504 / 等后端超时**：上游在 proxy_read_timeout 内没有返回响应头（`upstream timed out`）→ 上游慢（线程池、数据库、外部依赖）；对照该后端的首字节耗时。
   - **Nginx 自身（未转发）**：限流（limit_req 默认 503）、return / rewrite、权限或磁盘错误；**无法区分**表示日志没有记录 `$upstream_addr` / `$upstream_header_time`，不要猜。
4. **4xx 与 499**：401 / 403 / 404 多为正常业务响应（未登录、无权限、资源不存在），已知噪声（如 JumpServer 登录过期页面轮询）已单独计数，只有明显高于基线时才分析。499 是客户端在响应前断开：断开前耗时长（P95 数秒以上）且已转发到后端，多为后端慢；耗时很短多为客户端取消；流式输出或长轮询接口的取消属正常。429 是限流。
5. **定位上游**：从报告的 `codes[].top.upstream`、`upstreams`（每次尝试计一次，`switched` 为失败后切到其他后端）与 SSH 的 config.upstreams 得到地址；上游在本机时用 `ssh_diagnose_service_map` 找到监听该端口的进程与单元，再按 platform-service / platform-java 查该服务；上游在其它主机时写明地址，并建议对那台主机发起诊断，不猜测其状态。
6. **时间关联**：报告的 `timeline` 与 `error_log.series`（5xx 与 error.log 错误行同一时间桶）给出何时开始；对照上游服务重启（service_detail 的 history）、部署、流量突增与 Zabbix 的 Web 场景或端口监控项历史。
7. **耗时**：`timing` 各阶段含义不同，不能相加；后端总耗时含各次重试；首字节耗时接近整个请求时瓶颈在后端处理，否则可能是大响应、慢客户端或流式输出。WebSocket（101）不计入耗时。

## 报告要点

- 给出窗口内总请求数、5xx / 4xx（不含已知噪声）/ 499 的数量与占比及基线、主要错误码、受影响的路由与后端，引用专项报告或 SSH 证据的数值与编号。
- 区分已确认事实（报告与 SSH、Zabbix 的数值）、高可信推断与待验证假设；专项报告的 `verify` 与 `coverage.gaps` 写进待验证事项或诊断不足。
- 访问日志只读取文件尾部有限字节、窗口被轮转切断时（window_not_covered）要写明 SSH 统计的覆盖范围；不能把样本当全量。
- 不建议直接重启 Nginx：先给出上游修复方向；需要调整 proxy_*_timeout、worker_connections、keepalive 时说明依据与风险。

<!-- platform-template-version: 2 -->
