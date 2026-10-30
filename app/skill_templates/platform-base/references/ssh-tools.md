# SSH MCP 原生工具

对应 https://github.com/beijing10000-boop/ssh-mcp-server 。平台 provider：ssh_mcp。`call_mcp_tool` 的 name 填原生工具名，arguments 为 JSON 对象。平台校验只读工具、已解析主机和 expected_revision；SSH 服务再校验客户端主机组、动作权限、资产版本与参数白名单。平台只向模型展示当前令牌获准执行的工具（未授权的列在 capabilities.unauthorized_tools）。

## 目标解析

| 工具 | 主要参数 | 用途 |
| --- | --- | --- |
| `ssh_resolve_target` | address：已登记内网 IP | 返回 host_id、revision、name、asset_type、mode；不发起 SSH |
| `ssh_resolve_host` | zabbix_hostid：数字字符串 | 唯一的 Zabbix 映射；失败时 error_code 为 not_linux（附 asset_type）、not_ready、mapping_unresolved 或 unavailable |
| `ssh_list_hosts` | query、offset、limit（1–1000）、可选 group_id | 已授权且就绪的 Linux 资产；模糊搜索需精确核验 |

## 固定诊断（只传 host_id 与 expected_revision）

detail 可选 summary（默认，结构化摘要与 findings）或 full（另带脱敏原文，只在需要原文且预算允许时用）。

- CPU、内存和进程：`ssh_diagnose_cpu`、`ssh_diagnose_memory`、`ssh_diagnose_processes`、`ssh_diagnose_memory_processes`、`ssh_diagnose_pressure`、`ssh_diagnose_resource_limits`
- 磁盘与 I/O：`ssh_diagnose_disk`、`ssh_diagnose_io`、`ssh_diagnose_mounts`、`ssh_diagnose_block_devices`
- 网络：`ssh_diagnose_network`、`ssh_diagnose_sockets`、`ssh_diagnose_peer_connections`、`ssh_diagnose_peer_traffic`、`ssh_diagnose_tcp_states`
- 系统与服务：`ssh_diagnose_system`、`ssh_diagnose_health`、`ssh_diagnose_capabilities`、`ssh_diagnose_failed_services`、`ssh_diagnose_service_inventory`、`ssh_diagnose_timers`、`ssh_diagnose_time_sync`、`ssh_diagnose_service_map`（端口 → 进程 → 单元 / 容器）
- 容器与日志：`ssh_diagnose_containers`、`ssh_diagnose_container_stats`、`ssh_diagnose_system_errors`、`ssh_diagnose_oom`、`ssh_diagnose_kernel`（后三个可传 minutes 1–120）、`ssh_diagnose_security_status`
- 应用：`ssh_diagnose_java`（Java 进程、应用名、JVM 参数、线程、句柄、cgroup 内存上限）

## 带参数的诊断

| 工具 | 参数 | 用途 |
| --- | --- | --- |
| `ssh_collect` | actions（1–6 个固定动作，如 ["cpu","processes","pressure"]）、可选 service、minutes | 同一 SSH 会话依次执行多个固定诊断，每步单独返回 summary / findings；每步都需要授权 |
| `ssh_diagnose_service` | service | systemd 服务当前状态（含 LoadState、NRestarts） |
| `ssh_diagnose_service_detail` | service、minutes（1–1440） | 状态、退出原因、重启记录、启动命令、单元文件、进程、端口、日志 |
| `ssh_diagnose_logs` | service、minutes（1–120） | 指定服务的有界日志 |
| `ssh_diagnose_syslog` | minutes 或 since / until（Unix 秒，最长 24 小时）、unit、priority、keyword、pid、lines（20–300） | journald 或 /var/log 系统日志，分类线索与代表性日志 |
| `ssh_diagnose_nginx` | minutes（1–1440） | Nginx 二进制、配置摘要、upstream、进程、端口、窗口内 error.log 统计 |
| `ssh_diagnose_nginx_access` | minutes 或 since / until、path、status（all / 4xx / 5xx / 具体码）、keyword、top（5–30） | 访问日志状态码分布、TOP URI / IP / UA、按分钟趋势、请求与上游耗时 |
| `ssh_diagnose_jvm` | pid、probes（heap_info、vm_flags、gc_stat、gc_log） | jcmd / jstat 探针，中等开销，只对需要的单个进程执行一次 |
| `ssh_diagnose_directory_usage` | root（白名单目录） | 指定根路径下一层的目录用量 |

## 常用返回字段

- `ssh_diagnose_cpu`：load_1m / 5m / 15m、load_per_core（告警线 1.5，与 Zabbix 默认一致）、vmstat 1 秒采样（运行 / 阻塞队列，us / sy / id / wa / st）、procs_running、procs_blocked；`load_cpu_divergence` 表示负载高但 CPU 空闲较多。
- `ssh_diagnose_processes`：cpu_percent 为生命周期平均值；`cpu_interval` 为最近 1 秒增量；`state_counts`、`uninterruptible`（D 状态进程与 wchan）。B 模式网关主机没有后三项。
- 日志类结果的 summary 带 `entries`（最近若干行）、`matched`（oom / io_error / network / service / kernel / auth 分类）、`first_at` / `last_at`；`journal_access` 为 limited 时诊断账号看不到全部系统日志。
- `ssh_diagnose_service` / `service_detail`：`unit_not_found` 表示单元名不存在（不是服务停止）；`service_restarts`、`service_result` 给出重启与退出原因。
- 结果字段 `status` 为 partial / failed / cancelled，`timed_out`、`incomplete_reason`（timeout / output_limit / exit_code / stderr）或 findings 中的 `collection_coverage` 都表示采集不完整，要在报告中保留不足说明。
- 失败结果的 `error_code`：forbidden、unavailable、mapping_unresolved、not_linux、not_ready、busy（同主机排队超时，可稍后重试）、timeout、revision_changed、host_unverified、unsupported（B 模式不支持该动作）、invalid_argument、cancelled、failed。

字段可能随服务版本变化，不假设一定存在；旧版本没有上述新字段或新工具时如实说明。
