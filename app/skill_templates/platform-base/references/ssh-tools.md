# SSH MCP 原生工具

对应 https://github.com/beijing10000-boop/ssh-mcp-server 。平台 provider：ssh_mcp。`call_mcp_tool` 的 name 填原生工具名，arguments 为 JSON 对象。平台校验只读工具、已解析主机和 expected_revision；SSH 服务再校验客户端主机组、动作权限、资产版本、目录和服务名。平台只向模型展示当前令牌获准执行的工具。

| 工具 | 主要参数 | 用途 |
| --- | --- | --- |
| `ssh_resolve_target` | address：已登记内网 IP | 返回 host_id、address、name、revision、zabbix_hostid；不发起 SSH |
| `ssh_resolve_host` | zabbix_hostid：数字字符串 | 解析唯一的 Zabbix 映射，返回 SSH host_id 与 revision |
| `ssh_list_hosts` | query、offset、limit（1–1000）、可选 group_id | 已授权且就绪的 Linux 资产；模糊搜索需精确核验 |
| `ssh_diagnose_service` | host_id、service、expected_revision | systemd 服务当前状态 |
| `ssh_diagnose_logs` | host_id、service、minutes（1–120）、expected_revision | 指定服务的有界日志 |
| `ssh_diagnose_kernel` | host_id、minutes（1–120）、expected_revision | 内核告警 |
| `ssh_diagnose_directory_usage` | host_id、root、expected_revision | 指定根路径下一层的目录用量 |

其余诊断工具都传 host_id 与 expected_revision；detail 可选 summary（默认）或 full（需要原文且预算允许时）。

- CPU、内存和进程：`ssh_diagnose_cpu`、`ssh_diagnose_memory`、`ssh_diagnose_processes`、`ssh_diagnose_memory_processes`、`ssh_diagnose_pressure`、`ssh_diagnose_resource_limits`
- 磁盘与 I/O：`ssh_diagnose_disk`、`ssh_diagnose_io`、`ssh_diagnose_mounts`、`ssh_diagnose_block_devices`
- 网络：`ssh_diagnose_network`、`ssh_diagnose_sockets`、`ssh_diagnose_peer_connections`、`ssh_diagnose_peer_traffic`、`ssh_diagnose_tcp_states`
- 系统与服务：`ssh_diagnose_system`、`ssh_diagnose_health`、`ssh_diagnose_capabilities`、`ssh_diagnose_failed_services`、`ssh_diagnose_service_inventory`、`ssh_diagnose_timers`、`ssh_diagnose_time_sync`
- 容器与错误：`ssh_diagnose_containers`、`ssh_diagnose_container_stats`、`ssh_diagnose_system_errors`、`ssh_diagnose_oom`、`ssh_diagnose_security_status`（system_errors 与 oom 可传 minutes 1–120，默认 30）

## 常用返回字段（SSH MCP v0.5.0）

- `ssh_diagnose_cpu`：load_1m / load_5m / load_15m、load_per_core（告警线 1.5，与 Zabbix 默认一致）、load_per_core_5m、vmstat 1 秒采样（vmstat_runnable、vmstat_blocked、cpu_user/system/idle/iowait/steal_percent）、procs_running、procs_blocked。findings 中的 `load_cpu_divergence` 表示负载高但 CPU 空闲较多。
- `ssh_diagnose_processes`：processes[].cpu_percent 为进程生命周期平均值；`cpu_interval` 为最近 1 秒的 CPU 增量；`state_counts` 为各状态进程数；`uninterruptible` 为 D 状态进程及其 wchan。B 模式网关主机没有后三项。
- `ssh_diagnose_memory_processes`：processes[] 可能带 application 与 identity_source（jar / service）；没有时只写实际进程名和 PID，不猜测业务归属，不写完整命令行或环境变量。
- 失败结果含 `error_code`：forbidden、unavailable、mapping_unresolved、timeout、revision_changed、host_unverified、unsupported、invalid_argument、cancelled、failed。

返回 status 为 partial / failed / cancelled，或 findings 写明采集受限时，在报告中保留不足说明。字段可能随服务版本变化，不假设一定存在；旧版本没有上述新字段时如实说明。
