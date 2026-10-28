# SSH MCP 原生工具

对应 https://github.com/beijing10000-boop/ssh-mcp-server 。IP 精确解析需要 0.4.1；其余工具仍以现场 list_mcp_tools 返回的目录和参数为准。

平台 provider：ssh_mcp。call_mcp_tool 的 name 填原生工具名，arguments 为 JSON 对象。平台自动校验只读工具、已解析主机和 expected_revision；SSH 服务再校验客户端主机组、动作权限、资产版本、目录和服务名。

| 工具 | 主要参数 | 返回或用途 |
| --- | --- | --- |
| `ssh_resolve_target` | address: 已登记内网 IP | status、host_id、address、name、revision、zabbix_hostid；不发起 SSH |
| `ssh_resolve_host` | zabbix_hostid: 数字字符串 | 解析唯一 Zabbix 映射，返回 SSH host_id 与 revision |
| `ssh_list_hosts` | query: 字符串，offset: 0 起，limit: 1–1000，可选 group_id | 当前授权且就绪的 Linux 资产列表，id、name、address、revision 等；模糊搜索需精确核验 |
| `ssh_list_groups` | 无 | 当前客户端可见的主机组 |
| `ssh_list_tool_catalog` | 无 | 当前客户端授权的诊断动作和参数说明 |
| `ssh_test_connection` | host_id、expected_revision | 固定只读连接验证 |
| `ssh_diagnose_service` | host_id、service、expected_revision | systemd 服务当前状态 |
| `ssh_diagnose_logs` | host_id、service、minutes: 1–120、expected_revision | 指定服务有界日志 |
| `ssh_diagnose_kernel` | host_id、minutes: 1–120、expected_revision | 内核日志 |
| `ssh_diagnose_directory_usage` | host_id、root、expected_revision | 指定根路径下一层目录用量 |

以下无额外场景参数的诊断工具，均传 host_id、expected_revision；detail 可选 summary（默认）或 full（需要原文且预算允许时）。先看实际参数结构。新版 SSH MCP 的 ssh_diagnose_memory_processes 在获准读取时，summary.processes[] 可返回 application（已识别的 JAR 基名或 systemd 单元）与 identity_source（jar/service）。没有字段时只显示实际 comm/name 和 PID，不猜测业务归属；不得把完整 JVM 命令行、参数或环境变量写进报告：

CPU、内存和进程：`ssh_diagnose_cpu`、`ssh_diagnose_memory`、`ssh_diagnose_processes`、`ssh_diagnose_memory_processes`、`ssh_diagnose_pressure`、`ssh_diagnose_resource_limits`。

磁盘与 I/O：`ssh_diagnose_disk`、`ssh_diagnose_io`、`ssh_diagnose_mounts`、`ssh_diagnose_block_devices`。

网络：`ssh_diagnose_network`、`ssh_diagnose_sockets`、`ssh_diagnose_peer_connections`、`ssh_diagnose_peer_traffic`、`ssh_diagnose_tcp_states`。

系统与服务：`ssh_diagnose_system`、`ssh_diagnose_health`、`ssh_diagnose_capabilities`、`ssh_diagnose_failed_services`、`ssh_diagnose_service_inventory`、`ssh_diagnose_timers`、`ssh_diagnose_time_sync`。

容器与错误：`ssh_diagnose_containers`、`ssh_diagnose_container_stats`、`ssh_diagnose_system_errors`、`ssh_diagnose_oom`、`ssh_diagnose_security_status`。system_errors 和 oom 还可传 minutes: 1–120，默认 30。

返回 status 为 partial/failed/cancelled，或 summary/findings 明确存在采集限制时，保留不足说明。data、summary、findings 和脱敏原文结构可能随服务版本变化，不假设所有字段一定存在。不要把工具目录可见等同于客户端获准执行全部动作。
