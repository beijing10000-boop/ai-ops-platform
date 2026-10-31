---
name: platform-linux
description: Linux 主机诊断：CPU 与负载、内存、磁盘容量、I/O、网络、系统与不可达类告警的 Zabbix + SSH 联合取证规则。设备类型为 Linux 或尚未识别时加载。
devices: [linux, unknown]
prefetch:
- scopes: [alert]
  types: [cpu, bottleneck]
  ssh: [ssh_diagnose_cpu, ssh_diagnose_processes, ssh_diagnose_pressure]
  zabbix_items: [system.cpu.load, system.cpu.util, system.cpu.num]
  history: ["system.cpu.load[all,avg5]", system.cpu.util, "system.cpu.util[,iowait]", "system.cpu.load[all,avg1]", "system.cpu.util[,steal]", "system.cpu.util[,system]", "system.cpu.load[all,avg15]", "system.cpu.util[,idle]"]
  schemas: [history_get, trend_get]
- scopes: [alert]
  types: [memory]
  ssh: [ssh_diagnose_memory, ssh_diagnose_memory_processes, ssh_diagnose_pressure, ssh_diagnose_oom, ssh_diagnose_java]
  zabbix_items: [vm.memory, system.swap]
  history: [vm.memory.utilization, "vm.memory.size[pavailable]", "vm.memory.size[available]"]
  schemas: [history_get, trend_get]
- scopes: [alert]
  types: [disk]
  ssh: [ssh_diagnose_disk, ssh_diagnose_mounts]
  zabbix_items: [vfs.fs]
  history: ["vfs.fs.*size[*,pused]", "vfs.fs.*inode[*,pfree]"]
  schemas: [history_get, trend_get]
- scopes: [alert]
  types: [io]
  ssh: [ssh_diagnose_io, ssh_diagnose_cpu, ssh_diagnose_pressure, ssh_diagnose_processes]
  zabbix_items: [vfs.dev, system.cpu.util]
  history: ["vfs.dev.util[*]", "vfs.dev.read.await[*]", "vfs.dev.write.await[*]", "system.cpu.util[,iowait]"]
  schemas: [history_get, trend_get]
- scopes: [alert]
  types: [network]
  ssh: [ssh_diagnose_network, ssh_diagnose_sockets, ssh_diagnose_tcp_states]
  zabbix_items: [net.if, net.tcp]
  history: ["net.if.in[*]", "net.if.out[*]"]
  schemas: [history_get, trend_get]
- scopes: [alert]
  types: [system, unreachable]
  ssh: [ssh_diagnose_system, ssh_diagnose_failed_services]
  schemas: [history_get, event_get]
- scopes: [qa, web]
  types: [cpu, bottleneck]
  ssh: [ssh_diagnose_cpu, ssh_diagnose_processes]
- scopes: [qa, web]
  types: [memory]
  ssh: [ssh_diagnose_memory, ssh_diagnose_memory_processes]
- scopes: [qa, web]
  types: [disk]
  ssh: [ssh_diagnose_disk]
- scopes: [qa, web]
  types: [io]
  ssh: [ssh_diagnose_io, ssh_diagnose_pressure]
- scopes: [qa, web]
  types: [network]
  ssh: [ssh_diagnose_network, ssh_diagnose_sockets]
---

# Linux 主机诊断

预采集已按告警类型执行了下列 SSH 诊断（同一会话，结果在 `evidence.prefetched`），并取得触发器监控项与同一对象相关监控项的告警前后历史、7 天趋势。缺少的维度再按下文补查。

## CPU 与负载

- 对比“每核负载”与触发器阈值，同时看 CPU 利用率与 `cpu_idle_percent`：负载高不等于 CPU 打满。
- `load_cpu_divergence`（负载高但 CPU 空闲）时，优先核查 `procs_blocked`、D 状态进程（`uninterruptible` 的 wchan）、`cpu_iowait_percent` 与 PSI（`ssh_diagnose_pressure` 的 io/cpu），再结合 `ssh_diagnose_io` 与 Zabbix 的 `vfs.dev.*` 判断是否为存储等待；不要只看 CPU 占用排行。
- 当前谁在占 CPU 以 `cpu_interval`（最近 1 秒增量）为准；`cpu_percent` 是进程生命周期平均值，不能代表告警时段。占用高的是 Java 进程时调用 `ssh_diagnose_java`（必要时 `ssh_diagnose_jvm` 看 GC）。
- VMware 等虚拟机的 steal 通常为 0，不能据此排除宿主机 CPU 争抢；需要时建议在虚拟化平台查看 CPU Ready。

## 内存

- 以 MemAvailable 判断是否真正不足，缓存占用不等同于内存不足；持续偏高看 PSI memory 与 `ssh_diagnose_oom`（OOM 记录），必要时 `ssh_diagnose_syslog` 查 OOM 被杀进程。
- 未配置 Swap（总量为 0）是常见的有意配置，按正常处理：不要在结论、分析或建议中提及（包括“未启用 Swap”“建议配置 Swap”）；只有 Swap 实际被使用时才分析换页。
- 用 7 天趋势区分“持续增长”（泄漏或容量不足）与“突增”（批处理、流量峰值）；只有趋势证据时不能断言内存泄漏。
- RSS 排行中的 Java 进程以 `ssh_diagnose_java` 核对 -Xmx、MaxRAMPercentage、容器内存上限与 RSS 的关系：RSS 远高于堆上限说明堆外、元空间或线程栈占用；未设堆上限的多个 JVM 共存容易挤爆内存。

## 磁盘容量与 I/O

- 容量看 pused 与 inode，结合 7 天趋势估算增长速度；目录占用按 platform-base 的 references/directory-analysis.md 逐层展开（`read_skill_resource` 的 name 填 platform-base），`ssh_diagnose_directory_usage` 每次只扫描下一层。
- 只读挂载（`ssh_diagnose_mounts`）、文件系统错误要用 `ssh_diagnose_syslog` 查 I/O error / EXT4-fs / XFS 记录确认。
- I/O 告警看设备 util、await、`cpu_iowait_percent`、PSI io 与 D 状态进程；iostat 缺失时 diskstats 只是累计计数，不能换算速率。

## 网络

- 网卡错误、丢包是累计计数：用 Zabbix 历史的前后差值判断是否在告警时段增长；带宽结合接口速率判断是否打满。
- `ssh_diagnose_tcp_states` 看 CLOSE-WAIT / TIME-WAIT 积压，`ssh_diagnose_peer_connections` 看连接集中在哪些对端；端口归属用 `ssh_diagnose_service_map`。

## 系统与不可达

- 不可达 / agent 不可用：预采集已有可用性监控项历史（何时由 1 变 0）、近 24 小时事件和该主机全部监控项的最近采集时间，`signals` 的 `collection_freshness` 已算好仍在更新的监控项数。全部停止更新按整机不可达或采集链路中断处理，部分仍在更新更可能是 agent 服务本身；SSH 仍能连通时用 `ssh_diagnose_system`（uptime 判断是否重启）与 `ssh_diagnose_service_detail`（zabbix-agent 单元）确认。没有 ICMP 监控项时写明无法区分整机宕机与 agent 停止。
- 重启类告警以 uptime、`ssh_diagnose_syslog` 的 boot 信息与内核日志判断是计划重启、崩溃还是断电。
