---
name: platform-windows
description: Windows 主机诊断：只使用 Zabbix 监控数据（性能计数器、服务状态、可用性与事件日志监控项）分析 CPU、内存、磁盘、网络、服务与不可达类告警，不做 SSH。设备类型为 Windows 时加载。
devices: [windows]
prefetch:
- scopes: [alert, web]
  types: [cpu, bottleneck]
  zabbix_items: [system.cpu, perf_counter_en]
  history: [system.cpu.util, "perf_counter_en*Processor Queue*", "perf_counter_en*Privileged*", "perf_counter_en*Interrupt*", "perf_counter_en*Context Switches*"]
- scopes: [alert, web]
  types: [memory]
  zabbix_items: [vm.memory, system.swap, perf_counter_en]
  history: [vm.memory.util, "vm.memory.size[used]", "perf_counter_en*Pages/sec*", "perf_counter_en*Committed*", "perf_counter_en*Paging*"]
- scopes: [alert, web]
  types: [disk, io]
  zabbix_items: [vfs.fs, perf_counter_en]
  history: ["vfs.fs.dependent.size[*,pused]", "vfs.fs.size[*,pused]", "perf_counter_en*Idle*", "perf_counter_en*Disk sec*", "perf_counter_en*Queue Length*"]
- scopes: [alert, web]
  types: [network]
  zabbix_items: [net.if]
  history: ["net.if.in[*]", "net.if.out[*]"]
- scopes: [alert, web]
  types: [service, logs, system]
  zabbix_items: [service.info, eventlog, system.uptime]
  history: ["service.info[*,state]", system.uptime]
---

# Windows 主机诊断（仅 Zabbix）

Windows 主机没有 SSH 实时证据：所有结论来自 Zabbix 监控项的最新值、告警前后历史、7 天趋势与事件。不要调用任何 `ssh_` 工具；报告中说明“未采集实时进程级数据”的影响。

## CPU

- `system.cpu.util` 与 `\System\Processor Queue Length`：队列长期超过 2 × 逻辑核数才说明 CPU 争抢；单点峰值不算。
- `% Privileged Time` 高说明内核态（驱动、杀毒、I/O）占用，`% Interrupt Time` / DPC 高指向硬件或驱动；`Context Switches/sec` 激增常见于线程过多或锁竞争。
- 默认模板不采集进程级 CPU：没有 `proc_info` 或 Process(*) 计数器时，不能说出具体进程，建议补充相应监控项或在主机上用任务管理器 / Resource Monitor 确认。

## 内存

- `vm.memory.util` 与 `\Memory\% Committed Bytes In Use`：提交量接近上限比物理内存占用更危险；`Pages/sec` 持续偏高说明硬缺页、内存不足或页面文件抖动；`Paging file % Usage` 高说明页面文件不足。
- 用 7 天趋势区分持续增长与突增；没有进程级内存数据时不能断言是哪一个进程泄漏。

## 磁盘

- 容量看 `vfs.fs.dependent.size[盘符,pused]` 与趋势估算剩余时间；同一盘符的 `PhysicalDisk` 计数器由预采集的“相关监控项”一并给出。
- `Avg. Disk sec/Read|Write` 超过 0.02 秒（20 ms）或 `% Idle Time` 很低、队列长度持续大于 2 说明磁盘繁忙；结合告警前后历史判断是否突发。

## 网络、服务与可用性

- 网卡流量对比接口速率；errors / dropped 是累计计数，用历史差值判断告警时段是否增长。
- 服务告警看 `service.info[服务名,state]` 的历史（0 为运行），以及启动类型是否为自动；有 `eventlog[...]` 监控项时引用其中的错误事件。
- agent 不可用：结合 `agent.ping`、`signals.collection_freshness` 与 ICMP 监控项区分整机宕机、网络中断与 agent 服务停止；`system.uptime` 回落说明发生过重启。
