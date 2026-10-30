---
name: platform-syslog
description: Linux 系统日志诊断：按告警时间窗口读取 journald 或 /var/log（messages、syslog、secure、auth.log），识别 OOM、磁盘 I/O 与文件系统错误、网络链路、服务失败、内核异常、登录失败与重启。日志、系统、内存、I/O、不可达类告警时加载。
types: [logs, system, memory, io, unreachable]
devices: [linux, unknown]
prefetch:
- scopes: [alert]
  types: [logs, system, io]
  ssh: [ssh_diagnose_syslog]
---

# 系统日志诊断

## 读取方式

- 用 `ssh_diagnose_syslog`，since / until 取告警时间前 15 分钟到告警后 15 分钟（Unix 秒，平台预采集已这样做）；需要更早的上下文时再扩大窗口，单次最长 24 小时。按 unit、pid、keyword、priority 缩小范围，不要一次读取大量 info 级日志。
- 返回的 source 说明实际来源：journald、文件日志（files_used）或二者都不可用；`journal_access=limited` 表示诊断账号不在 systemd-journal / adm 组，只能看到部分日志；`priority_approx` 表示文件日志按关键字近似过滤了级别。以上情况下空结果不能写成“没有错误”。

## 分类线索（matched）

- **oom**：`Out of memory: Killed process <pid> (<name>)`、`oom-kill`、`memory cgroup out of memory` 指明被杀进程与 cgroup；结合内存历史与服务重启记录确认影响。
- **io_error**：`I/O error`、`blk_update_request`、`EXT4-fs error`、`XFS ... error`、`Remounting filesystem read-only`：存储故障或文件系统损坏，优先级高于容量与性能问题，建议核查磁盘与 RAID / 云盘状态。
- **network**：`link is down`、`NIC Link is Down`、`carrier lost`：物理链路或虚拟网卡问题，结合网卡错误计数与 Zabbix 接口历史。
- **service**：`Failed to start`、`Main process exited`、`start request repeated too quickly`：对应服务用 `ssh_diagnose_service_detail` 继续查。
- **kernel**：`segfault`、`soft lockup`、`hung_task`、`Call Trace`：内核或驱动层问题，hung_task 常伴随 D 状态进程与 I/O 卡顿。
- **auth**：大量 `Failed password` / `Invalid user`（auth.top_sources 给出来源 IP）说明扫描或暴力破解，可能造成 CPU 与连接数升高。
- `boot.rebooted_in_window` 为真时窗口内发生过重启，之前的进程与内存状态已丢失，结论要区分重启前后。

## 报告要点

引用日志时只摘录关键行的关键片段（时间、进程、错误类型），不要整段复制；注明日志来源与时间窗口，计数是窗口内返回的有界结果，不等于全天总数。
