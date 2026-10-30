---
name: platform-network
description: 网络设备诊断（交换机、路由器、防火墙、无线控制器等 SNMP 设备）：只使用 Zabbix 的 SNMP 监控数据与历史趋势，分析接口状态、错误与丢包、带宽利用率、CPU / 内存、ICMP 可达性与时延、设备重启。设备类型为网络设备时加载。
devices: [network]
prefetch:
- scopes: [alert, web]
  types: ["*"]
  zabbix_items: [icmpping, system.cpu.util, vm.memory, system.uptime, system.hw.uptime, sensor]
  history: ["icmpping*", "system.cpu.util*", "vm.memory.util*", "system.uptime*", "system.hw.uptime*"]
  schemas: [history_get, trend_get]
---

# 网络设备诊断（仅 Zabbix / SNMP）

网络设备没有 SSH 实时证据：结论来自 SNMP 监控项的最新值、告警前后历史、7 天趋势与事件。不要调用任何 `ssh_` 工具。预采集已按触发器取得告警监控项，并按触发器 key 中的接口索引取得**同一接口**的其它监控项（状态、流量、错误、丢弃）。

## 接口告警

- 状态：`net.if.status[...]` 由 1（up）变为 2（down）的时间点即故障开始；同时看对端接口或上联设备是否同时告警（`event_get` 的同时段事件）。
- 错误与丢弃：`net.if.in.errors` / `net.if.in.discards` 等是累计计数器（或 Zabbix 已换算的每秒速率），用告警前后的差值判断是否在告警时段增长；CRC / 输入错误持续增长多指向物理链路（光模块、网线、双工不匹配），出方向丢弃多指向拥塞或 QoS。
- 带宽：`net.if.in` / `net.if.out` 与 `net.if.speed` 对比得出利用率；7 天趋势判断是突发流量还是长期容量不足。
- 接口抖动：近 24 小时同一触发器多次触发（`signals.recurrence`）说明链路不稳定，结论应指向物理链路或对端设备排查。

## 设备整体

- CPU / 内存：厂商模板的 `system.cpu.util[...]`、`vm.memory.util[...]` 持续高位会导致控制平面丢包、协议震荡；结合趋势区分常态与突发。
- 可达性：`icmpping`、`icmppingloss`、`icmppingsec` 判断设备是否可达与时延；SNMP 不可用但 ICMP 正常多为 SNMP 进程或 ACL 问题。
- 重启：`system.uptime` / `system.hw.uptime` 回落说明设备重启，结合事件时间判断是否与告警相关。
- 温度、风扇、电源（`sensor.*`）告警直接引用对应监控项的历史。

## 报告

说明使用的是 SNMP 监控数据、查询的接口名称或索引；无法获得设备日志、配置或实时会话信息时写明需要登录设备核查的具体命令方向（例如查看接口错误计数、光功率、日志缓冲区），不要编造设备侧状态。
