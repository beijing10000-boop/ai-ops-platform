---
name: platform-network
description: 网络设备诊断（交换机、路由器、防火墙、无线控制器等 SNMP 设备）：使用 Zabbix 的 SNMP 监控数据与历史趋势（不做 SSH），分析接口状态、错误与丢包、带宽利用率、CPU / 内存、ICMP 可达性与时延、设备重启；设备日志接入日志分析平台时结合设备事件。设备类型为网络设备时加载。
devices: [network]
prefetch:
- scopes: [alert, web]
  types: ["*"]
  zabbix_items: [icmpping, system.cpu.util, vm.memory, system.uptime, system.hw.uptime, sensor]
  history: ["icmpping*", "system.cpu.util*", "vm.memory.util*", "system.uptime*", "system.hw.uptime*"]
  schemas: [history_get, trend_get]
---

# 网络设备诊断（仅 Zabbix / SNMP）

网络设备没有 SSH 实时证据：结论来自 SNMP 监控项的最新值、告警前后历史、7 天趋势与事件。不要调用任何 `ssh_` 工具。预采集已按触发器取得告警监控项，并按触发器 key 中的接口索引取得**同一接口**的其它监控项（状态、流量、错误、丢弃）。设备日志已接入日志分析平台时（`capabilities.logs` 为 used / available），预采集还有该设备告警前后的设备事件（端口抖动、事件时间线、配置变更），是与 SNMP 指标相互独立的维度，读法见 platform-logs。

## 接口告警

- 状态：`net.if.status[...]` 由 1（up）变为 2（down）的时间点即故障开始；同时看对端接口或上联设备是否同时告警（`event_get` 的同时段事件）。
- 错误与丢弃：`net.if.in.errors` / `net.if.in.discards` 等是累计计数器（或 Zabbix 已换算的每秒速率），用告警前后的差值判断是否在告警时段增长；CRC / 输入错误持续增长多指向物理链路（光模块、网线、双工不匹配），出方向丢弃多指向拥塞或 QoS。
- 带宽：`net.if.in` / `net.if.out` 与 `net.if.speed` 对比得出利用率；7 天趋势判断是突发流量还是长期容量不足。
- 接口抖动：近 24 小时同一触发器多次触发（`signals.recurrence`）说明链路不稳定，结论应指向物理链路或对端设备排查。

## SNMP 采集中断（nodata）与 SNMP 不可用

触发器表达式是 `nodata(...)`，或标题是“采集中断”“no data”“SNMP 不可用”时，告警说的是 Zabbix 取不到数据，不是设备指标越限。按顺序确定范围与原因：

1. **范围**：同一设备的 ICMP 与其它 SNMP 监控项是否仍在更新（`lastclock`、`collection_freshness`）。只有这一项（或这一张表）停 → 该 OID / 该 walk 本身；全部 SNMP 停而 ICMP 正常 → SNMP 代理、ACL / 团体名、上送 CPU 限速；ICMP 也断 → 设备或链路（按不可达处理）。
2. **Zabbix 记录的原因**：触发器监控项的 `state` / `error`（如 Timeout、No such object、Too big）、`type`（20 = SNMP）与 `delay`。对一整张表（如全部 AP 的指标）做 walk 而间隔只有几秒到几十秒，单次响应大、频率高，最容易被设备限速并超时。
3. **设备日志**（`device_problem_events`、`log_network_events` 的时间线）：
   - 「上送 CPU 报文被限速丢弃（CPCAR）」且协议（Protocol / Packet-Type）为 snmp：设备把超过 CPCAR 承诺速率（CIR）的 SNMP 报文丢掉，walk 因此超时、断数——与停更时间对得上时就是直接原因。其他协议（arp、bpdu、ospf…）被丢弃说明控制平面压力，可能导致协议震荡。
   - 「SNMP 认证失败 / 源 IP 锁定」（SNMP_FAIL 团体名错误、SNMP_IPLOCK）：某个网管地址用错团体名，设备锁定该源 IP 一段时间；被锁的若是 Zabbix server / proxy 的地址，采集就会中断。写出日志里的源 IP，说明它是不是本平台的采集地址。
4. **规律**：结合 `recurrence`（每天几次、每次几分钟后自行恢复）判断是持续限速还是偶发，`related_alerts` 里同一时刻是否还有其它设备的采集告警（共用同一采集代理时可能是 Zabbix 侧 SNMP 轮询繁忙）。

建议写到具体参数：把大表 walk 的采集间隔调到 60–300 秒、拆分 OID 或改为按需采集；必要时在设备上提高 snmp 报文的 CPCAR 速率（变更需审批，先用 `display cpu-defend statistics packet-type snmp` 确认丢弃仍在增长）；团体名错误则找到并修正该源 IP 的配置；触发器的 nodata 时长短于实际采集间隔加一次超时的，给出调整值。可直接写出的只读命令：`display cpu-defend statistics packet-type snmp`、`display snmp-agent statistics`、`display logbuffer`。

## 设备整体

- CPU / 内存：厂商模板的 `system.cpu.util[...]`、`vm.memory.util[...]` 持续高位会导致控制平面丢包、协议震荡；结合趋势区分常态与突发。
- 可达性：`icmpping`、`icmppingloss`、`icmppingsec` 判断设备是否可达与时延；SNMP 不可用但 ICMP 正常多为 SNMP 进程或 ACL 问题。
- 重启：`system.uptime` / `system.hw.uptime` 回落说明设备重启，结合事件时间判断是否与告警相关。值一直为 0 的 uptime 监控项是设备不支持该 OID，不能用来判断重启，报告里不必讨论它。
- 不可达（ICMP）：`event_age` 显示问题已持续一天以上且未恢复时，先确认设备是否已下线、搬迁或更换管理地址（停用监控或改地址），再谈链路与供电排查；多台设备同时不可达（`related_alerts`）先找共同的上联设备或链路。
- 温度、风扇、电源（`sensor.*`）告警直接引用对应监控项的历史。

## 报告

说明使用的是 SNMP 监控数据、查询的接口名称或索引；无法获得设备日志、配置或实时会话信息时写明需要登录设备核查的具体命令方向（例如查看接口错误计数、光功率、日志缓冲区），不要编造设备侧状态。

<!-- platform-template-version: 2 -->
