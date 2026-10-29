# initMAX Zabbix MCP 查询

对应 https://github.com/initMAX/zabbix-mcp-server 。平台 provider：zabbix_mcp。平台只开放九种只读工具：`host_get`、`hostgroup_get`、`hostinterface_get`、`event_get`、`problem_get`、`trigger_get`、`item_get`、`history_get`、`trend_get`。远端有写入能力也不能使用。

output、selectInterfaces、selectInventory、selectTags、selectHostGroups 等按字段数组填写；平台会按远端实际 Schema 转换格式。不要自行填写 server、extra_params、凭据或其他未开放的参数。数字 ID 一律用字符串数组。

## 定位主机

- 明确 Host ID：`host_get` 传 hostids。
- 明确 IP：先把点号换成短横线，用 `host_get` 的 filter.host 精确匹配技术主机名，只承认返回的 host 字段完全相同的结果。没有匹配时，用 `hostinterface_get` 的 filter.ip 查候选，再逐个核验。不要在 host_get 的 filter 里填 ip。
- 一个 IP 对应多个 Host ID 且无法唯一确定时，不猜测历史监控对象，说明需要明确的 Host ID；SSH 实时查询不受影响。
- 需要设备类型时，host_get 按需选择 selectInventory: [os, type]、selectTags: [tag, value]、selectHostGroups: [groupid, name]。

## 告警与历史

1. 告警事实不足时，用 `event_get` 的 eventids 核实 clock、value、r_eventid；需要当前问题或触发器状态时用 `problem_get`、`trigger_get`。`problem_get` 的 sortfield 只支持 eventid，按时间分析时读取返回的 clock。平台不开放触发器表达式；描述里没有明确阈值时，写明阈值未核实。
2. `item_get` 按 hostids 与 search.key_ 或 search.name 查找监控项，可用 searchByAny，限制数量；保留 itemid、value_type、lastvalue、lastclock、units。
3. `history_get` 只能使用本任务 item_get 返回过的 itemids；history 与 value_type 对应；time_from、time_till 为秒级 Unix 时间戳。先查告警前后的短窗口；每次不超过 8 个监控项、86400 秒、120 条。平台给模型的历史结果是数值统计加少量样本，样本不是完整序列，不能据此推断逐分钟变化或精确持续时长。
4. `trend_get` 同样先核验 itemid，再查有界时间段，分析 value_min / value_avg / value_max；不能把小时平均值写成瞬时峰值。告警诊断用它查近 7 天基线。

“昨天”指北京时间昨日 00:00 至今日 00:00 前一秒，不等于过去 24 小时。返回为空、参数不支持、接口拒绝或历史缺失时，在报告中保留缺口，不编造监控项、阈值或恢复状态。恢复事件与当前采集分别说明；缺少新鲜指标时，不能仅凭事件已恢复就说当前状态正常。
