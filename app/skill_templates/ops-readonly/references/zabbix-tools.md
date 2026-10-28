# initMAX Zabbix MCP 查询

对应 https://github.com/initMAX/zabbix-mcp-server 。平台 provider：zabbix_mcp。

平台只开放九种查询工具：`host_get`、`hostgroup_get`、`hostinterface_get`、`event_get`、`problem_get`、`trigger_get`、`item_get`、`history_get`、`trend_get`。远端有写入能力也不能使用；不要调用 raw_api_call 或创建、更新、删除、确认告警等动作。

list_mcp_tools 返回平台接受的参数结构。call_mcp_tool 中 output 用字段数组，selectInterfaces/selectInventory/selectTags/selectHostGroups 等也按数组填写。平台会根据远端实际 Schema 把 output 转成逗号字符串，并把允许的扩展参数放入 extra_params。不要自行向平台 wrapper 填额外 server、extra_params、凭据字段或未经允许的 Zabbix 参数。

## 定位主机

明确 Host ID：host_get 传 hostids: [数字字符串]。

明确 IP：先 hostinterface_get，filter: {ip: 用户明确的 IP}，output: [hostid, ip]。只采用返回 IP 完全相同的记录；得到唯一 hostid 后再 host_get。不要在 host_get 的 filter 中填 ip；IP 属于接口对象。一个 IP 对应多条 Zabbix Host ID 时，不猜测历史监控目标，说明需要明确 Host ID；独立 SSH 实时查询仍可按已登记 IP 执行。

需要设备类型时，host_get 按需选择 selectInventory: [os, type]、selectTags: [tag, value]、selectHostGroups: [groupid, name]。不能把 Windows、网络设备、VMware 当 Linux 执行 SSH 诊断。

## 告警与历史

1. 对可信告警 event_id 用 event_get 的 eventids 查询，核实 clock、value、r_eventid；必要时用 problem_get、trigger_get 查询当前问题及触发器状态与描述。`problem_get` 的 `sortfield` 只允许 `eventid`（不是 `clock`），按时间分析时读取返回的 clock 并在模型中比较，不向 problem_get 传入 clock 排序。当前平台不开放 expression/recovery_expression 字段；描述没有明确阈值时，写明阈值未核实，不自行添加参数。
2. item_get 按 hostids 与 search.key_ 或 search.name 找相关监控项；可用 searchByAny，限制结果数量。保留 itemid、value_type、lastvalue、lastclock、units。
3. history_get 必须使用本任务 item_get 已返回的 itemids；history 对应 value_type；time_from、time_till 为秒级 Unix 时间戳。先查告警前后短窗口，再按需补查。每次不超过 8 个 item、86400 秒、120 条结果；不要混淆字符串类型与数值类型。
4. trend_get 同样先核验 itemid，再查有界 time_from/time_till，分析 value_min/value_avg/value_max。不能把小时平均值写成瞬时峰值。

数字 ID 均用字符串数组。output 只选择工具参数目录允许的字段。query 返回 empty、不支持参数、接口拒绝或历史缺失时，在报告中保留缺口；不要编造监控项、阈值或恢复状态。

“昨天”使用北京时间昨日 00:00 至今日 00:00 前一秒，不等同于过去 24 小时。趋势达到条数上限时按监控项或时间拆分；原始历史优先缩小至告警前后窗口，不能把前 120 条当完整全天记录。恢复事件与当前采集分别说明；缺少新鲜指标时不能仅凭事件恢复就声称当前主机状态正常。
