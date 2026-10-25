# 接入独立 SSH MCP

平台仅作为 SSH MCP 客户端。请先部署 [ssh-mcp-server](https://github.com/beijing10000-boop/ssh-mcp-server)，使用 v0.2.0 或更新版。

1. 在 SSH MCP Web 完成飞书初始化，登记主机、SSH 凭据、跳板和主机公钥，并核验指纹。
2. 为每台主机填写其真实 Zabbix Host ID，保证唯一。SSH MCP 内部主机 ID 与 Zabbix Host ID 不同。
3. 为 AI 平台签发独立 MCP 客户端令牌，限定主机组和诊断动作。
4. 平台 Web → 连接管理 → SSH MCP：填写 `/mcp` 地址、令牌、开关与超时，验证后保存。
5. 平台 AI 诊断页直接查询并选择 Zabbix 主机，用“验证诊断参数与关联”检查后发起诊断。告警按事件 Host ID 解析；平台不维护本地主机资产，主机类型来自 Zabbix OS/aiops.device_type 标签。

当前十类剧本：CPU（cpu/processes）、内存（memory/memory_processes/kernel）、磁盘（disk）、IO（io/cpu）、服务（service/sockets/logs/memory/disk）、网络（network/sockets）、系统（system/kernel）、不可达（system）、瓶颈（cpu/memory/io/network）、日志（logs）。服务与日志需要合法服务名。目录排行、IP 连接与流量等其它能力在独立 SSH MCP 使用；平台不再复制其管理与执行实现。

标准与深度模式按需补查；快速模式仅监控。未授权动作、命令缺失或日志权限不足会形成部分结果。主机修改导致 revision 变化时，旧任务失效，管理员处理后显式重试新任务。root 是否使用及系统权限由独立 SSH MCP 管理，平台不会获得 SSH 私钥。

Windows、网络设备及 VMware 保留监控分析，不发送 Linux 诊断。没有实时证据时报告明确说明不足。
