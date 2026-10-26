# 接入独立 SSH MCP

平台仅作为 SSH MCP 客户端。请先部署 [ssh-mcp-server](https://github.com/beijing10000-boop/ssh-mcp-server)，使用 v0.2.0 或更新版。

1. 在 SSH MCP Web 完成飞书初始化，登记主机、SSH 凭据、跳板和主机公钥，并核验指纹。
2. 为每台主机填写其真实 Zabbix Host ID，保证唯一。SSH MCP 内部主机 ID 与 Zabbix Host ID 不同。
3. 为 AI 平台签发独立 MCP 客户端令牌，限定主机组和诊断动作。
4. 平台 Web → 连接管理 → SSH MCP：填写 `/mcp` 地址、令牌、开关与超时，验证后保存。
5. 平台 AI 诊断页直接查询并选择 Zabbix 主机，用“验证诊断参数与关联”检查后发起诊断。告警按事件 Host ID 解析；平台不维护本地主机资产，主机类型来自 Zabbix OS、aiops.device_type 标签或经核验的 Linux 主机组，明确的非 Linux 分类优先。

“验证连接”会实际握手并检查 `ssh_resolve_host` 工具；缺少时提示升级。该检查不能代替远端版本确认，也不能证明目标主机可达。应同时核对 SSH MCP 自身展示的运行版本及部署的发行记录；实际诊断还会验证主机关联、授权与 `expected_revision`。

当前十类剧本：CPU（cpu/processes）、内存（memory/memory_processes/kernel）、磁盘（disk）、IO（io/cpu）、服务（service/sockets/logs/memory/disk）、网络（network/sockets）、系统（system/kernel）、不可达（system）、瓶颈（cpu/memory/io/network）、日志（logs）。服务与日志需要合法服务名。IP 连接与流量等其它能力在独立 SSH MCP 使用；平台不复制其管理与执行实现。

飞书或 Web 问答可直接写“看下 172.20.2.101 这台机器 /data 目录下的空间占用率，列出 5 层”。平台先用 Zabbix 接口 IP 精确过滤，读取 Host ID、主机组、标签、OS；只有唯一精确匹配并确认为 Linux 才进入 SSH 关联。也支持明确的 `Host ID：11600`。多目标、近似匹配、重复 IP、类型未知或 SSH 映射失败时不猜测目标。主机信息写入报告，避免问答报告错误显示“未关联”。

目录查询使用 SSH MCP 的 `ssh_diagnose_directory_usage`，其客户端令牌须授权 `directory` 动作，远端须提供该工具。平台先查文件系统使用率，再对所选根目录及其直接子目录逐层扫描，最多 5 层。路径受固定根目录校验，子路径只来自父扫描返回的直接子目录；不接收 Shell。每次远端扫描最多 8 秒、同一文件系统、每层根路径最多 30 个子目录排行。采集次数或总时间不足时保留已收集结果并标记覆盖不全；不能把排行当完整目录树，也不能把 `du` 字节数当 `df` 使用率。

标准与深度模式对可信绑定的 Linux 主机，按固定剧本自动采集一轮 SSH 实时证据，再交由 AI 结合监控分析；后续补查仍受授权、次数与时间预算限制。快速模式仅监控。未授权动作、命令缺失或日志权限不足会形成部分结果。主机修改导致 revision 变化时，旧任务失效，管理员处理后显式重试新任务。root 是否使用及系统权限由独立 SSH MCP 管理，平台不会获得 SSH 私钥。

Windows、网络设备及 VMware 保留监控分析，不发送 Linux 诊断。没有实时证据时报告明确说明不足。

报告中的 `logs.read` 控制查看日志正文，不是 SSH 工具执行权限。日志默认隐藏；有权限时点击“读取日志证据”。隐藏时仍显示安全的预算/授权失败分类。SSH 客户端动作授权与目标 Linux 日志权限在独立 SSH MCP 管理。
