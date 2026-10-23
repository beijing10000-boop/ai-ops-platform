# Linux SSH 诊断

## 模式 A：标准免 Agent（默认）

支持使用 root 或普通账号和已配置的 SSH 密钥，不依赖 sudo、目标端 Python、强制命令网关或采集代理。平台只执行审核过的固定命令，允许 UID 0。使用 root 时，在资产编辑中把 SSH 账号设为 `root`、诊断模式选「A · 标准免 Agent」即可，无需勾选 B 模式确认。

目标需具备 OpenSSH 与基础 POSIX 工具。读取 /proc、ps、df、journalctl、systemctl 等；iostat、vmstat、ss、ip 不存在时记录能力缺失，部分提供 /proc 降级。不会自动安装软件。普通账号可能无法查看内核日志或某些进程，报告必须展示权限不足。账号自身通常仍可写自己的目录，不能称为操作系统层面的绝对只读账号。

1. 为 root 或普通账号配置 SSH 密钥登录；私钥通过 Web 凭据管理加密保存。
2. 通过独立可信渠道核验目标 SSH 公钥（例如目标控制台读取 `/etc/ssh/ssh_host_ed25519_key.pub` 并核对指纹）。不得把未经核验的 ssh-keyscan 结果直接当可信值。
3. 登记资产：device_type=linux、精确 Zabbix Host ID、私网 IPv4/ULA IPv6、账号、SSH 端口、固定主机公钥、凭据、模式 A。IP 不接受公网、DNS、loopback 或消息中自动提取值。
4. 必要时登记一个跳板：独立账号、凭据与主机公钥；平台先验证跳板，再验证目标。跳板账号需允许到目标的 direct-tcpip 转发，可在 SSH 服务端收窄目的地址；不安装 root 诊断网关到跳板。
5. 运行连接测试，通过后用专用测试告警逐类检查。

支持 RSA、Ed25519、ECDSA 私钥及相应固定公钥；旧算法和目标 SSH 策略的实际兼容性仍需测试。每个主机并发 1，总并发默认 4；全局跨进程租约、连接和执行超时、输出截断、取消关闭连接。stdout 最多 32768 字符、stderr 最多 2048，执行时间 3–30 秒。网络异常会保存已有证据。

磁盘默认只读容量/inode/挂载信息。目录占用检查需管理员在资产预先登记，最多五个，且限定 /data、/var/log、/var/lib、/opt 及子目录；单个目录用 nice 19、timeout 3 秒和 `du -x -s`，不跨文件系统。大目录仍可能产生短时 I/O，需按实际负载授权。缺少限时工具时不执行扫描。不自动清日志或释放空间。

## 模式 B：可选受限特权

如需在目标端通过强制命令网关约束诊断密钥，可选择模式 B，由管理员在 Web 确认网关已配置，并在目标安装 root 所有的固定网关。模式 B 是可选的执行方式，使用 root 不必切换到模式 B。专用诊断密钥不能复用普通管理密钥。

网关源码 `gateway/aiops-diagnostic-gateway` 只依赖 /bin/sh 和常见系统工具，协议为 `aiops-v1 <固定动作> <分钟> [验证后的服务或路径]`，不接受任意 Shell、传输、PTY、SCP/SFTP 或转发。authorized_keys 应使用经核验的密钥，并指定固定来源 IP：

```text
restrict,from="实际诊断出口IP",command="/usr/local/sbin/aiops-diagnostic-gateway" ssh-ed25519 你的专用公钥主体
```

管理员手工审核安装，或从 Ansible 控制机（控制机需要 Ansible，目标无需 Python）执行可选自动化：

```bash
ansible-playbook -i inventory.ini ops/gateway.yml -e @gateway-vars.yml
```

`gateway-vars.yml` 提供 gateway_approved=true、diagnostic_source_ip、diagnostic_public_key（只含 `ssh-ed25519 base64`，无注释）。inventory 中组名为 diagnostic_gateway_targets。文件不包含私钥。网关及目录必须 root 所有且不可由低权限用户修改；部署前备份对应文件和 authorized_keys。自动化只追加精确限制行，检测到相同公钥已有其他限制会拒绝。

回滚用相同参数增加 `gateway_operation=rollback`：撤销该精确公钥行并恢复 .previous 网关（若存在），不恢复整个旧 authorized_keys，避免删除后来新增的正常管理密钥。部署/回滚在真实目标尚未测试，应先用测试机验证。

平台要求网关输出标识；该标识只是协议校验，不能代替目标公钥与安装审计。真实环境须检查 OpenSSH 强制命令、来源限制和禁用转发是否生效。A 模式通常更适合默认部署。

## 已实现剧本

CPU（load、CPU 计数、CPU 排序进程）、内存（meminfo、RSS 排序进程）、磁盘（容量/inode/登记目录）、I/O（iostat 或累计 diskstats）、服务（验证后的 unit 状态/限量日志）、网络（接口/路由/协议计数/监听概况）、系统（启动时间/内核告警）、不可达（有限连接证据）、瓶颈（CPU/内存/I/O 组合）、日志（服务/内核限时限量）。不模拟 Sysmon/SysOM 的持续事件或历史 eBPF 数据；没有采到的证据明确缺失。
