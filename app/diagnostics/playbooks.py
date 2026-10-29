PLAYBOOKS = {
    "cpu": {
        "label": "CPU 异常",
        "metrics": ["system.cpu.util", "system.cpu.load", "vm.memory", "system.swap"],
        "limitation": "当前进程 CPU 不能证明其造成历史告警；必须核对采集时间和 iowait",
    },
    "memory": {
        "label": "内存不足",
        "metrics": ["vm.memory", "system.swap", "system.cpu.load"],
        "limitation": "无权限读取内核日志时无法确认 OOM；RSS 排名不是完整归因",
    },
    "disk": {
        "label": "磁盘容量",
        "metrics": ["vfs.fs.size", "vfs.fs.inode"],
        "limitation": "文件系统容量与 inode 不能确定具体大目录；目录占用可在独立 SSH MCP 检查，禁止自动清理",
    },
    "io": {
        "label": "IO 性能",
        "metrics": ["vfs.dev", "system.cpu.util"],
        "limitation": "无 iostat 时仅返回累计 diskstats，不能将单点累计计数当作实时 IO 延迟",
    },
    "service": {
        "label": "服务异常",
        "metrics": ["proc.num", "net.tcp.service", "systemd"],
        "limitation": "必须显式提供 systemd 服务名；禁止自动重启",
    },
    "network": {
        "label": "网络异常",
        "metrics": ["net.if", "net.tcp"],
        "limitation": "网卡错误和 TCP 重传为累计计数，缺少前后对照时不能换算当前丢包率",
    },
    "system": {
        "label": "系统异常",
        "metrics": ["system.uptime", "vm.memory"],
        "limitation": "SSH 当前快照不能重建未被采集的历史系统活动",
    },
    "unreachable": {
        "label": "主机不可达",
        "metrics": ["agent.ping", "icmpping", "system.uptime"],
        "limitation": "SSH 失败不等于主机关机，应分别核验 Agent、SSH 和网络",
    },
    "bottleneck": {
        "label": "资源瓶颈",
        "metrics": ["system.cpu", "vm.memory", "vfs.dev", "net.if"],
        "limitation": "相关性不等于因果关系",
    },
    "logs": {
        "label": "日志异常",
        "metrics": ["log", "systemd"],
        "limitation": "仅指定服务和受限时间窗口；自动脱敏不保证移除全部业务敏感信息",
    },
}


def classify(text):
    lower = str(text).lower()
    for kind, terms in [
        ("memory", ("memory", "swap", "oom", "内存")),
        (
            "disk",
            (
                "disk space",
                "filesystem",
                "disk full",
                "space is low",
                "fs [",
                "磁盘空间",
                "磁盘容量",
                "inode",
                "vfs.fs",
                "/data",
            ),
        ),
        (
            "io",
            (
                "iowait",
                "io latency",
                "io延迟",
                "disk read",
                "disk write",
                "read/write",
                "i/o",
                "await",
                "iops",
                "queue length",
                "vfs.dev",
                "磁盘读",
                "磁盘写",
                "读写",
                "响应时间",
            ),
        ),
        ("cpu", ("cpu", "load", "负载")),
        ("unreachable", ("unreachable", "不可达", "agent is not")),
        ("service", ("service", "服务", "process is not")),
        ("network", ("network", "packet", "网络", "丢包", "interface")),
        ("logs", ("日志", "log error")),
        (
            "system",
            ("reboot", "kernel", "installed packages", "重启", "内核", "软件包"),
        ),
    ]:
        if any(term in lower for term in terms):
            return kind
    return "bottleneck"
