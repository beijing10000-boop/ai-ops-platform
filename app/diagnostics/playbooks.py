"""Diagnostic types: the alert class a task is filed under.

The type selects Skill prefetch rules and tells the model which family of
evidence to collect; the Skill, not this table, decides tool order.
"""

import re

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
    "nginx": {
        "label": "Nginx / Web 异常",
        "metrics": ["nginx", "web.page", "net.tcp.service[http"],
        "limitation": "访问日志只读取文件尾部有限字节；错误率按窗口内请求计算，不是全天统计",
    },
    "java": {
        "label": "Java / JVM 异常",
        "metrics": ["jmx", "proc.num[java", "vm.memory"],
        "limitation": "JVM 探针为瞬时快照；GC 计数为启动以来累计值",
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

# Word-boundary patterns, most specific first: "upload" is not a load alert,
# "zoom" is not OOM, and an Nginx 5xx alert is a web problem before a service one.
RULES = (
    (
        "nginx",
        r"\bnginx\b|\bopenresty\b|\btengine\b|\b50[0-9]\b.*(http|请求|错误率)|http.*\b5xx\b|\b5xx\b|upstream|\bweb ?server\b|网关错误|网站",
    ),
    (
        "java",
        r"\bjava\b|\bjvm\b|\bheap\b|\bgc\b|\btomcat\b|\bspring\b|堆内存|垃圾回收|\bjmx\b",
    ),
    ("memory", r"\bmemory\b|\bswap\b|\boom\b|内存|out of memory"),
    (
        "disk",
        r"disk space|filesystem|disk full|space is low|\bfs \[|磁盘空间|磁盘容量|\binode\b|vfs\.fs|/data\b",
    ),
    ("io", r"\biowait\b|io latency|io ?延迟|disk read|disk write|i/o"),
    ("cpu", r"\bcpu\b|\bload\b|负载"),
    (
        # An interface going down is a network event, not an unreachable host.
        "network",
        r"\binterface\b|link down|link up|接口|\bbandwidth\b|带宽|流量|\btraffic\b|丢包|\bpacket\b",
    ),
    (
        "unreachable",
        r"\bunreachable\b|不可达|agent is not|\bicmp\b|\bping\b|\bunavailable\b|宕机|无法连接",
    ),
    ("service", r"\bservice\b|服务|process is not|\bsystemd\b|\bprocess\b.*\bnot\b"),
    ("network", r"\bnetwork\b|网络"),
    ("logs", r"日志|log error|\blog\b.*\berror\b|\blogrt?\["),
    (
        "system",
        r"\breboot\b|\bkernel\b|installed packages|重启|内核|软件包|\buptime\b",
    ),
)


def classify(text):
    lower = str(text).lower()
    for kind, pattern in RULES:
        if re.search(pattern, lower):
            return kind
    return "bottleneck"


# Trigger item keys say what the alert measures better than its free text does.
KEY_RULES = (
    ("nginx", r"^(nginx|web\.page|net\.tcp\.service\[http)"),
    ("java", r"^jmx\[|java"),
    (
        "unreachable",
        r"^(icmpping|agent\.ping|zabbix\[host,agent,available\]|net\.tcp\.service\[ssh)",
    ),
    ("logs", r"^logr?t?\[|^log\.count\[|^logrt\.count\["),
    ("network", r"^net\.if\.|^net\.tcp\.|^net\.udp\.|^ifInErrors|^ifOutErrors|^ifHC"),
    ("disk", r"^vfs\.fs\."),
    ("io", r"^vfs\.dev\."),
    ("memory", r"^vm\.memory\.|^system\.swap\."),
    ("cpu", r"^system\.cpu\.|^system\.load"),
    ("service", r"^proc\.num\[|^systemd\.unit|^net\.tcp\.service\[|^net\.tcp\.port\["),
    ("system", r"^system\.uptime|^system\.boottime|^kernel\."),
)


def classify_keys(keys, current="bottleneck"):
    """Refine a classification with the alert trigger's item keys.

    Keys decide only when the text classification was the generic fallback or
    plainly disagrees with every key; a CPU alert whose trigger also reads
    memory stays a CPU alert.
    """
    kinds = []
    for key in keys:
        key = str(key or "")
        for kind, pattern in KEY_RULES:
            if re.search(pattern, key):
                kinds.append(kind)
                break
    if not kinds:
        return current, None
    if current in kinds:
        return current, None
    # Nginx and Java keys are specific enough to override any text class;
    # reachability and interface keys override only the vague text classes.
    vague = {"bottleneck", "unreachable", "service", "system", "logs"}
    specific = next(
        (
            k
            for k in kinds
            if k in {"nginx", "java"}
            or (k in {"unreachable", "network"} and current in vague)
        ),
        None,
    )
    if specific:
        return specific, f"触发器监控项 key 指向 {PLAYBOOKS[specific]['label']}"
    if current == "bottleneck":
        return kinds[0], f"触发器监控项 key 指向 {PLAYBOOKS[kinds[0]]['label']}"
    return current, None
