"""Fixed snippets shared with the optional forced-command gateway; no sudo."""

import re
import shlex

SERVICE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\Z", re.ASCII)
PREFIX = "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; LC_ALL=C; export LC_ALL; "
COMMANDS = {
    "connection": "printf 'AIOPS_SSH_OK\\n'; id -u; uname -s",
    "cpu": "cat /proc/loadavg /proc/stat; if command -v vmstat >/dev/null 2>&1; then vmstat 1 2; else printf 'CAPABILITY_MISSING:vmstat\\n'; fi",
    "memory": "cat /proc/meminfo; if command -v free >/dev/null 2>&1; then free -k; else printf 'CAPABILITY_MISSING:free\\n'; fi",
    "processes": "ps -eo pid,ppid,comm,pcpu,pmem,rss,etime,state --sort=-pcpu | head -n 25",
    "memory_processes": "ps -eo pid,ppid,comm,pcpu,pmem,rss,etime,state --sort=-rss | head -n 25",
    "disk": "df -Pk -l; df -Pi -l; head -n 80 /proc/mounts",
    "io": "if command -v iostat >/dev/null 2>&1; then iostat -dx 1 2; else printf 'CAPABILITY_MISSING:iostat; cumulative counters only\\n'; cat /proc/diskstats; fi",
    "network": "cat /proc/net/dev /proc/net/snmp; if command -v ip >/dev/null 2>&1; then ip -s link; ip route show; else printf 'CAPABILITY_MISSING:ip\\n'; cat /proc/net/route; fi",
    "sockets": "if command -v ss >/dev/null 2>&1; then ss -s; ss -lnt | head -n 60; else printf 'CAPABILITY_MISSING:ss; proc fallback\\n'; head -n 60 /proc/net/tcp /proc/net/tcp6; fi",
    "system": "date -u '+%Y-%m-%dT%H:%M:%SZ'; uname -sr; cat /proc/uptime /proc/loadavg; if command -v who >/dev/null 2>&1; then who -b; fi",
}


def validate_path(value):
    # Only local application/log data trees; never /, pseudo-filesystems or parent traversal.
    if (
        not isinstance(value, str)
        or len(value) > 200
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
        or ".." in value.split("/")
    ):
        raise ValueError("目录必须为受限数据路径，不能包含空白、父路径或 Shell 字符")
    value = value.rstrip("/")
    if not any(
        value == p or value.startswith(p + "/")
        for p in ("/data", "/var/log", "/var/lib", "/opt")
    ):
        raise ValueError("目录仅允许 /data、/var/log、/var/lib、/opt 及其子目录")
    return value


def build(action, service=None, time_window=30):
    if (
        isinstance(time_window, bool)
        or not isinstance(time_window, int)
        or not 1 <= time_window <= 120
    ):
        raise ValueError("时间窗口必须为 1–120 分钟")
    if action in COMMANDS:
        if service is not None:
            raise ValueError("此动作不接受服务参数")
        return PREFIX + COMMANDS[action]
    if action == "directory":
        path = shlex.quote(validate_path(service))
        return (
            PREFIX
            + f"if command -v timeout >/dev/null 2>&1 && command -v du >/dev/null 2>&1 && command -v nice >/dev/null 2>&1; then timeout -k 1 3 nice -n 19 du -x -s -- {path}; else printf 'CAPABILITY_MISSING:bounded-directory-check\\n'; fi"
        )
    if action in {"service", "logs"}:
        if not isinstance(service, str) or not SERVICE.fullmatch(service):
            raise ValueError("请指定有效的 systemd 服务名称")
        unit = shlex.quote(service)
        if action == "service":
            return (
                PREFIX
                + f"if command -v systemctl >/dev/null 2>&1; then systemctl show --no-pager --property=Id,ActiveState,SubState,Result,MainPID,ExecMainStatus,ActiveEnterTimestamp -- {unit}; else printf 'CAPABILITY_MISSING:systemctl\\n'; fi"
            )
        return (
            PREFIX
            + f"if command -v journalctl >/dev/null 2>&1; then journalctl --no-pager -q -u {unit} --since '-{time_window} min' -n 120 -o short-iso; else printf 'CAPABILITY_MISSING:journalctl\\n'; fi"
        )
    if action == "kernel" and service is None:
        return (
            PREFIX
            + f"if command -v journalctl >/dev/null 2>&1; then journalctl --no-pager -q -k --since '-{time_window} min' -p warning -n 100 -o short-iso; else printf 'CAPABILITY_MISSING:bounded-kernel-log\\n'; fi"
        )
    raise ValueError("不支持的固定诊断动作")


def gateway_request(action, service=None, time_window=30):
    build(action, service, time_window)
    return (
        "aiops-v1 "
        + action
        + " "
        + str(time_window)
        + (" " + service if service else "")
    )
