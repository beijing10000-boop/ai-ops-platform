"""What the platform itself knows around an alert, for its analysis.

Two things no MCP can tell the model: the other alerts the platform received
around the same time (another host or trigger failing with it, the
"linked alerts" an engineer looks for first), and what earlier analyses of
the same host and trigger concluded (a trigger that fires every day should
get a consistent answer, and its permanent fix, not a fresh guess each time).
Both come from the platform's own tables; neither is evidence the model can
cite, the earlier conclusions least of all.
"""

import logging
import re

log = logging.getLogger(__name__)
# Alerts about reaching a host or collecting from it: when the alert is one,
# other hosts' alerts of this kind at the same moment point at a shared
# cause (a switch, a link, a proxy); for a CPU or disk alert they are noise.
AVAILABILITY = re.compile(
    r"(?i)unavailable|not available|unreachable|icmp|no ?data|snmp|link down"
    r"|采集中断|不可达|不可用|中断"
)

# Other alerts within this many seconds of the alert, at most RELATED of them.
RELATED_SECONDS, RELATED = 900, 12
# Earlier analyses of the same host and trigger: this many days, at most PREVIOUS.
PREVIOUS_DAYS, PREVIOUS = 7, 2
CAUSE_CHARS, ACTION_ROWS, ACTION_CHARS = 240, 4, 80
NOTICE = (
    "平台自己的记录，不是工具证据，不能用证据编号引用：related_alerts 是平台在本次告警前后 "
    "15 分钟收到的其它主机的同名告警（本次是可用性 / 采集类告警时还包括其它主机的可用性告警），"
    "用来判断是否为同一原因引起的联动告警；other_hosts_alerting 是同一时段有告警的其它主机数"
    "（告警风暴）；same_host_24h 是本主机近 24 小时的其它告警；previous_analyses 是此前对同一主机、"
    "同一触发器的 AI 分析结论，只能作为线索，必须用本次证据重新核对，"
    "本次证据不支持时不要沿用，支持时说明与上次一致并侧重根治措施"
)


def _beijing(stamp):
    """A stored UTC timestamp (CURRENT_TIMESTAMP) as Beijing local time."""
    from datetime import datetime, timedelta, timezone

    try:
        moment = datetime.strptime(str(stamp)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(stamp)
    beijing = moment.replace(tzinfo=timezone.utc).astimezone(
        timezone(timedelta(hours=8))
    )
    return beijing.strftime("%Y-%m-%d %H:%M:%S")


def _sections(answer):
    """诊断结论 and 处理建议 of a stored report answer (its readable form)."""
    cause, actions, current = [], [], None
    for line in str(answer or "").splitlines():
        text = line.strip()
        if text in ("诊断结论", "处理建议", "分析与依据", "诊断范围（平台生成）"):
            current = text
            continue
        if text.startswith("诊断范围") or text.startswith("证据核对"):
            current = None
            continue
        if not text:
            continue
        if current == "诊断结论":
            cause.append(text)
        elif current == "处理建议":
            actions.append(text)
    return " ".join(cause), actions


def _clip(text, limit):
    text = str(text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def context(event, clock):
    """The alert's platform context, or None when there is nothing to add.

    `event` is the trusted alert (its host_id and trigger_id come from the
    Zabbix webhook), `clock` its moment in Unix seconds. Failures are logged
    and leave the context out: it must never stop an analysis.
    """
    from .main import connection
    from .orchestrator.tasks import decode

    host = str(event.get("host_id") or "")
    trigger = str(event.get("trigger_id") or "")
    event_id = str(event.get("event_id") or "")
    if not (host.isdigit() and event_id and clock):
        return None
    own_name = str(event.get("event_name") or "")
    availability = bool(AVAILABILITY.search(own_name))

    def linked(name):
        """Another host's alert worth the model's attention: the same
        trigger (several hosts at once), or, for an availability alert,
        another availability alert."""
        name = str(name or "")
        return name == own_name or (availability and bool(AVAILABILITY.search(name)))

    result = {}
    try:
        with connection() as db:
            rows = db.execute(
                "SELECT event_name, host_name, severity, received_at, "
                "json_extract(event_json,'$.host_id'), "
                "EXISTS (SELECT 1 FROM alert_events r WHERE r.event_id=a.event_id "
                "AND r.event_value='0') "
                "FROM alert_events a WHERE event_value='1' AND event_id != ? "
                "AND received_at BETWEEN datetime(?,'unixepoch') AND datetime(?,'unixepoch') "
                "ORDER BY abs(strftime('%s',received_at) - ?) LIMIT ?",
                (
                    event_id,
                    clock - RELATED_SECONDS,
                    clock + RELATED_SECONDS,
                    clock,
                    200,
                ),
            ).fetchall()
            related, seen, others = [], set(), set()
            for name, host_name, severity, received, host_id, recovered in rows:
                if str(host_id) == host:
                    continue
                others.add(host_name)
                if not linked(name):
                    continue
                key = (host_name, name)
                if key in seen:
                    continue
                seen.add(key)
                related.append(
                    {
                        "host": _clip(host_name, 80),
                        "alert": _clip(name, 120),
                        "severity": severity,
                        "received_at": _beijing(received),
                        **({"recovered": True} if recovered else {}),
                    }
                )
                if len(related) >= RELATED:
                    break
            if related:
                result["related_alerts"] = related
            if len(others) >= 5:
                # Many hosts alerting at once (of any kind) is an alert storm
                # worth knowing even when none is listed.
                result["other_hosts_alerting"] = len(others)
            same = db.execute(
                "SELECT event_name, COUNT(*), MAX(received_at) FROM alert_events "
                "WHERE event_value='1' AND event_id != ? "
                "AND json_extract(event_json,'$.host_id')=? "
                "AND json_extract(event_json,'$.trigger_id') != ? "
                "AND received_at BETWEEN datetime(?,'unixepoch') AND datetime(?,'unixepoch') "
                "GROUP BY event_name ORDER BY MAX(received_at) DESC LIMIT 8",
                (event_id, host, trigger, clock - 86400, clock + RELATED_SECONDS),
            ).fetchall()
            if same:
                result["same_host_24h"] = [
                    {"alert": _clip(name, 120), "count": count, "last": _beijing(last)}
                    for name, count, last in same
                ]
            if trigger.isdigit():
                earlier = db.execute(
                    "SELECT t.status, t.completed_at, t.report FROM diagnostic_tasks t "
                    "JOIN alert_events a ON a.event_id=t.event_id AND a.event_value='1' "
                    "WHERE t.kind='analysis' AND t.status IN ('success','partial') "
                    "AND t.event_id != ? AND t.completed_at >= datetime(?,'unixepoch') "
                    # Concluded before this alert: an alert analysed later
                    # (a click hours afterwards) is not told what came after.
                    "AND t.completed_at <= datetime(?,'unixepoch') "
                    "AND json_extract(a.event_json,'$.host_id')=? "
                    "AND json_extract(a.event_json,'$.trigger_id')=? "
                    "ORDER BY t.completed_at DESC LIMIT ?",
                    (
                        event_id,
                        clock - PREVIOUS_DAYS * 86400,
                        clock,
                        host,
                        trigger,
                        PREVIOUS,
                    ),
                ).fetchall()
            else:
                earlier = []
        previous = []
        for status, completed, report in earlier:
            try:
                answer = (decode(report) or {}).get("answer")
            except Exception:
                continue
            cause, actions = _sections(answer)
            if not cause:
                continue
            previous.append(
                {
                    "completed_at": _beijing(completed),
                    "status": status,
                    "cause": _clip(cause, CAUSE_CHARS),
                    **(
                        {
                            "actions": [
                                _clip(item, ACTION_CHARS)
                                for item in actions[:ACTION_ROWS]
                            ]
                        }
                        if actions
                        else {}
                    ),
                }
            )
        if previous:
            result["previous_analyses"] = previous
    except Exception:
        log.exception("ALERT_HISTORY_FAILED event_id=%s", event_id)
        return None
    if not result:
        return None
    return {"notice": NOTICE, **result}
