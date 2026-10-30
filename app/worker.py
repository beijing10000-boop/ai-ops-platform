"""Read-only AI diagnostics worker. Never executes Zabbix mutations."""

import asyncio
import json
import logging
import os
import re
import httpx
from redis import Redis
from rq import Worker, Queue
from rq.job import Job
from .main import read_setting
from .orchestrator import queues

log = logging.getLogger(__name__)
# Immutable Feishu card output contract; diagnostic policy lives in enabled Skills.
ALERT_OUTPUT_CONTRACT = (
    "告警卡片要求只输出 JSON 对象，必须包含 "
    "host_groups,cause,action,analysis,findings,human_required 字段，另加 evidence 数组。"
    "cause 写完整中文结论（100–200 字）：证据充分的直接成因和主要依据，关键数值后注明证据编号（E2）；"
    "action 为处理建议数组，按影响与风险排序，每项一句；"
    "analysis 写证据之间的关联、排除项和尚未证实的方向（200–400 字）。"
    "findings 为对象："
    '{"confirmed":[{"statement":"已确认的事实","evidence":["E2"]}],'
    '"probable":[{"statement":"高可信推断","evidence":["E3"]}],'
    '"hypotheses":[{"statement":"待验证假设","verify":"可以怎样验证"}]}；'
    "confirmed 只放有证据编号直接证明的事实，probable 放有证据支持但未直接证实的推断，"
    "hypotheses 放尚无证据的可能原因；平台会把没有有效引用的 confirmed 降为推断。"
    "证据编号只以括号附在句末或数值后，如（E2），不要把编号当作句子的主语或宾语；"
    "目标、时间范围、告警字段、各证据数值和诊断不足由平台渲染，不要复述。"
    "evidence 每项为 "
    '{"id":"E2","quote":"从该证据原样摘录的关键数值或原文"}，列出支撑结论的 2–6 条关键证据；'
    "平台会核对 quote 是否真的出现在对应证据中，并据此评定可信度。"
    "无证据时明确写未知，不能编造事实。"
)
# Plain names for the evidence lines of the Feishu card.
TOOL_LABELS = {
    "history_get": "监控历史",
    "trend_get": "7 天趋势",
    "item_get": "监控项",
    "event_get": "告警事件",
    "problem_get": "当前问题",
    "trigger_get": "触发器",
    "host_get": "主机信息",
    "ssh_collect": "实时采集",
    "ssh_diagnose_cpu": "CPU 负载",
    "ssh_diagnose_processes": "进程排行",
    "ssh_diagnose_memory": "内存",
    "ssh_diagnose_memory_processes": "内存进程排行",
    "ssh_diagnose_pressure": "资源压力",
    "ssh_diagnose_disk": "磁盘",
    "ssh_diagnose_io": "磁盘 I/O",
    "ssh_diagnose_network": "网络接口",
    "ssh_diagnose_sockets": "端口与连接",
    "ssh_diagnose_tcp_states": "TCP 状态",
    "ssh_diagnose_oom": "OOM 记录",
    "ssh_diagnose_syslog": "系统日志",
    "ssh_diagnose_system_errors": "系统日志",
    "ssh_diagnose_kernel": "内核日志",
    "ssh_diagnose_logs": "服务日志",
    "ssh_diagnose_service": "服务状态",
    "ssh_diagnose_service_detail": "服务详情",
    "ssh_diagnose_service_map": "端口归属",
    "ssh_diagnose_failed_services": "失败服务",
    "ssh_diagnose_nginx": "Nginx 状态",
    "ssh_diagnose_nginx_access": "Nginx 访问日志",
    "ssh_diagnose_java": "Java 进程",
    "ssh_diagnose_jvm": "JVM",
    "ssh_diagnose_system": "系统信息",
}
DEVICE_NAMES = {
    "linux": "Linux",
    "windows": "Windows",
    "network": "网络设备",
    "vmware": "VMware",
    "other": "其它设备",
}
COLORS = {
    "0": "grey",
    "1": "blue",
    "2": "yellow",
    "3": "orange",
    "4": "red",
    "5": "carmine",
}
LEVELS = {
    "0": "未分类",
    "1": "信息",
    "2": "警告",
    "3": "一般严重",
    "4": "严重",
    "5": "灾难",
}


def alert_instructions() -> str:
    """Output protocol only. Skills own diagnostic guidance and tool order."""
    return ALERT_OUTPUT_CONTRACT


def cfg(key):
    return read_setting(key)


async def analyze(event, task_id=None):
    key = cfg("openai_api_key")
    model = cfg("openai_model")
    url = cfg("openai_base_url")
    if not key or not model or not url:
        raise RuntimeError("AI model configuration missing")
    # Tool calls are integrated in a separate MCP adapter; never assert MCP
    # evidence unless it has been fetched by that adapter.
    from .mcp_runtime import run

    prompt = alert_instructions()
    raw, token_usage = await run(
        prompt,
        json.dumps({"alert": event}, ensure_ascii=False),
        model=model,
        return_usage=True,
        event=event,
        task_id=task_id,
    )
    raw = raw.strip()
    try:
        data = json.loads(
            re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", raw)
        )
        if not isinstance(data, dict):
            raise ValueError("not object")
    except (ValueError, TypeError):
        data = {
            "cause": "分析结果需要人工复核",
            "action": "请检查告警相关指标及服务日志",
            "analysis": raw,
            "human_required": True,
            "host_groups": "未查到",
            "_unstructured": True,
        }
    from .mcp_runtime import numbered

    for key in ("cause", "action", "analysis"):
        if key in data:
            data[key] = numbered(data[key])
    data["_token_usage"] = token_usage
    data["_task_id"] = token_usage.get("task_id")
    if data["_task_id"]:
        from .orchestrator import tasks

        task = tasks.get(data["_task_id"]) or {}
        report = task.get("report") or {}
        data["_diagnostic_status"] = task.get("status")
        data["_report_answer"] = report.get("answer")
        data["_limitations"] = report.get("limitations", [])
        data["_duration_ms"] = task.get("duration_ms")
        citations = report.get("citations") or {}
        data["_evidence"] = list(citations.get("valid") or [])[:6]
        data["_confidence"] = citations.get("confidence")
        data["_capabilities"] = report.get("capabilities") or {}
    return data


def alert_profile(event):
    """Automatic analysis of low-severity or matched host-group alerts runs quick."""
    default = cfg("ai_analysis_profile") or "standard"
    try:
        ceiling = int(cfg("ai_quick_severity_max") or "-1")
        severity = int(event.get("severity") or 0)
    except ValueError:
        return default
    groups = str(event.get("host_groups") or "")
    keywords = [
        word.strip()
        for word in (cfg("ai_quick_host_groups") or "").split(",")
        if word.strip()
    ]
    if severity <= ceiling or any(word in groups for word in keywords):
        return "quick"
    return default


def recent_analysis(event):
    """A finished analysis of the same host and trigger within the reuse window."""
    from .main import beijing_time, connection

    host = str(event.get("host_id") or "")
    trigger = str(event.get("trigger_id") or "")
    try:
        hours = int(cfg("ai_alert_reuse_hours") or "0")
    except ValueError:
        hours = 0
    if hours <= 0 or not (host.isdigit() and trigger.isdigit()):
        return None
    with connection() as db:
        row = db.execute(
            "SELECT t.task_id,t.completed_at FROM diagnostic_tasks t "
            "JOIN alert_events a ON a.event_id=t.event_id AND a.event_value='1' "
            "WHERE t.kind='analysis' AND t.status IN ('success','partial') "
            "AND t.completed_at >= datetime('now', ?) AND t.event_id != ? "
            "AND json_extract(a.event_json,'$.host_id')=? "
            "AND json_extract(a.event_json,'$.trigger_id')=? "
            "ORDER BY t.completed_at DESC LIMIT 1",
            ("-" + str(hours) + " hours", str(event.get("event_id")), host, trigger),
        ).fetchone()
        if not row:
            return None
        occurrences = db.execute(
            "SELECT COUNT(*) FROM alert_events WHERE event_value='1' "
            "AND received_at >= datetime('now','-24 hours') "
            "AND json_extract(event_json,'$.host_id')=? "
            "AND json_extract(event_json,'$.trigger_id')=?",
            (host, trigger),
        ).fetchone()[0]
    return {
        "task_id": row[0],
        "completed": beijing_time(row[1]),
        "hours": hours,
        "occurrences": occurrences,
    }


def daily_budget():
    """(used, limit) Token of today's automatic alert analyses, or None if unlimited.

    Manual analyses carry the clicking user as actor and are not counted;
    analyses still running have no Token total yet.
    """
    from .main import connection

    try:
        limit = int(cfg("ai_daily_token_limit") or "0")
    except ValueError:
        return None
    if limit <= 0:
        return None
    with connection() as db:
        used = db.execute(
            "SELECT COALESCE(SUM(token_total),0) FROM diagnostic_tasks "
            "WHERE source='alert' AND actor='system' "
            "AND date(created_at,'+8 hours')=date('now','+8 hours')"
        ).fetchone()[0]
    return used, limit


def enqueue_analysis(queue_name, func, event, *args, profile_name=None, actor="system"):
    """Create the queued task before its job, so the active-task index refuses
    duplicates while the job waits. Returns (task, created)."""
    from .main import REDIS_URL
    from .mcp_runtime import create_task
    from .orchestrator import tasks

    redis = Redis.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=3)
    question = json.dumps({"alert": event}, ensure_ascii=False)
    task, created = create_task(question, event, profile_name, actor)
    if (
        not created
        and task["status"] == "queued"
        and not Job.exists(task["task_id"], connection=redis)
    ):
        # A queued task whose job vanished (e.g. Redis data lost) would block
        # this event forever; close it and queue a fresh one.
        tasks.finish(
            task["task_id"],
            {"message": "排队中的分析任务已丢失，已重新提交"},
            status="failed",
            error_type="QueueLost",
        )
        task, created = create_task(question, event, profile_name, actor)
    if not created:
        return task, False
    try:
        Queue(queue_name, connection=redis).enqueue(
            func,
            event,
            *args,
            task["task_id"],
            job_id=task["task_id"],
            # The runtime enforces the task's saved deadline; no second fixed cap.
            job_timeout=-1,
            result_ttl=86400,
        )
    except Exception:
        tasks.finish(
            task["task_id"],
            {"message": "任务入队失败，请检查 Redis 后重试"},
            status="failed",
            error_type="QueueUnavailable",
        )
        raise
    return task, True


def safe(value, n):
    return str(value or "未提供").replace("\n", " ")[:n]


def report_url(info):
    from urllib.parse import urlsplit

    task_id = str(
        info.get("_task_id") or (info.get("_token_usage") or {}).get("task_id") or ""
    )
    if not re.fullmatch(r"[0-9a-f]{32}", task_id):
        return ""
    scheme = cfg("web_protocol") or "http"
    host = cfg("web_public_host")
    parts = urlsplit(scheme + "://" + host)
    if (
        scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path
        or parts.query
        or parts.fragment
    ):
        return ""
    return scheme + "://" + parts.netloc + "/#report/" + task_id


def in_feishu(url):
    """AppLink that opens the page inside the Feishu client (built-in browser,
    a separate window on PC) instead of handing it to the system browser."""
    from urllib.parse import quote

    return "https://applink.feishu.cn/client/web_url/open?mode=window&url=" + quote(
        url, safe=""
    )


def analysis_summary(info):
    """Use the complete canonical report; transport handles byte-size segmentation."""
    from .mcp_runtime import readable_report_answer

    status = {"success": "已完成", "partial": "部分完成", "failed": "失败"}.get(
        info.get("_diagnostic_status")
    )
    body = ("**诊断状态**  " + status + "\n\n") if status else ""
    answer = info.get("_report_answer") or readable_report_answer(
        json.dumps(
            {
                key: info.get(key)
                for key in ("cause", "action", "analysis", "human_required")
            },
            ensure_ascii=False,
        )
    )
    body += answer
    if info.get("_limitations"):
        body += "\n\n**诊断不足与待核验**\n" + "\n".join(
            "- " + str(item) for item in info["_limitations"]
        )
    from .report_presentation import human_metrics

    return human_metrics(body)


EVIDENCE_REF = re.compile(
    r"\s*[（(]\s*E\d{1,3}(?:\s*[、,，/–\-和及与]\s*E\d{1,3})*\s*[)）]"
    r"|(?<![A-Za-z0-9])E\d{1,3}(?![A-Za-z0-9\-])"
)


def without_evidence_ids(text):
    """Evidence numbers only mean something next to the Web report's evidence list."""
    text = EVIDENCE_REF.sub("", str(text or ""))
    text = re.sub(r"[ \t]+(?=[，。；：、）)])", "", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


def source_line(info):
    """Which data sources the conclusion rests on, and which were unavailable."""
    caps = info.get("_capabilities") or {}
    path = caps.get("diagnostic_path")
    if not path:
        return ""
    device = DEVICE_NAMES.get(caps.get("device_type"))
    ssh = caps.get("ssh_mcp") or {}
    text = {
        "zabbix+ssh": "Zabbix 历史 + SSH 实时",
        "zabbix-only": "仅 Zabbix 监控数据",
        "ssh-only": "仅 SSH 实时数据",
        "none": "未取得监控或实时数据",
    }.get(path, "")
    if path == "zabbix-only" and ssh.get("status") not in (None, "used", "available"):
        reason = str(ssh.get("reason") or "").strip()
        if ssh.get("status") == "not_applicable" and device:
            reason = f"{device} 不做 SSH 诊断"
        if reason:
            text += "（" + clipped(reason, 40) + "）"
    elif device:
        text += "（" + device + "）"
    confidence = info.get("_confidence")
    return text + (f" · 依据可信度 {confidence}" if confidence else "")


def evidence_lines(info, limit=4):
    """The checked citations as short plain lines, without evidence ids."""
    lines = []
    for item in info.get("_evidence") or []:
        if not isinstance(item, dict) or not str(item.get("quote") or "").strip():
            continue
        label = TOOL_LABELS.get(str(item.get("tool")), str(item.get("tool") or ""))
        source = "SSH" if item.get("provider") == "ssh_mcp" else "Zabbix"
        quote = clipped(without_evidence_ids(str(item["quote"])), 70)
        lines.append(f"· {source} {label}：{quote}")
        if len(lines) == limit:
            break
    return lines


def card_summary(info):
    """Feishu card body: conclusion, the key checked evidence with the data
    sources, actions and (as room allows) the analysis, plus the status when
    not clean.

    Scope, the full citation check and limitations stay on the Web report the
    card links to; the conversation context keeps the full analysis_summary().
    """
    from .mcp_runtime import numbered
    from .report_presentation import human_metrics

    status = info.get("_diagnostic_status")
    lines = []
    if status in ("partial", "failed"):
        lines.append("**诊断状态**  " + ("部分完成" if status == "partial" else "失败"))
    if info.get("_unstructured"):
        # No structured answer (model error fallback, plain text): its first
        # line carries the reason; the collected evidence is on the Web report.
        first = str(info.get("analysis") or "").strip().split("\n", 1)[0]
        lines += [
            "**诊断结论**",
            first or "模型未给出结论。",
            "",
            "**处理建议**",
            "请打开完整诊断报告核验已采集的证据，必要时重新发起分析。",
        ]
    else:
        full = without_evidence_ids(numbered(info.get("cause")))
        cause = clipped(full, CAUSE_CHARS)
        if cause != full:
            cause += "（详见完整报告）"
        budget = CARD_CHARS - len(cause)
        lines += ["**诊断结论**", cause or "未知"]
        proof = evidence_lines(info)
        sources = source_line(info)
        if proof or sources:
            lines += ["", "**核心证据**" + (f"  {sources}" if sources else "")]
            lines += proof or ["未取得通过核对的证据引用，结论请在完整报告中核验。"]
            budget -= len(sources) + sum(len(line) for line in proof or [""]) + 8
        actions = [
            line.strip()
            for line in without_evidence_ids(numbered(info.get("action"))).split("\n")
            if line.strip()
        ]
        kept = []
        for index, item in enumerate(actions):
            if index == ACTION_ROWS or (kept and len(item) > budget):
                kept.append("其余建议见完整诊断报告。")
                budget -= len(kept[-1])
                break
            kept.append(clipped(item, max(budget, 40)))
            budget -= len(kept[-1])
        lines += ["", "**处理建议**"]
        lines += kept or ["无"]
        analysis = without_evidence_ids(numbered(info.get("analysis")))
        if analysis and budget >= ANALYSIS_MIN:
            shown = clipped(analysis, budget)
            if shown != analysis:
                shown += "（详见完整报告）"
            lines += ["", "**分析与依据**", shown]
    return human_metrics("\n".join(lines))


# Body text of the card: conclusion first, the key evidence and actions next,
# the analysis takes what is left; with headings it stays within ~1000 characters.
CARD_CHARS, CAUSE_CHARS, ACTION_ROWS, ANALYSIS_MIN = 1000, 400, 8, 80


def clipped(text, limit):
    """Cut long text at the last sentence end within the limit, else with an ellipsis."""
    if len(text) <= limit:
        return text
    cut = max(text.rfind(mark, 0, limit) for mark in "。；！？")
    return text[: cut + 1] if cut >= limit // 2 else text[: limit - 1].rstrip() + "…"


def valid_macro(value):
    """Suppress unresolved Zabbix macros, empty values and display placeholders."""
    value = str(value or "").strip()
    return (
        value
        if value
        and "{" not in value
        and value not in ("待查询", "未查到", "未提供", "UNKNOWN")
        else ""
    )


def event_duration(event):
    """Use Zabbix duration macro; derive it from event times only if absent."""
    value = valid_macro(event.get("event_duration"))
    if value:
        return value[:80]
    try:
        from datetime import datetime

        began = datetime.strptime(
            event["event_date"] + " " + event["event_time"], "%Y.%m.%d %H:%M:%S"
        )
        ended = datetime.strptime(
            event["recovery_date"] + " " + event["recovery_time"], "%Y.%m.%d %H:%M:%S"
        )
        seconds = int((ended - began).total_seconds())
        if seconds < 0:
            return ""
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        return (
            f"{days}天 " if days else ""
        ) + f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except (KeyError, ValueError, TypeError):
        return ""


def zabbix_event_link(event):
    """Link only to a validated event/trigger pair; never accept arbitrary URLs."""
    event_id = str(event.get("event_id") or "")
    trigger_id = str(event.get("trigger_id") or "")
    if not (event_id.isdigit() and trigger_id.isdigit()):
        return ""
    from urllib.parse import urlencode, urlsplit

    base = read_setting("zabbix_frontend_url").strip().rstrip("/")
    parts = urlsplit(base)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        return ""
    return (
        base
        + "/tr_events.php?"
        + urlencode({"triggerid": trigger_id, "eventid": event_id})
    )


def make_card(event, info=None, *, analysis=False, mute_info=None):
    """Mobile-friendly, compact ops event; separate rich severe AI analysis."""
    info = info or {}
    sev = str(event.get("severity", "0"))
    recovery = str(event.get("event_value", "1")) == "0"
    title = "告警恢复" if recovery else LEVELS.get(sev, "未知")
    if analysis and not recovery:
        title = LEVELS.get(sev, "未知") + "｜AI 分析结果"
    groups = valid_macro(event.get("host_groups")) or valid_macro(
        info.get("host_groups")
    )
    event_name = valid_macro(event.get("event_name")) or "未知事件"
    lines = [
        "**主机名称**  " + safe(event.get("host_name"), 80),
        "**主机 IP**  " + safe(event.get("host_ip"), 50),
    ]
    if groups:
        lines.append("**所属分组**  " + safe(groups, 180))
    if recovery:
        started = valid_macro(event.get("event_date")) and valid_macro(
            event.get("event_time")
        )
        if started:
            lines.append(
                "**告警时间**  " + event["event_date"] + " " + event["event_time"]
            )
        recovery_date = valid_macro(event.get("recovery_date"))
        recovery_time = valid_macro(event.get("recovery_time"))
        if recovery_date and recovery_time:
            lines.append("**恢复时间**  " + recovery_date + " " + recovery_time)
        duration = event_duration(event)
        if duration:
            lines.append("**持续时间**  " + duration)
    else:
        occurred_date = valid_macro(event.get("event_date"))
        occurred_time = valid_macro(event.get("event_time"))
        if occurred_date and occurred_time:
            lines.append("**发生时间**  " + occurred_date + " " + occurred_time)
    event_value_text = valid_macro(event.get("latest_value"))
    lines.extend(
        [
            "**事件名称**  " + safe(event_name, 250),
            "**事件数值**  " + safe(event_value_text, 300),
            "**事件 ID**  " + safe(event.get("event_id"), 40),
        ]
    )
    link = zabbix_event_link(event)
    elements = [{"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(lines)}}]
    if info.get("note") and not analysis and not recovery:
        # Why no automatic analysis follows (reused recent one, daily budget).
        elements.append(
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": "**AI 分析**  " + safe(info["note"], 600),
                },
            }
        )
    if not analysis:
        host_id = str(event.get("host_id") or "")
        trigger_id = str(event.get("trigger_id") or "")
        event_id = str(event.get("event_id") or "")
        actions = []
        if link:
            actions.append(
                {
                    "tag": "button",
                    "text": {"tag": "plain_text", "content": "🔗 事件来源"},
                    "type": "default",
                    "url": link,
                }
            )
        if event_id.isdigit() and trigger_id.isdigit():
            from .alert_mute import action_signature

            actions.append(
                {
                    "tag": "button",
                    "text": {"tag": "plain_text", "content": "🤖 AI分析"},
                    "type": "primary",
                    "value": {
                        "op": "analyze_alert",
                        "event_id": event_id,
                        "trigger_id": trigger_id,
                        "event_value": "0" if recovery else "1",
                        "sig": action_signature(event_id, trigger_id, 0),
                    },
                }
            )
            if not recovery and host_id.isdigit():
                actions.append(
                    {
                        "tag": "button",
                        "text": {"tag": "plain_text", "content": "🔕 暂时屏蔽"},
                        "type": "default",
                        "value": {
                            "op": "choose_mute",
                            "event_id": event_id,
                            "trigger_id": trigger_id,
                            "sig": action_signature(event_id, trigger_id, 0),
                        },
                    }
                )
        if actions:
            elements.append({"tag": "hr"})
            elements.append({"tag": "action", "actions": actions})
    if mute_info and not recovery:
        elements.append({"tag": "hr"})
        mute_section = {
            "tag": "div",
            "text": {
                "tag": "lark_md",
                "content": "**屏蔽信息**\n**操作人**  "
                + safe(mute_info.get("operator"), 100)
                + "\n**屏蔽时长**  "
                + safe(mute_info.get("duration"), 30)
                + "\n**操作时间**  "
                + safe(mute_info.get("time"), 40)
                + "\n**到期时间**  "
                + safe(mute_info.get("expires"), 40),
            },
        }
        if mute_info.get("active", True):
            from .alert_mute import action_signature

            host_id, trigger_id, event_id = (
                str(event.get(k) or "") for k in ("host_id", "trigger_id", "event_id")
            )
            if host_id.isdigit() and trigger_id.isdigit() and event_id.isdigit():
                mute_section["extra"] = {
                    "tag": "button",
                    "text": {"tag": "plain_text", "content": "关闭屏蔽"},
                    "type": "danger",
                    "value": {
                        "op": "unmute_alert",
                        "host_id": host_id,
                        "trigger_id": trigger_id,
                        "event_id": event_id,
                        "sig": action_signature(event_id, trigger_id, 0),
                    },
                }
        elements.append(mute_section)
    if analysis and not recovery:
        elements.append({"tag": "hr"})
        elements.append(
            {
                "tag": "div",
                "text": {"tag": "lark_md", "content": card_summary(info)},
            }
        )
        detail_url = report_url(info)
        if detail_url:
            elements.append(
                {
                    "tag": "action",
                    "actions": [
                        {
                            "tag": "button",
                            "text": {
                                "tag": "plain_text",
                                "content": "查看完整诊断报告",
                            },
                            "type": "default",
                            "url": in_feishu(detail_url),
                        }
                    ],
                }
            )
    if analysis:
        from .mcp_runtime import format_usage

        elements.append({"tag": "hr"})
        elements.append(
            {
                "tag": "note",
                "elements": [
                    {
                        "tag": "plain_text",
                        "content": "◉ "
                        + format_usage(
                            info.get("_token_usage"),
                            duration_ms=info.get("_duration_ms"),
                        ),
                    }
                ],
            }
        )
    return {
        "config": {"wide_screen_mode": True, "update_multi": True},
        "header": {
            "title": {"tag": "plain_text", "content": title},
            "template": "green" if recovery else COLORS.get(sev, "grey"),
        },
        "elements": elements,
    }


async def notify(card, event=None, *, analysis_info=None):
    """Send alert cards solely through the configured Feishu enterprise app."""
    if cfg("feishu_enabled").lower() != "true":
        log.warning("FEISHU_APP_ALERT_DISABLED")
        return
    from .feishu_client import get_token, send_rendered_card

    ids = cfg("feishu_alert_chat_ids") or cfg("allowed_chat_ids")
    chats = list(dict.fromkeys(x.strip() for x in ids.split(",") if x.strip()))
    if not chats:
        raise RuntimeError("未配置飞书企业应用告警群 Chat ID")
    errors = []
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        for chat_id in chats:
            try:
                original_id = None
                if event and (
                    str(event.get("event_value", "1")) == "0"
                    or analysis_info is not None
                ):
                    from .main import connection

                    with connection() as db:
                        row = db.execute(
                            "SELECT message_id FROM alert_message_links WHERE event_id=? AND chat_id=?",
                            (str(event["event_id"]), chat_id),
                        ).fetchone()
                    original_id = row[0] if row else None
                    if not original_id:
                        log.info(
                            "FEISHU_RECOVERY_NO_ORIGINAL event_id=%s chat_prefix=%s",
                            event["event_id"],
                            chat_id[:5],
                        )
                        continue
                response = await send_rendered_card(
                    client, token, card, chat_id=chat_id, reply_to=original_id
                )
                if not original_id:
                    if (
                        event
                        and str(event.get("event_value", "1")) == "1"
                        and analysis_info is None
                    ):
                        message_id = (response.get("data") or {}).get("message_id")
                        if not message_id:
                            raise RuntimeError(
                                "Feishu did not return original alert message ID"
                            )
                        from .main import connection

                        with connection() as db:
                            db.execute(
                                "INSERT INTO alert_message_links(event_id,chat_id,message_id) VALUES (?,?,?) "
                                "ON CONFLICT(event_id,chat_id) DO UPDATE SET message_id=excluded.message_id",
                                (str(event["event_id"]), chat_id, message_id),
                            )
                if event:
                    from .integrations.feishu_links import remember as remember_link

                    result_id = (response.get("data") or {}).get("message_id")
                    remember_link(
                        event,
                        chat_id,
                        result_id,
                        "analysis"
                        if analysis_info is not None
                        else "recovery"
                        if str(event.get("event_value")) == "0"
                        else "problem",
                    )
                    if analysis_info is not None and result_id:
                        from .conversation_context import remember

                        source = make_card(event)
                        origin = source["elements"][0]["text"]["content"]
                        remember(
                            chat_id,
                            original_id or result_id,
                            result_id,
                            str(event.get("event_name", "告警分析")),
                            analysis_summary(analysis_info),
                            parent_context={
                                "origin": origin,
                                "turns": [],
                                "event": event,
                            },
                            root_id=original_id or result_id,
                        )
                log.info(
                    "FEISHU_APP_ALERT_SENT chat_id_prefix=%s reply=%s",
                    chat_id[:5],
                    bool(original_id),
                )
            except Exception as exc:
                log.error(
                    "FEISHU_APP_ALERT_FAILED chat_id_prefix=%s error=%s",
                    chat_id[:5],
                    type(exc).__name__,
                )
                errors.append(chat_id[:5])
    if errors:
        raise RuntimeError("企业应用告警有群发送失败，数量：" + str(len(errors)))


def initial_info(event):
    recovery = str(event.get("event_value", "1")) == "0"
    return {
        "host_groups": "待查询",
        "cause": "Zabbix 告警恢复" if recovery else "Zabbix 监控触发告警",
        "action": "可查看 Zabbix 事件详情" if recovery else "请检查告警主机及监控项",
        "analysis": "恢复通知，无需 AI 分析"
        if recovery
        else "原始事件通知；达到 AI 分析门槛后另发分析结果",
        "human_required": not recovery,
    }


def store_alert_usage(event, usage):
    from .main import connection, save_token_usage

    with connection() as db:
        save_token_usage(
            db,
            "alert_events",
            "event_id=? AND event_value=?",
            (str(event.get("event_id")), str(event.get("event_value", "1"))),
            usage,
        )


def ai_state(info):
    """Alert-list AI status from the diagnosis itself, not from card delivery."""
    status = (info or {}).get("_diagnostic_status")
    return {"partial": "partial", "failed": "failed"}.get(status, "success")


def update_event(event, **states):
    from .main import connection

    allowed = {"notify_status", "ai_status"}
    changes = {key: value for key, value in states.items() if key in allowed}
    if not changes:
        return
    with connection() as db:
        db.execute(
            "UPDATE alert_events SET "
            + ", ".join(key + "=?" for key in changes)
            + " WHERE event_id=? AND event_value=?",
            (
                *changes.values(),
                str(event["event_id"]),
                str(event.get("event_value", "1")),
            ),
        )


async def handle_alert(event):
    # Delivery and AI diagnostics are separate: do not wait for the model
    # before sending the initial alert.
    severity = int(event.get("severity", "0"))
    recovery = str(event.get("event_value", "1")) == "0"
    info = initial_info(event)
    if recovery:
        # A recovery is only useful in Feishu if its original problem was
        # actually delivered. Muted/failed/disabled/unknown problems are silent.
        from .main import connection

        with connection() as db:
            previous = db.execute(
                "SELECT notify_status FROM alert_events WHERE event_id=? AND event_value='1'",
                (str(event.get("event_id", "")),),
            ).fetchone()
        if not previous or previous[0] != "sent":
            update_event(
                event, notify_status="suppressed_unpaired", ai_status="not_required"
            )
            log.info(
                "FEISHU_RECOVERY_SUPPRESSED_UNPAIRED event_id=%s previous_status=%s",
                event.get("event_id"),
                previous[0] if previous else "missing",
            )
            return {
                "event_id": event["event_id"],
                "notified": False,
                "recovery_suppressed": True,
                "ai_skipped": True,
            }
    if not recovery:
        from .main import connection
        import time

        host_id = str(event.get("host_id") or "")
        trigger_id = str(event.get("trigger_id") or "")
        if host_id.isdigit() and trigger_id.isdigit():
            with connection() as db:
                muted = db.execute(
                    "SELECT 1 FROM alert_mutes WHERE host_id=? AND trigger_id=? AND expires_at>?",
                    (host_id, trigger_id, int(time.time())),
                ).fetchone()
            if muted:
                update_event(event, notify_status="muted", ai_status="not_required")
                log.info("FEISHU_ALERT_MUTED event_id=%s", event.get("event_id"))
                return {"event_id": event["event_id"], "notified": False, "muted": True}
    threshold = int(cfg("ai_min_severity") or "4")
    # Decide before notifying, so a skip reason rides on the original card
    # instead of another message.
    plan = None if recovery or severity < threshold else "analyze"
    reused = budget = None
    if plan:
        reused = recent_analysis(event)
        budget = None if reused else daily_budget()
        if reused:
            plan = "reuse"
            url = report_url({"_task_id": reused["task_id"]})
            info["note"] = (
                f"近 {reused['hours']} 小时内同一主机、同一触发器已完成 AI 分析"
                f"（{reused['completed']}），近 24 小时共 {reused['occurrences']} 次告警，"
                "本次不重复分析。"
                + (f"[查看该次报告]({in_feishu(url)})。" if url else "")
                + "需要重新分析可点击“AI分析”。"
            )
        elif budget and budget[0] >= budget[1]:
            plan = "budget"
            info["note"] = (
                f"今日自动 AI 分析已用 {budget[0]:,} Token，达到每日上限 {budget[1]:,}，"
                "本告警未自动分析；需要时可点击“AI分析”手动发起。"
            )
    try:
        await notify(make_card(event, info), event=event)
        update_event(
            event,
            notify_status="sent"
            if cfg("feishu_enabled").lower() == "true"
            else "disabled",
        )
    except Exception:
        update_event(event, notify_status="failed")
        log.exception(
            "INITIAL_ALERT_DELIVERY_FAILED event_id=%s", event.get("event_id")
        )
        raise
    if plan != "analyze":
        if plan:
            update_event(
                event, ai_status="reused" if plan == "reuse" else "skipped_budget"
            )
        return {
            "event_id": event["event_id"],
            "notified": True,
            "diagnosed": False,
            "ai_skipped": True,
            **({"reused_task_id": reused["task_id"]} if reused else {}),
            **({"budget_exhausted": True} if plan == "budget" else {}),
        }
    # Analysis runs on its own workers so the next alert's notification never
    # waits behind a model call.
    try:
        task, queued = enqueue_analysis(
            queues.ALERT_ANALYSIS,
            "app.worker.process_alert_analysis",
            event,
            profile_name=alert_profile(event),
        )
    except Exception as exc:
        update_event(event, ai_status="failed")
        log.warning(
            "ALERT_ANALYSIS_ENQUEUE_FAILED event_id=%s error=%s",
            event.get("event_id"),
            type(exc).__name__,
        )
        return {
            "event_id": event["event_id"],
            "notified": True,
            "diagnosed": False,
            "ai_failed": True,
        }
    if not queued:
        log.info(
            "ALERT_ANALYSIS_ALREADY_ACTIVE event_id=%s task_id=%s",
            event.get("event_id"),
            task["task_id"],
        )
    return {
        "event_id": event["event_id"],
        "notified": True,
        "diagnosed": False,
        "analysis_queued": queued,
        "task_id": task["task_id"],
    }


async def handle_alert_analysis(event, task_id=None):
    update_event(event, ai_status="running")
    try:
        analysis = await analyze(event, task_id)
        store_alert_usage(event, analysis.get("_token_usage"))
    except Exception as exc:
        update_event(event, ai_status="failed")
        log.warning(
            "ALERT_ANALYZE_FAILED event_id=%s error=%s",
            event.get("event_id"),
            type(exc).__name__,
        )
        # Initial notification already arrived. Avoid flooding the same group
        # with another card when the model is unavailable.
        return {
            "event_id": event["event_id"],
            "notified": True,
            "diagnosed": False,
            "ai_failed": True,
        }
    try:
        await notify(
            make_card(event, analysis, analysis=True),
            event=event,
            analysis_info=analysis,
        )
        update_event(event, ai_status=ai_state(analysis))
    except Exception:
        update_event(event, ai_status="failed")
        log.exception("AI_ANALYSIS_DELIVERY_FAILED event_id=%s", event.get("event_id"))
        raise
    return {"event_id": event["event_id"], "notified": True, "diagnosed": True}


def process_alert(event):
    return asyncio.run(handle_alert(event))


def task_still_queued(task_id):
    """Skip jobs whose task was cancelled while waiting, like diagnostic_worker."""
    if task_id is None:
        return True  # Jobs queued before v0.9.9 create their task when they run.
    from .orchestrator import tasks

    task = tasks.get(task_id)
    return bool(task) and task["status"] == "queued"


def process_alert_analysis(event, task_id=None):
    if not task_still_queued(task_id):
        update_event(event, ai_status="cancelled")
        return {"event_id": event.get("event_id"), "skipped": True}
    return asyncio.run(handle_alert_analysis(event, task_id))


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    redis = Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
    # `python -m app.worker analysis` serves manual clicks before automatic analysis.
    names = (
        [queues.ALERT_MANUAL, queues.ALERT_ANALYSIS]
        if sys.argv[1:] == ["analysis"]
        else [queues.ALERTS]
    )
    Worker([Queue(name, connection=redis) for name in names], connection=redis).work()


async def analyze_on_demand(event, message_id, chat_id=None, task_id=None):
    """Fault and recovery: reply with progress, update it, preserve threaded context."""
    from .feishu_client import reply_card, update_card
    from .conversation_context import remember, mark_pending, clear_pending

    if not message_id or not str(message_id).startswith("om_"):
        raise ValueError("missing original Feishu message id")
    event_id = str(event.get("event_id") or "")
    is_recovery = str(event.get("event_value", "1")) == "0"
    subject = ("恢复事件" if is_recovery else "故障事件") + " " + event_id
    question = (
        subject
        + "："
        + str(event.get("event_name") or "未知事件")
        + "；主机："
        + str(event.get("host_name") or "")
        + "；IP："
        + str(event.get("host_ip") or "")
        + "；Host ID："
        + str(event.get("host_id") or "")
    )
    # Resolve known delivery chat before creating the progress card, so replies
    # while AI is running can be rejected without an extra Feishu API request.
    if not chat_id:
        from .main import connection

        with connection() as db:
            rows = db.execute(
                "SELECT chat_id FROM alert_message_links WHERE event_id=? AND message_id=?",
                (event_id, message_id),
            ).fetchall()
        if len(rows) == 1:
            chat_id = rows[0][0]
    update_event(event, ai_status="running")
    progress_id = None
    try:
        progress_id = await reply_card(
            message_id,
            "AI 分析中",
            "**分析对象**  "
            + question[:240]
            + "\n\n⏳ 正在查询后台MCP服务并进行分析……",
        )
        if chat_id:
            mark_pending(chat_id, progress_id)
        log.info(
            "ALERT_AI_PROGRESS_SENT event_id=%s recovery=%s", event_id, is_recovery
        )
    except Exception:
        log.exception("ALERT_AI_PROGRESS_FAILED event_id=%s", event_id)
    try:
        result = await analyze(event, task_id)
        store_alert_usage(event, result.get("_token_usage"))
        # The card shows the conclusion and actions; the full summary is kept
        # as conversation context so follow-up questions see the analysis.
        detail = analysis_summary(result)
        card = card_summary(result)
        detail_url = report_url(result)
        if detail_url:
            card += "\n\n[查看完整诊断报告](" + in_feishu(detail_url) + ")"
        from .mcp_runtime import format_usage

        card += "\n\n---\n" + format_usage(
            result.get("_token_usage"), duration_ms=result.get("_duration_ms")
        )
        if progress_id:
            try:
                await update_card(progress_id, "AI 分析结果", card)
            except Exception:
                log.exception("ALERT_AI_CARD_UPDATE_FAILED event_id=%s", event_id)
                progress_id = await reply_card(message_id, "AI 分析结果", card)
        else:
            progress_id = await reply_card(message_id, "AI 分析结果", card)
        try:
            # A Feishu GET /im/v1/messages/{id} may return 400 even when
            # reply and PATCH succeed. Use the verified delivery link instead.
            if not chat_id:
                from .main import connection

                with connection() as db:
                    rows = db.execute(
                        "SELECT chat_id FROM alert_message_links WHERE event_id=? AND message_id=?",
                        (event_id, message_id),
                    ).fetchall()
                    if not rows:
                        rows = db.execute(
                            "SELECT DISTINCT chat_id FROM alert_message_links WHERE event_id=?",
                            (event_id,),
                        ).fetchall()
                if len(rows) == 1:
                    chat_id = rows[0][0]
                else:
                    log.warning(
                        "ALERT_AI_CONTEXT_CHAT_AMBIGUOUS event_id=%s matches=%s",
                        event_id,
                        len(rows),
                    )
            if chat_id:
                from .integrations.feishu_links import remember as remember_link

                remember_link(event, chat_id, progress_id, "analysis")
                # Use the actual visible alert card text, not a guessed summary.
                source_card = make_card(event)
                original = (
                    str(source_card["header"]["title"]["content"])
                    + "\\n"
                    + str(source_card["elements"][0]["text"]["content"])
                )
                remember(
                    chat_id,
                    message_id,
                    progress_id,
                    question,
                    detail,
                    parent_context={"origin": original, "turns": [], "event": event},
                    root_id=message_id,
                )
                log.info(
                    "ALERT_AI_CONTEXT_SAVED event_id=%s recovery=%s",
                    event_id,
                    is_recovery,
                )
            else:
                log.warning("ALERT_AI_CONTEXT_CHAT_MISSING event_id=%s", event_id)
        except Exception:
            log.exception("ALERT_AI_CONTEXT_SAVE_FAILED event_id=%s", event_id)
        if chat_id:
            clear_pending(chat_id, progress_id)
        update_event(event, ai_status=ai_state(result))
        return {"diagnosed": True, "event_id": event_id, "reply_id": progress_id}
    except Exception:
        if chat_id:
            clear_pending(chat_id, progress_id)
        update_event(event, ai_status="failed")
        log.exception("MANUAL_AI_ANALYSIS_FAILED event_id=%s", event_id)
        if progress_id:
            try:
                await update_card(
                    progress_id, "AI 分析失败", "分析失败，请稍后重试。", "red"
                )
            except Exception:
                log.exception(
                    "ALERT_AI_FAILURE_CARD_UPDATE_FAILED event_id=%s", event_id
                )
        raise


def process_manual_analysis(event, message_id, chat_id=None, task_id=None):
    if not task_still_queued(task_id):
        update_event(event, ai_status="cancelled")
        return {"event_id": event.get("event_id"), "skipped": True}
    # Jobs queued before v0.9.9 carry no task_id; the runtime then creates one.
    return asyncio.run(analyze_on_demand(event, message_id, chat_id, task_id))
