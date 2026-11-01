"""Read-only AI diagnostics worker. Never executes Zabbix mutations."""

import asyncio
import json
import logging
import re
import time
from datetime import datetime
from urllib.parse import urlencode, urlsplit
import httpx
from redis import Redis
from rq import Worker, Queue
from rq.exceptions import NoSuchJobError
from .orchestrator.tasks import StopRequested
from rq.job import Job
from .alert_mute import action_signature
from .evidence_check import answer_object
from .main import read_setting
from .orchestrator import queues

log = logging.getLogger(__name__)
# Immutable Feishu card output contract; diagnostic policy lives in enabled Skills.
ALERT_OUTPUT_CONTRACT = (
    "告警卡片要求只输出 JSON 对象，必须包含 "
    "host_groups,cause,action,analysis,findings,human_required 字段，另加 evidence 数组；"
    "输出前核对括号成对闭合，字符串内不要换行。"
    "cause 显示在飞书卡片上：写一段完整中文结论（60–150 字），不分点、不换行，"
    "写清证据充分的直接成因和 2–3 个关键数值，关键数值后注明证据编号（E2）；"
    "action 为处理建议数组，2–4 项，按影响与风险排序，每项一句、不超过 50 字，"
    "写能直接执行的操作：要查的命令或指标、要处理的进程、服务或配置项；"
    "不写“持续观察”“必要时评估”“打开报告核验”这类没有具体动作的建议；"
    "analysis 只在网页报告显示，写证据之间的关联、排除项和尚未证实的方向（200–400 字）。"
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


# Names models give the card fields instead of the contract's.
FIELD_ALIASES = {
    "cause": ("conclusion", "summary", "diagnosis", "root_cause", "结论", "诊断结论"),
    "action": (
        "actions",
        "suggestions",
        "recommendations",
        "advice",
        "steps",
        "处理建议",
        "建议",
    ),
    "analysis": ("details", "reasoning", "explanation", "分析", "分析与依据"),
}
# Keys that make a JSON object in the answer the card's, under either name.
CARD_KEYS = (
    *FIELD_ALIASES,
    *(name for names in FIELD_ALIASES.values() for name in names),
)


def card_fields(raw):
    """The answer's JSON object under the contract's field names, or None for
    prose and for an object holding none of the card fields (which then reads
    as text instead of an empty "model gave no conclusion" card). An object
    under the other names is found where the contract's is: alone, in a code
    fence or after a heading."""
    data = answer_object(raw)
    if data is None:
        data = answer_object(raw, CARD_KEYS)
    if data is None:
        return None
    data = dict(data)
    for key, names in FIELD_ALIASES.items():
        if not data.get(key):
            alias = next((data[name] for name in names if data.get(name)), None)
            if alias:
                data[key] = alias
    return data if any(key in data for key in FIELD_ALIASES) else None


async def analyze(event, task_id=None):
    key = cfg("openai_api_key")
    model = cfg("openai_model")
    url = cfg("openai_base_url")
    if not key or not model or not url:
        raise RuntimeError("AI model configuration missing")
    # Tool calls are integrated in a separate MCP adapter; never assert MCP
    # evidence unless it has been fetched by that adapter.
    from .mcp_runtime import numbered, run

    raw, token_usage = await run(
        alert_instructions(),
        json.dumps({"alert": event}, ensure_ascii=False),
        model=model,
        return_usage=True,
        event=event,
        task_id=task_id,
    )
    raw = raw.strip()
    data = card_fields(raw)
    if data is None:
        data = {
            "cause": "分析结果需要人工复核",
            "action": "请检查告警相关指标及服务日志",
            "analysis": raw,
            "human_required": True,
            "host_groups": "未查到",
            "_unstructured": True,
        }
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


def daily_budget(task_id=None):
    """(used, limit) Token of today's automatic alert analyses, or None if unlimited.

    Finished analyses count with the total the model reported; analyses still
    queued or running have none yet and count with their task Token budget, so
    an alert storm cannot pass this check many times before the first analysis
    ends. `task_id` is that queued analysis rechecking as it starts: it counts
    finished and already running analyses besides itself, not the ones queued
    with it (each rechecks when it starts). Manual analyses carry the clicking
    user as actor and are not counted.
    """
    from .main import connection
    from .orchestrator.budgets import PROFILES
    from .orchestrator.tasks import decode

    try:
        limit = int(cfg("ai_daily_token_limit") or "0")
    except ValueError:
        return None
    if limit <= 0:
        return None
    today = (
        "source='alert' AND actor='system' "
        "AND date(created_at,'+8 hours')=date('now','+8 hours')"
    )
    active = "('running')" if task_id else "('queued','running')"
    with connection() as db:
        used = db.execute(
            "SELECT COALESCE(SUM(token_total),0) FROM diagnostic_tasks WHERE " + today
        ).fetchone()[0]
        requests = db.execute(
            "SELECT request FROM diagnostic_tasks WHERE "
            + today
            + " AND status IN "
            + active
            + " AND task_id!=?",
            (task_id or "",),
        ).fetchall()
    for (request,) in requests:
        limits = (decode(request) or {}).get("limits") or {}
        used += limits.get("tokens") or PROFILES["standard"]["tokens"]
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


def event_text(value, n):
    """An alert field for a lark_md card. Zabbix values can be log lines, so
    markup in them is shown as text."""
    return lark_safe(safe(value, n))


def report_base():
    """scheme://host of the Web reports, or "" when the host is not usable."""
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
    return scheme + "://" + parts.netloc


def report_url(info):
    task_id = str(
        info.get("_task_id") or (info.get("_token_usage") or {}).get("task_id") or ""
    )
    if not re.fullmatch(r"[0-9a-f]{32}", task_id):
        return ""
    base = report_base()
    return base + "/#report/" + task_id if base else ""


def analysis_summary(info):
    """Use the complete canonical report; transport handles byte-size segmentation."""
    from .mcp_runtime import readable_report_answer
    from .report_presentation import human_metrics

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
    return human_metrics(body)


# Evidence ids as models write them: "（E2）", "（见 E1、E2）", "（4.00%，E2）",
# "（E3 返回为空）", "与 E2 的值". Hardware names such as E5-2680 are kept.
EVIDENCE_IDS = (
    r"(?<![A-Za-z0-9])E\d{1,3}(?:\s*[、,，/–\-和及与]\s*E\d{1,3})*(?![A-Za-z0-9\-])"
)
CITE_WORD = r"(?:(?:证据|见|参见|来源|依据)\s*[:：]?\s*)?"
# Removed: a bracket holding only ids, ids closing a bracket, ids after "证据".
EVIDENCE_REF = re.compile(
    r"\s*[（(\[【]\s*" + CITE_WORD + EVIDENCE_IDS + r"\s*[)）\]】]"
    r"|\s*[，,、；;]\s*" + CITE_WORD + EVIDENCE_IDS + r"(?=\s*[)）\]】])"
    r"|(?<=证据)[ \t]*" + EVIDENCE_IDS + r"[ \t]*"
)
# Any other id is part of the sentence ("参考 E3"): it reads as "证据".
BARE_EVIDENCE_REF = re.compile(r"[ \t]*" + EVIDENCE_IDS + r"[ \t]*")


def _evidence_word(match):
    text, start, end = match.string, match.start(), match.end()
    spaced = [
        0 <= at < len(text) and text[at].isascii() and text[at].isalnum()
        for at in (start - 1, end)
    ]
    return (" " if spaced[0] else "") + "证据" + (" " if spaced[1] else "")


def without_evidence_ids(text):
    """Evidence numbers only mean something next to the Web report's evidence list."""
    text = EVIDENCE_REF.sub("", str(text or ""))
    text = BARE_EVIDENCE_REF.sub(_evidence_word, text)
    text = re.sub(r"[ \t]+(?=[，。；：、）)])|(?<=[，。；：、（])[ \t]+", "", text)
    # Runs of spaces left inside a line; leading indentation stays.
    return re.sub(r"(?<=\S)[ \t]{2,}", " ", text).strip()


# Sizes human_metrics leaves as written: decimal-looking names (kB, MB, GB, TB),
# `free -h` forms (Ki, Mi, Gi, Ti) and sizes written next to Chinese text.
# Linux tools and Zabbix count these in 1024s, so they are binary sizes. Rates
# (MB/s), bits (Mb, Gb) and bare letters (4G, -Xmx512m) stay as written.
# Commas only group thousands ("1,024 MB"): a list ("16,32,64 GB") or a
# decimal comma stays as written, its last number included.
CAPACITY = re.compile(
    r"(?<![A-Za-z0-9_.])(?<!\d,)(?P<number>(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?)\s*"
    r"(?P<unit>[kK]i?B|[MT]i?B|GB|[KMGT]i)(?![A-Za-z0-9_/])"
)


def _capacity(match):
    """In GiB with two decimals; under 0.01 GiB in MiB, as human_metrics does."""
    size = float(match["number"].replace(",", "")) * 1024 ** (
        "KMGT".index(match["unit"][0].upper()) + 1
    )
    if not size:
        return "0 GiB"
    gib = size / 1024**3
    return f"{gib:.2f} GiB" if gib >= 0.01 else f"{size / 1024**2:.2f} MiB"


# The platform's hosts run without Swap on purpose, so advice to set it up and
# notes that it is absent are noise. Only text saying just that is dropped,
# and nothing when the user asked about Swap (asks_about_swap).
SWAP = r"(?:[Ss][Ww][Aa][Pp]|交换(?:分区|空间|内存))(?:\s*(?:分区|空间|文件))?"
SETUP = r"(?:配置|启用|开启|增加|添加|创建|设置|扩容|扩大|调大|分配|挂载)"
WORDS = r"[^，,；;。！？\n]"
ADVISE = r"(?:(?:建议|可以?|应(?:该|当)?|需要?|考虑|评估|酌情)\s*)*"
ASIDE = r"\s*(?:（[^）]{0,30}）|\([^)]{0,30}\))?"
# A suggestion to set up Swap anywhere in an action item ("建议配置 2 GiB
# Swap 作为缓冲").
SWAP_SETUP = re.compile(
    SETUP + WORDS + "{0,12}?" + SWAP + "|" + SWAP + WORDS + "{0,6}?" + SETUP
)
# Advice that is only that: "建议开启 swap 作为缓冲", "启用 swap 分区".
SWAP_ADVICE = ADVISE + SETUP + WORDS + "{0,12}?" + SWAP + WORDS + "{0,10}"
# A clause saying only that Swap is absent or should be set up: "且未配置 Swap",
# "Swap：未启用（总量 0 B）", "Swap 总量为 0", "建议开启 swap 作为缓冲".
SWAP_CLAUSE = re.compile(
    r"(?:且|并且|同时|另外|此外|而且|并|也|但)?\s*(?:主机|系统|服务器|节点|该机)?\s*(?:"
    + "|".join(
        (
            r"(?:未|没有|无|不)" + SETUP + r"?\s*" + SWAP,
            SWAP + r"\s*[:：]?\s*(?:均|也|都|当前)?\s*(?:未|没有|无|不)" + SETUP + "?",
            SWAP + r"\s*(?:总量|大小|容量|空间)?\s*[:：]?\s*(?:为|是)?\s*"
            r"0(?:\.0+)?\s*(?:B|KiB|MiB|GiB|kB)?",
            SWAP_ADVICE,
        )
    )
    + ")"
    + ASIDE
)
SWAP_ADVICE_PART = re.compile(SWAP_ADVICE + ASIDE)
# 或、和、并… join Swap advice to other advice ("建议增加内存或启用 swap");
# between two setup verbs they join one piece of advice ("创建并启用 Swap").
JOINER = re.compile(r"((?<!" + SETUP + r")\s*(?:或者|或|以及|和|及|并且|并|、)\s*)")
# A bare Swap after advice shares its setup verb ("增加内存和 Swap").
SWAP_NOUN = re.compile(r"(?:\d+(?:\.\d+)?\s*[KMGT]i?B?\s*)?" + SWAP)
SETUP_LEAD = re.compile(ADVISE + SETUP)
CLAUSE = re.compile(r"([^，,；;。！？!?\n]*)([，,；;。！？!?]?)")
COMMAS = ("，", ",", "；", ";")


def asks_about_swap(question):
    """A chat question about Swap itself: its answer keeps what it says of it."""
    return re.search(SWAP, str(question or "")) is not None


def without_swap_parts(text, swap):
    """`text` without its parts joined by 或、和、并… that `swap` matches, each
    with the joiner before it ("扩容内存或增加 Swap 空间" keeps "扩容内存");
    "" when no other part is left."""
    parts = JOINER.split(text)
    texts = [part.strip() for part in parts[::2]]
    drop = [
        bool(swap(part))
        or bool(n and SWAP_NOUN.fullmatch(part) and SETUP_LEAD.match(texts[n - 1]))
        for n, part in enumerate(texts)
    ]
    if not any(drop):
        return text
    kept = [
        [parts[2 * n - 1] if n else "", parts[2 * n]]
        for n, gone in enumerate(drop)
        if not gone
    ]
    if not any(part.strip() for _, part in kept):
        return ""
    kept[0][0] = ""
    return "".join(join + part for join, part in kept)


def without_swap_notes(text):
    """Drop clauses that only say Swap is absent or should be set up, and Swap
    advice joined to other advice ("建议增加内存或启用 swap" keeps "建议增加
    内存"); a clause saying anything else stays whole ("内存不足且未配置 Swap"
    is kept)."""
    lines = []
    for line in str(text).split("\n"):
        mark = LIST_MARK.match(line)
        head, body = (line[: mark.end()], line[mark.end() :]) if mark else ("", line)
        kept, changed = [], False
        for clause, end in CLAUSE.findall(body):
            parts = [part.strip() for part in JOINER.split(clause)[::2]]
            if any(parts) and all(
                SWAP_CLAUSE.fullmatch(part) for part in parts if part
            ):
                rest = ""
            else:
                rest = without_swap_parts(clause, SWAP_ADVICE_PART.fullmatch)
            if rest or not clause.strip():
                changed = changed or rest != clause
                if rest or end:
                    kept.append([rest, end])
                continue
            changed = True
            # "A，且未配置 Swap。" keeps "A。"; a sentence of only Swap goes.
            if end not in COMMAS and kept and kept[-1][1] in COMMAS:
                kept[-1][1] = end
        if changed:
            body = "".join(clause + end for clause, end in kept).strip()
            if not body:
                continue
            line = head + body
        lines.append(line)
    return "\n".join(lines)


# lark_md markup a model, a tool result or a user could slip into a card:
# mentions (<at id=all></at>), tags (<font>, <a>) and markdown links.
MD_LINK = re.compile(r"\[([^\[\]\n]*)\]\(([^()\s]*)\)")
TAG_OPEN = re.compile(r"<|&(?:lt|#0*60|#x0*3c);", re.I)


def lark_safe(text):
    """Untrusted text for a lark_md card: no mention, tag or link except to the
    platform's own reports. The platform's own markup is added after this."""
    text = str(text or "")
    if "](" in text:
        base = report_base()
        own = base + "/#report/" if base else ""
        text = MD_LINK.sub(
            lambda link: link[0] if own and link[2].startswith(own) else link[1],
            text,
        )
        # Other link forms ("[[x]](…)", "(…(…))", "( url)", '(url "title")')
        # lose their "](" to a full-width bracket, which opens no link.
        text = re.sub(
            r"\]\(" + ("(?!" + re.escape(own) + ")" if own else ""), "］(", text
        )
    return TAG_OPEN.sub("＜", text)


def feishu_text(text, keep_swap=False):
    """Model and tool text as Feishu shows it: no evidence ids, sizes in GiB,
    no Swap notes (kept when `keep_swap`: the user asked about Swap) and no
    markup it could slip into the card."""
    from .report_presentation import human_metrics

    text = CAPACITY.sub(_capacity, human_metrics(without_evidence_ids(text)))
    return lark_safe(text if keep_swap else without_swap_notes(text))


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
        "zabbix+ssh+logs": "Zabbix 历史 + SSH 实时 + 日志",
        "zabbix+logs": "Zabbix 历史 + 日志",
        "ssh+logs": "SSH 实时 + 日志",
        "logs-only": "仅日志数据",
        "none": "未取得监控或实时数据",
    }.get(path, "")
    if path in ("zabbix-only", "zabbix+logs") and ssh.get("status") not in (
        None,
        "used",
        "available",
    ):
        reason = str(ssh.get("reason") or "").strip()
        if ssh.get("status") == "not_applicable" and device:
            reason = f"{device} 不做 SSH 诊断"
        if reason:
            text += "（" + clipped(reason, 40) + "）"
    elif device:
        text += "（" + device + "）"
    confidence = info.get("_confidence")
    return text + (f" · 依据可信度 {confidence}" if confidence else "")


# The card holds the conclusion and what to do; the evidence, the analysis and
# the scope are on the Web report it links to.
CAUSE_CHARS, ACTION_ROWS, ACTION_CHARS = 200, 4, 80
LIST_MARK = re.compile(r"^\s*(?:\d{1,2}\s*[.、)）](?!\d)\s*|[-•·*]\s+)")
# Report section names, which models also write as bare heading lines.
SECTIONS = r"(?:诊断结论|诊断结果|结论|故障原因|原因分析|根因分析|处理建议|建议|分析与依据|诊断范围|证据核对)"
HEADING = re.compile(
    r"^(?:#|\x60\x60\x60)|^\*\*[^*]{1,20}\*\*[：:]?$"
    r"|^" + SECTIONS + r"(?:（[^）]{1,10}）)?[：:]?$"
)
# "诊断结论：……" on one line: the label is the card's own heading already.
CONCLUSION_LABEL = re.compile(
    r"^[#*\s]*(?:诊断结论|诊断结果|结论|故障原因)(?:（[^）]{1,10}）)?\**[：:]\s*"
)
ADVICE_HEADING = re.compile(r"^[#*\s]*(?:处理|操作|修复)?(?:建议|措施)[*：:\s]*$")
# What to do when the analysis did not finish, by the reason its answer gives.
RETRY = "在原告警卡片上点「🤖 AI分析」重新分析"
# A chat question runs again when it is asked again where it was asked.
QA_RETRY = "在群里重新发送该问题（追问告警时，回复原告警或上一条 AI 回复）"
UNFINISHED_STEPS = (
    ("请求超时", [RETRY, "反复超时时，在 系统配置 → AI 配置 调高「AI 单次请求超时」"]),
    (
        "时间预算",
        [RETRY, "反复出现时，在 系统配置 → AI 配置 调高该分析模式的「总时间（秒）」"],
    ),
    ("未形成完整结论", ["在 系统配置 → AI 配置 调高该分析模式的「最大轮次」", RETRY]),
    (
        "请求被拒绝",
        ["在 系统配置 → AI 配置 点「验证模型连接」，核对地址、模型与密钥", RETRY],
    ),
    (
        "",
        [
            "稍后" + RETRY,
            "持续失败时，在 系统配置 → AI 配置 点「验证模型连接」检查模型服务",
        ],
    ),
)
# The answer of an analysis that did not finish (evidence fallback, no final
# answer). Its pointers to the Web report ("请查看诊断不足与预算", "请在下方…
# 核验") mean nothing in Feishu, where the steps say what to do instead.
UNFINISHED = ("模型未完成最终诊断", "未形成完整结论")
REPORT_POINTER = re.compile(r"(?:请(?:在下方|查看|打开|到)|详见)[^。！？\n]*[。！？]?")


def unfinished_steps(text, retry=RETRY):
    """The steps for the reason an unfinished answer gives; `retry` is how this
    channel runs the analysis again."""
    steps = next(steps for marker, steps in UNFINISHED_STEPS if marker in text)
    return [step.replace(RETRY, retry) for step in steps]


def failure_text(exc, retry=RETRY):
    """Body of a failure card: what stopped the analysis and what to do next."""
    from .orchestrator import tasks

    if isinstance(exc, tasks.Cancelled):
        reason, steps = "分析已在平台上取消，没有形成结论。", ["需要时" + retry]
    elif isinstance(exc, tasks.AlreadyRunning):
        reason = "该告警已有分析在进行，本次没有重复执行。"
        steps = ["等待进行中的分析回复结果，或在平台「分析历史」查看进度"]
    elif not all(
        cfg(key) for key in ("openai_base_url", "openai_model", "openai_api_key")
    ):
        reason = "AI 模型尚未配置，分析没有开始。"
        steps = [
            "在 系统配置 → AI 配置 填写模型 Base URL、部署名称与 API Key，"
            "再点「验证模型连接」",
            retry,
        ]
    else:
        reason, steps = "分析失败，没有形成结论。", unfinished_steps("", retry)
    return (
        reason
        + "\n\n**处理建议**\n"
        + "\n".join(f"{n}. {step}" for n, step in enumerate(steps, 1))
    )


def action_items(value):
    """Suggestions as plain items, whether a list or numbered lines of text."""
    lines = value if isinstance(value, list) else str(value or "").splitlines()
    items = (LIST_MARK.sub("", str(line)).strip() for line in lines)
    return [item for item in items if item]


def plain_answer_parts(text, retry=RETRY):
    """Conclusion and actions of an answer that is not JSON.

    The conclusion is its first line of text (a heading, bare section name or
    code fence would show as an empty conclusion); the actions are the list
    under a heading that names suggestions. An analysis that did not finish
    gets the steps that address why, never a bare "check the report"; `retry`
    is how this channel runs it again.
    """
    text = str(text or "")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    prose = [
        CONCLUSION_LABEL.sub("", line) for line in lines if not HEADING.match(line)
    ]
    actions, listing = [], False
    for line in lines:
        if ADVICE_HEADING.match(line):
            listing = True
        elif listing and LIST_MARK.match(line):
            actions.append(LIST_MARK.sub("", line))
        elif listing and actions:
            break
    conclusion = prose[0] if prose else ""
    if any(marker in text for marker in UNFINISHED):
        conclusion = REPORT_POINTER.sub("", conclusion).strip()
        if not actions:
            actions = unfinished_steps(text, retry)
    return conclusion, actions


def card_text(value):
    """Model text for the card: one paragraph, shown as feishu_text() shows it."""
    return feishu_text(re.sub(r"\s*\n\s*", " ", str(value)))


def card_summary(info):
    """Feishu card body: the status when not clean, the conclusion and up to
    four numbered actions.

    The data sources, confidence and usage are the card's footer (card_note);
    the conversation context keeps the full analysis_summary().
    """
    from .mcp_runtime import numbered

    if info.get("_unstructured"):
        cause, actions = plain_answer_parts(info.get("analysis"))
    else:
        cause, actions = numbered(info.get("cause")), action_items(info.get("action"))
    lines = []
    status = info.get("_diagnostic_status")
    if status in ("partial", "failed"):
        lines += [
            "**诊断状态**  " + ("部分完成" if status == "partial" else "失败"),
            "",
        ]
    full = card_text(cause or "")
    shown = clipped(full, CAUSE_CHARS)
    lines += ["**诊断结论**", shown + "（详见完整报告）" if shown != full else full]
    if lines[-1] == "":
        lines[-1] = "模型未给出结论。"
    # An item loses only its advice to set up Swap; one holding nothing else goes.
    items = [
        clipped(
            card_text(without_swap_parts(str(item), SWAP_SETUP.search)), ACTION_CHARS
        )
        for item in actions
    ]
    items = [item for item in items if item]
    if items:
        lines += ["", "**处理建议**"]
        lines += [f"{n}. {item}" for n, item in enumerate(items[:ACTION_ROWS], 1)]
        if len(items) > ACTION_ROWS:
            lines.append(f"另有 {len(items) - ACTION_ROWS} 条建议见完整报告")
    return "\n".join(lines)


def card_note(info):
    """Footer of the analysis card: what the conclusion rests on, how far it
    can be trusted, and what the run cost."""
    from .mcp_runtime import format_usage

    usage = format_usage(info.get("_token_usage"), duration_ms=info.get("_duration_ms"))
    return " · ".join(part for part in (source_line(info), usage) if part)


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
    host_id, trigger_id, event_id = (
        str(event.get(key) or "") for key in ("host_id", "trigger_id", "event_id")
    )
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
        "**主机名称**  " + event_text(event.get("host_name"), 80),
        "**主机 IP**  " + event_text(event.get("host_ip"), 50),
    ]
    if groups:
        lines.append("**所属分组**  " + event_text(groups, 180))
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
            "**事件名称**  " + event_text(event_name, 250),
            "**事件数值**  " + event_text(event_value_text, 300),
            "**事件 ID**  " + event_text(event.get("event_id"), 40),
        ]
    )
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
        link = zabbix_event_link(event)
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
        if (
            mute_info.get("active", True)
            and host_id.isdigit()
            and trigger_id.isdigit()
            and event_id.isdigit()
        ):
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
                            "url": detail_url,
                        }
                    ],
                }
            )
    if analysis:
        elements.append({"tag": "hr"})
        elements.append(
            {
                "tag": "note",
                "elements": [{"tag": "plain_text", "content": "◉ " + card_note(info)}],
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
    """Send alert cards solely through the configured Feishu enterprise app.

    Each group stands alone: one that fails (dissolved, bot removed) does not
    fail the delivery for the groups that got the card, which keep their
    analysis and recovery replies. Raises only when no group got it.
    """
    if cfg("feishu_enabled").lower() != "true":
        log.warning("FEISHU_APP_ALERT_DISABLED")
        return
    from .conversation_context import remember
    from .feishu_client import get_token, send_rendered_card
    from .integrations.feishu_links import remember as remember_link
    from .main import connection

    ids = cfg("feishu_alert_chat_ids") or cfg("allowed_chat_ids")
    chats = list(dict.fromkeys(x.strip() for x in ids.split(",") if x.strip()))
    if not chats:
        raise RuntimeError("未配置飞书企业应用告警群 Chat ID")
    delivered, errors = 0, []
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        for chat_id in chats:
            try:
                original_id = None
                if event and (
                    str(event.get("event_value", "1")) == "0"
                    or analysis_info is not None
                ):
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
                        with connection() as db:
                            db.execute(
                                "INSERT INTO alert_message_links(event_id,chat_id,message_id) VALUES (?,?,?) "
                                "ON CONFLICT(event_id,chat_id) DO UPDATE SET message_id=excluded.message_id",
                                (str(event["event_id"]), chat_id, message_id),
                            )
                if event:
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
                        origin = make_card(event)["elements"][0]["text"]["content"]
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
                delivered += 1
            except Exception as exc:
                log.error(
                    "FEISHU_APP_ALERT_FAILED chat_id_prefix=%s error=%s",
                    chat_id[:5],
                    type(exc).__name__,
                )
                errors.append(chat_id[:5])
    if errors and not delivered:
        raise RuntimeError("企业应用告警全部群发送失败，数量：" + str(len(errors)))
    if errors:
        log.warning(
            "FEISHU_APP_ALERT_PARTIAL delivered=%s failed=%s", delivered, len(errors)
        )


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
    from .main import connection

    severity = int(event.get("severity", "0"))
    recovery = str(event.get("event_value", "1")) == "0"
    # Extra card context: the plain alert card reads only "note" and
    # "host_groups" from it, falling back to the event macros when absent.
    info = {}
    if recovery:
        # A recovery is only useful in Feishu if its original problem was
        # actually delivered. Muted/failed/disabled/unknown problems are silent.
        # notify() replies only in the groups holding the problem card, so a
        # problem some groups got (earlier releases recorded it as "failed")
        # pairs there.
        with connection() as db:
            previous = db.execute(
                "SELECT notify_status FROM alert_events WHERE event_id=? AND event_value='1'",
                (str(event.get("event_id", "")),),
            ).fetchone()
            delivered = db.execute(
                "SELECT 1 FROM alert_message_links WHERE event_id=? LIMIT 1",
                (str(event.get("event_id", "")),),
            ).fetchone()
        if not delivered and (not previous or previous[0] != "sent"):
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
    else:
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
                + (f"[查看该次报告]({url})。" if url else "")
                + "需要重新分析可点击“AI分析”。"
            )
        elif budget and budget[0] >= budget[1]:
            plan = "budget"
            info["note"] = (
                f"今日自动 AI 分析已用 {budget[0]:,} Token（含进行中分析的预算），"
                f"达到每日上限 {budget[1]:,}，"
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
    except Exception:
        update_event(event, ai_status="failed")
        log.exception(
            "ALERT_ANALYSIS_ENQUEUE_FAILED event_id=%s", event.get("event_id")
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


def close_unstarted(task_id, exc):
    """End a task its job failed before starting (no model configured): left
    queued it would block the event's next analysis and hold daily budget."""
    if not task_id:
        return
    from .orchestrator import tasks

    try:
        task = tasks.get(task_id)
        if task and task["status"] == "queued":
            tasks.finish(
                task_id,
                {"message": "AI 分析未完成，请核对模型与连接配置"},
                status="failed",
                error_type=type(exc).__name__,
            )
    except Exception:
        log.exception("UNSTARTED_TASK_CLOSE_FAILED task_id=%s", task_id)


async def handle_alert_analysis(event, task_id=None):
    update_event(event, ai_status="running")
    try:
        analysis = await analyze(event, task_id)
        store_alert_usage(event, analysis.get("_token_usage"))
    except Exception as exc:
        update_event(event, ai_status="failed")
        close_unstarted(task_id, exc)
        # The job itself succeeds (no retry), so the traceback is only here.
        log.exception("ALERT_ANALYZE_FAILED event_id=%s", event.get("event_id"))
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
    # Rechecked as it starts: analyses that ended while this one waited may
    # have used more than their budget, or the limit was lowered.
    budget = daily_budget(task_id) if task_id else None
    if budget and budget[0] >= budget[1]:
        from .orchestrator import tasks

        tasks.finish(
            task_id,
            {
                "message": f"今日自动 AI 分析 Token 已达每日上限（{budget[0]:,} / "
                f"{budget[1]:,}），本次排队的分析未执行；需要时在告警卡片上点"
                "「🤖 AI分析」手动分析。"
            },
            status="cancelled",
            error_type="DailyBudget",
        )
        update_event(event, ai_status="skipped_budget")
        log.info(
            "ALERT_ANALYSIS_SKIPPED_BUDGET event_id=%s task_id=%s",
            event.get("event_id"),
            task_id,
        )
        return {"event_id": event.get("event_id"), "skipped": True}
    return asyncio.run(handle_alert_analysis(event, task_id))


async def analyze_on_demand(event, message_id, chat_id=None, task_id=None):
    """Fault and recovery: reply with progress, update it, preserve threaded context."""
    from .feishu_client import reply_card, update_card
    from .conversation_context import remember, mark_pending, clear_pending
    from .integrations.feishu_links import remember as remember_link
    from .main import connection

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
            + lark_safe(question[:240])
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
        card = card_summary(result) + "\n\n---\n" + card_note(result)
        link = report_url(result) or None
        if progress_id:
            try:
                await update_card(progress_id, "AI 分析结果", card, link=link)
            except Exception:
                log.exception("ALERT_AI_CARD_UPDATE_FAILED event_id=%s", event_id)
                if chat_id:
                    # The result goes out as a new reply; the stale progress
                    # card is no longer the one being analysed.
                    clear_pending(chat_id, progress_id)
                progress_id = await reply_card(
                    message_id, "AI 分析结果", card, link=link
                )
        else:
            progress_id = await reply_card(message_id, "AI 分析结果", card, link=link)
        try:
            # A Feishu GET /im/v1/messages/{id} may return 400 even when
            # reply and PATCH succeed. Use the verified delivery link instead.
            if not chat_id:
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
                remember_link(event, chat_id, progress_id, "analysis")
                # Use the actual visible alert card text, not a guessed summary.
                source_card = make_card(event)
                original = (
                    str(source_card["header"]["title"]["content"])
                    + "\n"
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
    except Exception as exc:
        if chat_id:
            clear_pending(chat_id, progress_id)
        update_event(event, ai_status="failed")
        close_unstarted(task_id, exc)
        log.exception("MANUAL_AI_ANALYSIS_FAILED event_id=%s", event_id)
        if progress_id:
            try:
                await update_card(progress_id, "AI 分析失败", failure_text(exc), "red")
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


def interrupted_text(retry, service):
    """Body of a progress card whose worker was killed mid-analysis."""
    return (
        "分析进程意外中断（服务重启或资源不足），本次没有形成结论。\n\n**处理建议**\n"
        f"1. {retry}\n"
        f"2. 反复中断时，请管理员执行 docker compose logs {service} 查看中断原因"
    )


def sync_ai_states():
    """Alert AI statuses and chat questions a killed worker left "running".

    An alert takes the end state of its latest analysis task once that ended
    over ten minutes ago (a live worker sets it as soon as its card is sent);
    a question still running after the longest analysis budget lost its worker.
    """
    from .main import connection
    from .orchestrator.tasks import stall_seconds

    latest = (
        " FROM diagnostic_tasks t WHERE t.event_id=alert_events.event_id "
        "AND t.kind='analysis' ORDER BY t.created_at DESC,t.rowid DESC LIMIT 1)"
    )
    stalled = f"-{stall_seconds()} seconds"
    with connection() as db:
        db.execute(
            "UPDATE alert_events SET ai_status=(SELECT CASE WHEN t.status IN "
            "('success','partial','cancelled') THEN t.status ELSE 'failed' END"
            + latest
            + " WHERE ai_status='running' AND (SELECT t.status NOT IN "
            "('queued','running') AND t.completed_at<datetime('now','-10 minutes')"
            + latest
        )
        db.execute(
            "UPDATE ai_questions SET status='failed',error_type='WorkerLost',"
            "completed_at=CURRENT_TIMESTAMP WHERE status='running' "
            "AND created_at<datetime('now',?)",
            (stalled,),
        )


def close_abandoned_progress():
    """A progress card whose worker was killed still reads "analysing": say the
    analysis stopped and how to run it again."""
    from .conversation_context import abandoned_progress, clear_pending
    from .feishu_client import update_card
    from .orchestrator.tasks import stall_seconds

    for reply_id, record in abandoned_progress(stall_seconds()):
        qa = record.get("kind") == "qa"
        text = interrupted_text(
            QA_RETRY if qa else RETRY, "qa-worker" if qa else "alert-analysis-worker"
        )
        clear_pending(record.get("chat_id"), reply_id)
        try:
            asyncio.run(update_card(reply_id, "AI 分析中断", text, "red"))
        except StopRequested:
            # RQ's SIGTERM handler raises it while the worker is idle.
            raise
        except Exception:
            log.exception("PROGRESS_CARD_CLOSE_FAILED")


def reconcile(redis=None):
    """Close what a killed worker (deploy, OOM) left running: its task, the
    alert's AI status, the chat question and the Feishu progress card.

    It never queues or re-runs anything and never stops the worker itself; a
    stop RQ asked for meanwhile (SIGTERM) goes through. `redis` is RQ's
    connection, which tells a queued task whose job is gone.
    """
    from .orchestrator import tasks

    def job_state(job_id):
        try:
            status = Job.fetch(job_id, connection=redis).get_status()
        except NoSuchJobError:
            return None
        return getattr(status, "value", status)

    for step, args in (
        (tasks.reconcile, (job_state if redis is not None else None,)),
        (sync_ai_states, ()),
        (close_abandoned_progress, ()),
    ):
        try:
            step(*args)
        except StopRequested:
            # RQ's SIGTERM handler raises it while the worker is idle (as it is
            # during maintenance); swallowed, the worker would miss its stop.
            raise
        except Exception:
            log.exception("RECONCILE_FAILED step=%s", step.__name__)


class MaintainedWorker(Worker):
    """An RQ worker (alert analysis, chat questions) whose maintenance (at
    start, then every ten minutes) also runs reconcile(), so nothing waits for
    someone to open a task."""

    def run_maintenance_tasks(self):
        super().run_maintenance_tasks()
        reconcile(self.connection)


if __name__ == "__main__":
    import sys
    from .main import REDIS_URL

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    redis = Redis.from_url(REDIS_URL)
    # `python -m app.worker analysis` serves manual clicks before automatic analysis.
    analysis = sys.argv[1:] == ["analysis"]
    names = (
        [queues.ALERT_MANUAL, queues.ALERT_ANALYSIS] if analysis else [queues.ALERTS]
    )
    # Only the analysis workers reconcile: on the alerts worker its Feishu
    # calls and SQLite waits would hold up the next alert's delivery.
    (MaintainedWorker if analysis else Worker)(
        [Queue(name, connection=redis) for name in names], connection=redis
    ).work()
