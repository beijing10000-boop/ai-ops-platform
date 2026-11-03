"""Code-checked evidence citations and rule-capped confidence for diagnosis reports.

Every MCP result the model sees carries an evidence id (E1, E2, ...). The final
answer cites ids with a short quote; a citation counts only when the id exists,
the evidence was collected successfully and the quote checks out against that
evidence or the platform signals derived from it:

- Dates and clock times in a quote must occur in the evidence, compared in a
  normalized form (Unix seconds and time zones in Beijing time); their digits
  are never numbers to look for.
- A quote with a significant number (10 or more, or one with decimals) needs
  every number it holds among the evidence's measurements, at the quote's own
  precision. Integers below 10 count too, but cannot ground a quote alone.
  Identifier fields (item ids, clocks, pids) never ground a quote; a pid next
  to a measurement ("java PID 4242 CPU 380.5%") is still found.
- A quote whose numbers are all below 10 must name the field each belongs to
  (an item key, a field name, or a Chinese name such as 核数, 重启, 丢包率):
  the number is compared with the value of that field, of the item_get row
  that key names, or of a signal value (changes, latest). A small number
  without a name proves nothing: almost any evidence holds one.
- A quote without numbers must occur in the evidence as text and match one of
  its values, not only key names or generic words (status, success).

Confidence is derived from the checked citations, never from the model: 高
needs several valid citations across sources or queries, at least one of them
checked by a number; an answer with no quotes to check (no evidence array, or
a broken JSON answer of which only some fields could be recovered) reaches 中
at most. Structured facts without a valid citation are demoted.
"""

from datetime import date, datetime, timedelta, timezone
import json
import re
from zoneinfo import ZoneInfo

BEIJING = ZoneInfo("Asia/Shanghai")
# A number standing on its own: not glued to a name ("load_1", "E2", "eth0"),
# never part of a longer number, and no HTTP status class ("5xx").
NUMBER = re.compile(r"(?<![A-Za-z0-9_.])-?\d+(?:\.\d+)?(?!\d)(?![xX]{2})")
# Dates and clock times ("2026-10-29 19:55:21", "10:21:40.120", "2026年10月29日",
# "10月29日"): checked as moments, never as numbers.
MOMENT = re.compile(
    r"(?<![\d.])(?:(?P<year>\d{4})[-/.年](?P<month>\d{1,2})[-/.月](?P<day>\d{1,2})日?"
    r"|(?P<m>\d{1,2})月(?P<d>\d{1,2})日"
    r"|(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?(?:\.\d+)?)(?!\d)"
)
# A timestamp with its zone ("2026-10-29T11:12:21Z"): also read in Beijing time.
ZONED = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?"
    r"\s?(Z|[+-]\d{2}:?\d{2})"
)
# Names: identifiers ("agent.ping", "system.cpu.load[all,avg5]", "GE0/0/1";
# digits inside one are no numbers) and runs of Chinese (U+3400–U+9FFF).
HAN = chr(0x3400) + "-" + chr(0x9FFF)
WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-/\[\],]*")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-/\[\],]*|[" + HAN + "]+")
LETTER = re.compile("[A-Za-z" + HAN + "]")
TOKEN_SPLIT = re.compile("[^0-9a-z" + HAN + "]+")
# Integers below this occur in almost any evidence (counts, states, flags):
# on their own they cannot tie a quote to the evidence it names.
SMALL_INTEGER = 10
CITED_ID = re.compile(r"\bE(\d{1,3})\b")
PROVIDER_LABELS = {"ssh_mcp": "SSH MCP", "zabbix_mcp": "Zabbix MCP", "logs": "日志 MCP"}
# JSON keys whose numbers are identifiers or bookkeeping, not measurements.
IDENTIFIER_KEYS = {
    "itemid",
    "itemids",
    "clock",
    "ns",
    "pid",
    "ppid",
    "hostid",
    "hostids",
    "eventid",
    "r_eventid",
    "triggerid",
    "objectid",
    "revision",
    "host_id",
    "zabbix_hostid",
    "record_count",
    "total_records",
    "numeric_count",
    "limit",
    "time_from",
    "time_till",
    "lastclock",
    "evidence_id",
    "job_id",
    "exit_code",
    "duration_ms",
    "captured_at",
    "at",
    "since",
    "until",
    "interfaceid",
    "groupid",
}


# Identifiers a quote may give next to a measurement ("java PID 4242 CPU
# 380.5%"): found when the evidence holds them, but they never ground a quote.
NAMED_IDS = {
    "pid",
    "ppid",
    "itemid",
    "eventid",
    "r_eventid",
    "triggerid",
    "hostid",
    "objectid",
}
# Fields that describe an item row or a result instead of measuring anything:
# "agent.ping 3" must not pass on the row's value_type 3.
METADATA_KEYS = {
    "value_type",
    "type",
    "flags",
    "status",
    "state",
    "delay",
    "history",
    "trends",
    "units",
    "valuemapid",
    "templateid",
}
# Keys holding Unix seconds (Zabbix clock, lastclock, time_from ...).
TIME_KEY = re.compile(r"clock|time|^(?:at|since|until|ts)$")
# Names that point at no measurement in particular: the value column of every
# item row, result envelopes, units. A small number next to them alone is as
# unnamed as a bare one ('"lastvalue": "0"' does not say which item).
GENERIC_NAMES = {
    "value",
    "values",
    "lastvalue",
    "prevvalue",
    "status",
    "state",
    "result",
    "results",
    "data",
    "record",
    "records",
    "evidence",
    "evidence_id",
    "b",
    "byte",
    "bytes",
    "k",
    "kb",
    "kib",
    "m",
    "mb",
    "mib",
    "g",
    "gb",
    "gib",
    "ms",
    "s",
    "sec",
    "second",
    "seconds",
    "pct",
    "percent",
    "x",
}
# Words every result holds: a quote of them (and key names) proves nothing.
GENERIC_WORDS = GENERIC_NAMES | {
    "success",
    "succeeded",
    "ok",
    "true",
    "false",
    "null",
    "none",
    "partial",
    "yes",
    "no",
    "成功",
}
GENERIC_CHINESE = {
    "状态",
    "数值",
    "数量",
    "次数",
    "个数",
    "当前",
    "达到",
    "约为",
    "大约",
    "共有",
    "合计",
}
# Chinese names of measurements and the fragments of the field names and
# item keys that hold them ("CPU 核数 4" names cpu_count / system.cpu.num).
FIELD_WORDS = {
    "核数": ("cpu_count", "cpu.num", "cores", "ncpu", "cpus", "processors"),
    "核": ("cpu_count", "cpu.num", "cores", "ncpu", "cpus"),
    "空闲": ("idle",),
    "等待": ("wait",),
    "负载": ("load",),
    "使用率": ("util", "pused", "percent", "usage", "used"),
    "利用率": ("util", "percent", "usage"),
    "重启": ("restart",),
    "丢包": ("loss",),
    "延迟": ("latency", "rtt", "delay"),
    "响应": ("response", "rtt"),
    "内存": ("mem",),
    "交换": ("swap",),
    "总": ("total",),
    "可用": ("avail", "free"),
    "剩余": ("free", "avail"),
    "已用": ("used",),
    "错误": ("error", "err"),
    "失败": ("fail",),
    "进程": ("proc", "process"),
    "线程": ("thread",),
    "连接": ("conn", "socket", "established"),
    "端口": ("port",),
    "磁盘": ("disk", "vfs.fs"),
    "文件系统": ("vfs.fs", "filesystem"),
    "可用性": ("ping", "avail"),
    "在线": ("ping", "avail"),
    "变化": ("change",),
    # A state change as the platform's hint words it: "由 1 变为 0".
    "由": ("from",),
    "从": ("from",),
    "变为": ("to",),
    "最新": ("latest", "last"),
    "最近": ("latest", "last"),
    "最大": ("max",),
    "最高": ("max", "peak"),
    "最小": ("min",),
    "最低": ("min",),
    "平均": ("avg", "mean"),
    "均值": ("avg", "mean"),
    "告警前": ("before",),
    "告警后": ("after",),
    "基线": ("baseline",),
    "倍": ("ratio",),
    "监控项": ("item",),
    "事件": ("event", "problem"),
    "触发": ("problem", "event", "trigger"),
    "上一窗口": ("previous",),
    "上一": ("previous",),
    "接口": ("interface", "net.if"),
    "抖动": ("flap",),
    "中断": ("down",),
    "主机": ("host",),
    "流量": ("traffic", "bytes", "bps"),
    "温度": ("temp",),
    "风扇": ("fan",),
    "电源": ("power", "psu"),
    "堆": ("heap",),
    "运行时间": ("uptime",),
    "队列": ("queue",),
    "僵尸": ("zombie",),
    "句柄": ("handle", "file"),
    "请求": ("request",),
}
# Why a citation was dropped.
MISSING = "证据编号不存在"
FAILED = "引用的是失败或未完成的采集结果"
MISMATCH = "证据中找不到引用的数值或原文"
WRONG_MOMENT = "证据中没有引用的日期或时刻"
UNNAMED = "小于 10 的数值没有写明监控项 key 或字段名，无法核对"
GENERIC = "引用只有字段名或通用字样（如 status、success），证明不了结论"
IDENTIFIER = "引用的只有编号类字段（itemid、pid 等），证明不了结论"


def _moment(match):
    """(the form a date or time must have in the evidence, every form it
    stands for), or None when the digits are no date or time ("25:99")."""
    group = match.groupdict()
    try:
        if group["year"]:
            day = date(int(group["year"]), int(group["month"]), int(group["day"]))
            return "d:" + day.isoformat(), {
                "d:" + day.isoformat(),
                "md:" + day.strftime("%m-%d"),
            }
        if group["m"]:
            # A leap year, so that 2月29日 stays a date.
            form = "md:" + date(2000, int(group["m"]), int(group["d"])).strftime(
                "%m-%d"
            )
            return form, {form}
    except ValueError:
        return None
    hour, minute = int(group["hour"]), int(group["minute"])
    second = None if group["second"] is None else int(group["second"])
    if hour > 23 or minute > 59 or (second or 0) > 59:
        return None
    short = f"t:{hour:02d}:{minute:02d}"
    if second is None:
        return short, {short}
    return f"{short}:{second:02d}", {short, f"{short}:{second:02d}"}


def _without_moments(text):
    return MOMENT.sub(lambda match: " " if _moment(match) else match.group(0), text)


def _numbers(text):
    """The numbers of a text; the digits of its dates and times are left out."""
    return [match.group(0) for match in NUMBER.finditer(_without_moments(str(text)))]


def _significant(raw):
    """A quoted number that can tie a quote to its evidence: not a small integer."""
    value = float(raw)
    return not (value.is_integer() and abs(value) < SMALL_INTEGER)


def _near(raw, candidates):
    """Whether a quoted number is among `candidates` at its own precision
    (12% for 12.4, 8 GiB for 7.62)."""
    value = float(raw)
    decimals = len(raw.split(".")[1]) if "." in raw else 0
    tolerance = 0.5 * 10**-decimals
    return any(abs(candidate - value) <= tolerance for candidate in candidates)


def _squeezed(value):
    return re.sub(r"[\s\"'{}\[\]:,，：]", "", str(value))


def _clock_forms(moment, found):
    found.update(
        {
            "d:" + moment.strftime("%Y-%m-%d"),
            "md:" + moment.strftime("%m-%d"),
            "t:" + moment.strftime("%H:%M"),
            "t:" + moment.strftime("%H:%M:%S"),
        }
    )


def _moments(text, found):
    """Add the dates and times a text holds, as written and, for a timestamp
    with its zone, in Beijing time."""
    for match in MOMENT.finditer(text):
        parsed = _moment(match)
        if parsed:
            found.update(parsed[1])
    for match in ZONED.finditer(text):
        *fields, zone = match.groups()
        digits = zone[1:].replace(":", "")
        offset = (
            timedelta(0)
            if zone == "Z"
            else timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            * (1 if zone[0] == "+" else -1)
        )
        try:
            moment = datetime(
                *(int(part or 0) for part in fields), tzinfo=timezone(offset)
            )
        except ValueError:
            continue
        _clock_forms(moment.astimezone(BEIJING), found)


def _epoch(raw, found):
    """Add the Beijing date and time of a Unix-seconds value (Zabbix clocks)."""
    try:
        stamp = float(raw)
    except (TypeError, ValueError, OverflowError):
        return
    if not isinstance(raw, bool) and 1e9 <= stamp < 1e10:
        _clock_forms(datetime.fromtimestamp(stamp, BEIJING), found)


def _folded(name):
    return name.casefold().rstrip(".,")


def _named_numbers(text):
    """[(the words before it, number)] for each number of a text that stands on
    its own, not inside a name such as "eth0" or "nginx/1.24.0"."""
    text = _without_moments(text)
    names = [
        (match.start(), match.end(), match.group(0)) for match in NAME.finditer(text)
    ]
    found = []
    for match in NUMBER.finditer(text):
        start = match.start()
        if any(left <= start < right for left, right, _ in names):
            continue
        before = [_folded(name) for _, right, name in names if right <= start][-2:]
        found.append((tuple(before), float(match.group(0))))
    return found


def _walk(value, path, profile, evidence):
    """Collect what quotes are checked against from an evidence document
    (`evidence`) or a signal value derived from it: each number with the
    names it goes by, key names, string values, dates and times.

    A number's own names are its key and, inside a string, the words before
    it; its context is the keys above it and the other strings of its object
    (an item_get row's key_ and name for its lastvalue, a signal's key).
    Signal strings ground nothing; their dates and times count.
    """
    if isinstance(value, list):
        for item in value:
            _walk(item, path, profile, evidence)
        return
    if isinstance(value, str):
        _moments(value, profile["moments"])
        if evidence:
            profile["strings"].append(value)
        return
    if not isinstance(value, dict):
        return
    context = tuple(
        item.casefold()
        for key, item in value.items()
        if isinstance(item, str)
        and str(key) not in IDENTIFIER_KEYS
        and len(item) <= 160
        and LETTER.search(item)
    )
    for key, item in value.items():
        name = str(key)
        folded = name.casefold()
        profile["keys"].add(folded)
        if isinstance(item, (dict, list)):
            _walk(item, path + (folded,), profile, evidence)
            continue
        if TIME_KEY.search(folded):
            _epoch(item, profile["moments"])
        if isinstance(item, str):
            _moments(item, profile["moments"])
            if evidence:
                profile["strings"].append(item)
        if evidence and name in NAMED_IDS:
            profile["ids"].extend(float(n) for n in _numbers(item))
        if (
            isinstance(item, bool)
            or item is None
            or name in IDENTIFIER_KEYS
            or folded in METADATA_KEYS
        ):
            continue
        if isinstance(item, (int, float)):
            others = path + context
            profile["leaves"].append(((folded,), others, (float(item),)))
        elif evidence:
            others = path + tuple(
                label for label in context if label != item.casefold()
            )
            for words, number in _named_numbers(item):
                profile["leaves"].append(((folded, *words), others, (number,)))


def _profile(text, derived=()):
    """What one evidence id's quotes are checked against: its measurements
    and identifiers, named field values, keys, string values and moments,
    with the numbers and moments of the signals derived from it."""
    profile = {
        "numbers": [],
        "ids": [],
        "leaves": [],
        "keys": set(),
        "strings": [],
        "moments": set(),
    }
    try:
        document = json.loads(text)
    except (TypeError, ValueError):
        text = str(text)
        profile["numbers"] = [float(n) for n in _numbers(text)]
        profile["strings"].append(text)
        _moments(text, profile["moments"])
        for line in text.splitlines():
            profile["leaves"].extend(
                (words, (), (number,)) for words, number in _named_numbers(line)
            )
    else:
        profile["numbers"] = _measurements(document)
        _walk(document, (), profile, True)
    for value in derived:
        profile["numbers"].extend(_derived(value))
        _walk(value, ("signals",), profile, False)
    profile["squeezed"] = _squeezed(text)
    profile["values"] = "\n".join(profile["strings"]).casefold()
    return profile


def _chinese(run):
    """Name specs of a run of Chinese: the field words it holds (with the
    fragments of the field names they stand for) and its other parts of two
    characters or more, each matched as written."""
    specs, rest, start = [], "", 0
    while start < len(run):
        size = next(
            (
                size
                for size in range(min(4, len(run) - start), 0, -1)
                if run[start : start + size] in FIELD_WORDS
            ),
            0,
        )
        if not size:
            rest += run[start]
            start += 1
            continue
        if len(rest) >= 2 and rest not in GENERIC_CHINESE:
            specs.append(((rest,), False, False))
        rest, term = "", run[start : start + size]
        specs.append((FIELD_WORDS[term] + ((term,) if size >= 2 else ()), False, False))
        start += size
    if len(rest) >= 2 and rest not in GENERIC_CHINESE:
        specs.append(((rest,), False, False))
    return specs


def _names(text):
    """[(fragments, generic, identifier)] for the names in a piece of a quote."""
    specs = []
    for match in NAME.finditer(text):
        token = match.group(0)
        if not token[0].isascii():
            specs.extend(_chinese(token))
            continue
        word = _folded(token)
        if word:
            specs.append(((word,), word in GENERIC_NAMES, True))
    return specs


def _matches(fragment, label, identifier):
    """Whether a name from a quote names this label: equal to it, a whole token
    of it (one or two letters), the start of one of its tokens (three), part
    of it (longer); Chinese as written. A long label inside an identifier the
    quote gives ("NRestarts" for restarts) counts too."""
    if fragment == label:
        return True
    if not fragment.isascii():
        return len(fragment) >= 2 and fragment in label
    if len(fragment) <= 2:
        return fragment in TOKEN_SPLIT.split(label)
    if len(fragment) == 3:
        hit = re.search(r"(?<![0-9a-z])" + re.escape(fragment), label) is not None
    else:
        hit = fragment in label
    return hit or (
        identifier and len(label) >= 4 and label.isascii() and label in fragment
    )


def _field_value(raw, specs, leaves):
    """Whether a small number is the value of the field its names point at.

    Each name a field goes by scores 2 as its own name (its key, or the words
    before it in a string), 1 as context (keys above it, its row's key_ or
    name); a field needs at least one name that is not generic. The number
    must be the value of one of the best-named fields: "可用 8 GiB" is checked
    against mem_available_gib, not against the total that is 8.
    """
    best, values = 0, []
    for own, context, numbers in leaves:
        score, named = 0, False
        for fragments, generic, identifier in specs:
            if any(_matches(f, label, identifier) for f in fragments for label in own):
                score += 2
            elif any(
                _matches(f, label, identifier) for f in fragments for label in context
            ):
                score += 1
            else:
                continue
            named = named or not generic
        if not named or score < best:
            continue
        if score > best:
            best, values = score, []
        values.extend(numbers)
    return bool(values) and _near(raw, values)


def _has_value(text, profile):
    """Whether a quote without numbers matches one of the evidence's values:
    a word of three letters (two Chinese characters) or more that is neither
    a key of the evidence nor a generic word ("status: success")."""
    for match in NAME.finditer(text):
        token = _folded(match.group(0))
        if token in profile["keys"] or token in GENERIC_WORDS:
            continue
        if len(token) >= (3 if token.isascii() else 2) and token in profile["values"]:
            return True
    return False


def _assessed(quote, profile):
    """(how the quote checked out: "number", "text" or "moment", None) or
    (None, why it did not)."""
    moments = [parsed for parsed in map(_moment, MOMENT.finditer(quote)) if parsed]
    if any(form not in profile["moments"] for form, _ in moments):
        return None, WRONG_MOMENT
    text = _without_moments(quote)
    words = [match.span() for match in WORD.finditer(text)]
    numbers = [
        match
        for match in NUMBER.finditer(text)
        if not any(left <= match.start() < right for left, right in words)
    ]
    rest = _squeezed(text)
    if not numbers:
        if rest not in profile["squeezed"]:
            return None, MISMATCH
        if _has_value(text, profile):
            return "text", None
        if moments:
            # Dates and times, found above, with at most the key that holds
            # them ("lastclock 2026-10-29 19:55:21").
            return "moment", None
        return None, GENERIC if LETTER.search(rest) else MISMATCH
    raws = [match.group(0) for match in numbers]
    if any(_significant(raw) for raw in raws):
        # Every number is found; a significant measurement grounds the quote.
        grounded = False
        for raw in raws:
            if _near(raw, profile["numbers"]):
                grounded = grounded or _significant(raw)
            elif not _near(raw, profile["ids"]):
                return None, MISMATCH
        return ("number", None) if grounded else (None, IDENTIFIER)
    # Only integers below 10: each must be the value of the field it names,
    # named before it ("agent.ping 0", "重启 3 次") or after it ("2 个 D 状态进程").
    verbatim = len(rest) >= 4 and any(
        rest in _squeezed(value) for value in profile["strings"]
    )
    for position, match in enumerate(numbers):
        start = numbers[position - 1].end() if position else 0
        end = numbers[position + 1].start() if position + 1 < len(numbers) else None
        specs = _names(text[start : match.start()])
        if all(generic for _, generic, _ in specs):
            specs += _names(text[match.end() : end])
        if all(generic for _, generic, _ in specs):
            return ("text", None) if verbatim else (None, UNNAMED)
        if not _field_value(match.group(0), specs, profile["leaves"]):
            return ("text", None) if verbatim else (None, MISMATCH)
    return "number", None


def _measurements(value):
    """Numbers of an evidence document, skipping identifier fields.

    Strings keep every number they contain (a log line's "Killed process
    4242" is evidence); only the listed identifier keys are left out.
    """
    if isinstance(value, dict):
        found = []
        for name, item in value.items():
            if str(name) in IDENTIFIER_KEYS:
                continue
            found.extend(_measurements(item))
        return found
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(_measurements(item))
        return found
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, float)):
        return [float(value)]
    return [float(n) for n in _numbers(value)]


def _derived(value):
    """Numbers of attached signal values, identifier fields skipped. Their
    strings (keys, times, log templates) repeat the evidence and are left out."""
    if isinstance(value, dict):
        return [
            number
            for name, item in value.items()
            if str(name) not in IDENTIFIER_KEYS
            for number in _derived(item)
        ]
    if isinstance(value, list):
        return [number for item in value for number in _derived(item)]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return []
    return [float(value)]


def attach_signals(index, signals):
    """Make the platform's derived signals citable under their evidence ids.

    A signal's numbers (a ratio to the 7-day baseline, load per core, item
    counts) are computed from the evidence it names and occur in no tool
    result; each signal's `value` joins that evidence's comparable numbers as
    `signals`, so quoting them under the signal's evidence id checks out
    (under the same rules as tool numbers: a count below 10 must be named,
    "changes 2", and the dates and times of a signal count as the evidence's).
    """
    for signal in signals or []:
        if not isinstance(signal, dict):
            continue
        source = index.get(str(signal.get("evidence_id") or ""))
        if isinstance(source, dict) and "value" in signal:
            source.setdefault("signals", []).append(signal["value"])


def _failed(source):
    status = str(source.get("status") or "")
    return bool(source.get("failed")) or status in {"failed", "cancelled"}


NO_NUMBER = "有效引用都只核对了原文或时刻，没有一条核对过数值，可信度最高评为中"


def _broad(valid, invalid=()):
    """Several valid citations across sources (or distinct queries of one,
    for a Zabbix-only task), not outweighed by rejected ones."""
    providers = {item["provider"] for item in valid}
    tools = {(item["provider"], item["tool"]) for item in valid}
    return (
        len(valid) >= 2
        and (len(providers) >= 2 or len(tools) >= 2 and len(valid) >= 3)
        and (not invalid or len(valid) >= 2 * len(invalid))
    )


def confidence(valid, invalid=()):
    """高: several checked citations across tools (or both sources), at least
    one of them checked by a number; 中: at least one; 低: none. Quotes that
    only matched text or a moment ("result oom-kill") reach 中 at most."""
    if _broad(valid, invalid) and any(item.get("basis") == "number" for item in valid):
        return "高"
    return "中" if valid else "低"


FENCED = re.compile(r"\x60\x60\x60(?:json)?\s*(.*?)\s*\x60\x60\x60", re.S | re.I)
ANSWER_FIELDS = ("cause", "action", "analysis")
# Top-level keys of the answer contracts; one a lost bracket nested is moved up.
ANSWER_KEYS = (*ANSWER_FIELDS, "findings", "evidence", "human_required", "host_groups")


def _closed(text):
    """``text`` with the string, arrays and objects it leaves open closed, or
    None when nothing is open or its brackets do not pair."""
    stack, quoted, escaped = [], False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
        elif char in "}]" and (not stack or stack.pop() != char):
            return None
    if not stack:
        return None
    return text + ('"' if quoted else "") + "".join(reversed(stack))


def _hoisted(parsed):
    """``parsed`` with answer keys a lost bracket put in a nested object moved
    back to the top level ("findings" left open swallows "evidence")."""
    for value in list(parsed.values()):
        if isinstance(value, dict):
            for key in ANSWER_KEYS:
                if key in value and key not in parsed:
                    parsed[key] = value.pop(key)
    return parsed


def _salvaged(text):
    """The answer fields of a broken object whose own values are whole JSON
    and end where the next field or the object does."""
    decoder, found = json.JSONDecoder(strict=False), {}
    for key in (*ANSWER_FIELDS, "human_required", "host_groups"):
        for match in re.finditer(r'"' + key + r'"\s*:\s*', text):
            try:
                value, end = decoder.raw_decode(text, match.end())
            except ValueError:
                continue
            whole = text[end:].lstrip()[:1] in (",", "}", "")
            if whole and (key not in ANSWER_FIELDS or isinstance(value, (str, list))):
                found[key] = value
                break
    return found if any(key in found for key in ANSWER_FIELDS) else None


def answer_object(answer, fields=ANSWER_FIELDS):
    """The model's structured answer as a dict, or None for a plain-text one.

    The prompts ask for bare JSON. Models sometimes wrap it in a code fence or
    put a heading before it ("## 诊断结果" + a fenced block); the object is then
    taken from the fence, or from the first "{" to the last "}", and only when
    it carries one of `fields` (the answer fields; the alert card also takes
    the names models use instead), so prose quoting JSON stays prose.
    Raw line breaks inside strings are accepted (``strict=False``): models
    write a multi-line "cause" that way, and strict JSON rejects it. A bracket
    the model lost or an output cut short is closed; failing that, each answer
    field whose own value is whole is taken on its own.
    """
    return parse_answer(answer, fields)[0]


def parse_answer(answer, fields=ANSWER_FIELDS):
    """answer_object() and how the object was read: "json" (the whole answer),
    "embedded" (a fenced block or the outermost braces), "repaired" (unclosed
    brackets closed) or "salvaged" (answer fields taken one by one from a
    broken object, the evidence array among the parts lost); (None, None) for
    a plain-text answer."""
    text = str(answer or "").strip()
    try:
        parsed = json.loads(
            re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", text),
            strict=False,
        )
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed, "json"
    candidates = [match.group(1) for match in FENCED.finditer(text)]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate, strict=False)
        except ValueError:
            continue
        if isinstance(parsed, dict) and any(key in parsed for key in fields):
            return parsed, "embedded"
    if start < 0:
        return None, None
    for candidate in (*candidates, text[start:]):
        repaired = _closed(candidate)
        try:
            parsed = json.loads(repaired, strict=False) if repaired else None
        except ValueError:
            continue
        if isinstance(parsed, dict):
            parsed = _hoisted(parsed)
            if any(key in parsed for key in fields):
                return parsed, "repaired"
    salvaged = _salvaged(text[start:])
    return (salvaged, "salvaged") if salvaged is not None else (None, None)


def _check_facts(parsed, valid_ids):
    """Structured statements: a confirmed fact needs a valid citation.

    Returns {confirmed, demoted, probable, hypotheses} counts and the lists the
    report renders. Facts citing nothing valid become probable statements.
    """
    findings = parsed.get("findings")
    if not isinstance(findings, dict):
        return None
    groups = {"confirmed": [], "probable": [], "hypotheses": []}
    demoted = []
    for group in ("confirmed", "probable", "hypotheses"):
        for item in list(findings.get(group) or [])[:12]:
            if isinstance(item, str):
                item = {"statement": item}
            if not isinstance(item, dict):
                continue
            statement = str(item.get("statement") or "").strip()[:300]
            if not statement:
                continue
            ids = [
                str(ident).strip().upper()
                for ident in (item.get("evidence") or [])
                if str(ident).strip()
            ]
            ids = ids or ["E" + m.group(1) for m in CITED_ID.finditer(statement)]
            cited = [ident for ident in ids if ident in valid_ids]
            entry = {"statement": statement, "evidence": cited}
            if group == "confirmed" and not cited:
                entry["note"] = "无有效引用，已降为推断"
                demoted.append(entry)
                groups["probable"].append(entry)
            elif group == "hypotheses":
                entry["verify"] = str(item.get("verify") or "").strip()[:200]
                groups["hypotheses"].append(entry)
            else:
                groups[group].append(entry)
    return {
        **groups,
        "demoted": demoted,
        "counts": {
            "confirmed": len(groups["confirmed"]),
            "demoted": len(demoted),
            "probable": len(groups["probable"]),
            "hypotheses": len(groups["hypotheses"]),
        },
    }


def _text_ids(parsed):
    """Evidence ids the answer's prose cites: its cause, analysis and actions,
    and its findings' statements, in order."""
    parts = []
    for key in ANSWER_FIELDS:
        value = parsed.get(key)
        parts.extend(value if isinstance(value, list) else [value])
    findings = parsed.get("findings")
    if isinstance(findings, dict):
        for group in findings.values():
            for item in group if isinstance(group, list) else []:
                parts.append(item.get("statement") if isinstance(item, dict) else item)
    text = "\n".join(str(part) for part in parts if part)
    return list(dict.fromkeys("E" + m.group(1) for m in CITED_ID.finditer(text)))


UNCHECKED = {
    "salvaged": "回答的 JSON 不完整，只恢复出部分字段，没有可核对的原文摘录",
    "structured": "回答没有 evidence 原文摘录",
    "text": "回答没有附原文摘录",
}


def check(answer, index):
    """Return {valid, invalid, confidence, method, facts} or None when nothing is cited.

    `index` maps evidence ids to {"provider", "tool", "text", "status", "failed"}
    as the model saw them, plus "signals" from attach_signals().
    Without an evidence array whose quotes can be checked (plain text, JSON
    without one, a broken answer read field by field) only the cited ids are
    checked; their existence alone never makes the confidence 高, and
    `confidence_note` says why it is capped. A valid quote's `basis` says how
    it checked out: "number", "text" or "moment".
    """
    parsed, how = parse_answer(answer)
    if parsed is not None and isinstance(parsed.get("evidence"), list):
        valid, invalid, profiles = [], [], {}
        for item in parsed["evidence"][:20]:
            if not isinstance(item, dict):
                continue
            ident = str(item.get("id", "")).strip().upper()
            quote = str(item.get("quote", "")).strip()[:200]
            source = index.get(ident)
            if not source:
                reason = MISSING
            elif _failed(source):
                reason = FAILED
            else:
                if ident not in profiles:
                    profiles[ident] = _profile(
                        source["text"], source.get("signals") or ()
                    )
                basis, reason = _assessed(quote, profiles[ident])
                if basis:
                    valid.append(
                        {
                            "id": ident,
                            "quote": quote,
                            "provider": source["provider"],
                            "tool": source["tool"],
                            "basis": basis,
                        }
                    )
                    continue
            invalid.append({"id": ident, "quote": quote, "reason": reason})
        # The conclusion's own text cites ids too ("（E7）"): one that does not
        # exist, or whose collection failed, is a bad citation like a quote's.
        quoted = {item["id"] for item in valid} | {item["id"] for item in invalid}
        for ident in _text_ids(parsed):
            source = index.get(ident)
            if ident in quoted or (source and not _failed(source)):
                continue
            quoted.add(ident)
            invalid.append(
                {
                    "id": ident,
                    "quote": "",
                    "reason": MISSING if not source else FAILED,
                    "where": "正文",
                }
            )
        result = {
            "method": "quote",
            "valid": valid,
            "invalid": invalid,
            "confidence": confidence(valid, invalid),
        }
        if result["confidence"] == "中" and _broad(valid, invalid):
            result["confidence_note"] = NO_NUMBER
        facts = _check_facts(parsed, {item["id"] for item in valid})
        if facts:
            result["facts"] = facts
        return result
    # No quotes to verify: check that the cited ids exist and succeeded.
    cited = list(
        dict.fromkeys("E" + m.group(1) for m in CITED_ID.finditer(str(answer)))
    )
    if not cited:
        return None
    kind = (
        "salvaged"
        if how == "salvaged"
        else "structured"
        if parsed is not None
        else "text"
    )
    valid = [
        {
            "id": ident,
            "quote": "",
            "provider": index[ident]["provider"],
            "tool": index[ident]["tool"],
        }
        for ident in cited
        if ident in index and not _failed(index[ident])
    ]
    invalid = [
        {
            "id": ident,
            "quote": "",
            "reason": MISSING if ident not in index else FAILED,
        }
        for ident in cited
        if ident not in index or _failed(index[ident])
    ]
    return {
        "method": "reference",
        "valid": valid,
        "invalid": invalid,
        # An id that exists proves no value: 中 at most without checked quotes.
        "confidence": "中" if valid else "低",
        "confidence_note": UNCHECKED[kind]
        + "；平台只核对了证据编号存在且采集成功，可信度最高评为中",
    }


STATUS_LABELS = {
    "used": "已使用",
    "available": "可用",
    "unused": "已授权但本次未调用",
    "not_applicable": "不适用",
    "unavailable": "不可用",
    "not_ready": "主机未就绪",
    "disabled": "未启用",
    "unreachable": "连接失败",
    "unauthorized": "未授权",
    "not_onboarded": "目标未接入",
}
# CAPABILITY_MISSING names SSH MCP reports for a host; others read "缺少 <name>".
HOST_LIMIT_LABELS = {
    "kernel-psi": "内核未启用 PSI（Rocky/RHEL 9 需启动参数 psi=1）",
    "journal-permission": "诊断账号无权读取完整 journal（需 root 或 systemd-journal/adm 组）",
    "journalctl": "主机没有 journalctl",
    "log-permission": "诊断账号无权读取日志文件",
    "log-files": "未找到可读的系统日志文件",
    "nginx": "主机未安装或未找到 Nginx",
    "jcmd": "主机缺少 jcmd",
    "jstat": "主机缺少 jstat",
    "runuser": "主机缺少 runuser，无法切换到 JVM 用户",
    "docker-or-podman": "主机未安装 Docker 或 Podman",
}
PATH_LABELS = {
    "zabbix+ssh": "Zabbix 历史 + SSH 实时联合分析",
    "zabbix-only": "仅 Zabbix 监控数据",
    "ssh-only": "仅 SSH 实时数据",
    "zabbix+ssh+logs": "Zabbix 历史 + SSH 实时 + 日志联合分析",
    "zabbix+logs": "Zabbix 历史 + 日志联合分析",
    "ssh+logs": "SSH 实时 + 日志联合分析",
    "logs-only": "仅日志数据",
    "none": "未取得任何数据源",
}
DEVICE_LABELS = {
    "linux": "Linux",
    "windows": "Windows",
    "network": "网络设备",
    "vmware": "VMware",
    "other": "其它",
    "unknown": "未识别",
}


def scope(index, target, capabilities=None, id_range=True):
    """Target, collection time, queried windows, sources and capabilities, rendered
    by the platform so the final model round does not have to restate them.

    `id_range=False` leaves out the evidence id range, for chat replies that
    have no evidence list to point at."""
    capabilities = capabilities or {}
    if not index and not capabilities:
        return ""

    def clock(stamp):
        return datetime.fromtimestamp(stamp, BEIJING).strftime("%Y-%m-%d %H:%M:%S")

    lines = ["诊断范围（平台生成）"]
    ids = [
        label + str(target[key])
        for key, label in (
            ("host_id", "Zabbix Host ID "),
            ("ssh_host_id", "SSH 资产 "),
            ("address", "地址 "),
        )
        if target.get(key) not in (None, "")
    ]
    if target.get("host_name") or ids:
        lines.append(
            "- 目标："
            + str(target.get("host_name") or "")
            + ("（" + "，".join(ids) + "）" if ids else "")
        )
    device = capabilities.get("device_type") or target.get("device_type")
    path = capabilities.get("diagnostic_path")
    if device or path:
        lines.append(
            "- 设备类型与路径："
            + DEVICE_LABELS.get(device, str(device or "未识别"))
            + (("，" + PATH_LABELS.get(path, path)) if path else "")
        )
    times = [item["at"] for item in index.values() if item.get("at")]
    if times:
        lines.append(
            f"- 采集时间（北京时间）：{clock(min(times))} – {clock(max(times))}"
        )
    windows = [item["window"] for item in index.values() if item.get("window")]
    if windows:
        lines.append(
            "- Zabbix 历史查询窗口（北京时间）："
            f"{clock(min(w[0] for w in windows))} – {clock(max(w[1] for w in windows))}"
        )
    counts = {}
    for item in index.values():
        label = PROVIDER_LABELS.get(item["provider"], item["provider"])
        counts.setdefault(label, [0, 0])
        counts[label][1 if _failed(item) else 0] += 1
    if index:
        first, last = next(iter(index)), next(reversed(index))
        lines.append(
            "- 证据来源："
            + "、".join(
                f"{label} {ok} 条" + (f"（另 {bad} 条失败或不完整）" if bad else "")
                for label, (ok, bad) in counts.items()
            )
            + (
                f"（{first}{'–' + last if last != first else ''}，详见证据与工具执行记录）"
                if id_range
                else ""
            )
        )
    notes = []
    for provider in ("zabbix_mcp", "ssh_mcp", "logs"):
        state = capabilities.get(provider)
        if not isinstance(state, dict):
            continue
        status = state.get("status")
        if status in (None, "used"):
            continue
        text = f"{PROVIDER_LABELS[provider]}{STATUS_LABELS.get(status, status)}"
        if state.get("reason"):
            text += "：" + str(state["reason"])
        notes.append(text)
    logs = capabilities.get("logs")
    if (
        isinstance(logs, dict)
        and logs.get("target")
        and (logs.get("tried") or logs.get("identity") == "hostname")
    ):
        # Found by another identity than the first IP: say which one.
        tried = [str(item) for item in logs.get("tried") or []]
        notes.append(
            (
                "日志来源按主机名 "
                if logs.get("identity") == "hostname"
                else "日志来源按 IP "
            )
            + str(logs["target"])
            + " 定位"
            + ("（" + "、".join(tried) + " 最近 7 天没有日志）" if tried else "")
        )
    for key, label in (
        ("unauthorized_tools", " SSH "),
        ("unauthorized_log_tools", "日志"),
    ):
        if capabilities.get(key):
            notes.append(
                f"令牌未授权的{label}工具：" + "、".join(capabilities[key][:8])
            )
    limits = [
        item
        for item in capabilities.get("host_limits") or []
        if isinstance(item, dict) and item.get("missing")
    ]
    if limits:
        names = list(dict.fromkeys(str(item["missing"]) for item in limits))
        notes.append(
            "主机不支持的采集项："
            + "；".join(
                HOST_LIMIT_LABELS.get(name, "缺少 " + name)
                + "（"
                + "、".join(
                    dict.fromkeys(
                        str(item["tool"]) for item in limits if item["missing"] == name
                    )
                )
                + "）"
                for name in names[:8]
            )
        )
    if notes:
        lines.append("- 能力说明：" + "；".join(notes))
    return "\n".join(lines)


def render(result):
    """Markdown section appended to the report; empty when nothing was cited."""
    if not result:
        return ""
    lines = [
        "证据核对",
        f"依据可信度：{result['confidence']}（"
        + (
            result.get("confidence_note")
            or "平台核对引用后评定："
            "多条有效引用且覆盖不同数据源或查询为高，有有效引用为中，没有为低"
        )
        + "）",
    ]
    for item in result["valid"]:
        source = PROVIDER_LABELS.get(item["provider"], item["provider"])
        quote = f"：“{item['quote']}”" if item["quote"] else ""
        lines.append(f"- {item['id']} {source} / {item['tool']}{quote}")
    if result["invalid"]:
        lines.append("未通过核对、已剔除的引用：")
        lines.extend(
            f"- {item['id']}{('：“' + item['quote'] + '”') if item['quote'] else ''}"
            f"（{'结论正文引用，' if item.get('where') else ''}{item['reason']}）"
            for item in result["invalid"]
        )
    facts = result.get("facts")
    if facts and any(facts[group] for group in ("confirmed", "probable", "hypotheses")):
        lines.append("")
        lines.append("事实与推断（平台按引用核对分级）")
        for title, group in (
            ("已确认事实", "confirmed"),
            ("高可信推断", "probable"),
            ("待验证假设", "hypotheses"),
        ):
            if not facts[group]:
                continue
            lines.append(title + "：")
            for item in facts[group]:
                suffix = ""
                if item.get("evidence"):
                    suffix = "（" + "、".join(item["evidence"]) + "）"
                if item.get("note"):
                    suffix += "［" + item["note"] + "］"
                if item.get("verify"):
                    suffix += " 可核验方式：" + item["verify"]
                lines.append(f"- {item['statement']}{suffix}")
    return "\n".join(lines)
