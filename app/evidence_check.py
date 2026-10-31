"""Code-checked evidence citations and rule-capped confidence for diagnosis reports.

Every MCP result the model sees carries an evidence id (E1, E2, ...). The final
answer cites ids with a short quote; a citation counts only when the id exists,
the evidence was collected successfully, and every number in the quote appears
in that evidence (at the quote's own precision), so a value cannot be attributed
to evidence that does not contain it. Identifier fields (item ids, clocks, pids)
never ground a quote. Confidence is derived from the valid citations, never
from the model; structured facts without a valid citation are demoted.
"""

from datetime import datetime
import json
import re
from zoneinfo import ZoneInfo

BEIJING = ZoneInfo("Asia/Shanghai")
NUMBER = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?")
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


def _numbers(text):
    return [match.group(0) for match in NUMBER.finditer(str(text))]


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


def evidence_numbers(evidence_text):
    try:
        document = json.loads(evidence_text)
    except (TypeError, ValueError):
        return [float(n) for n in _numbers(evidence_text)]
    return _measurements(document)


def _grounded(quote, evidence_text):
    """All numbers of the quote occur in the evidence; otherwise text containment."""
    wanted = _numbers(quote)
    if not wanted:
        squeeze = lambda value: re.sub(r"[\s\"'{}\[\]:,，：]", "", str(value))  # noqa: E731
        return len(squeeze(quote)) >= 4 and squeeze(quote) in squeeze(evidence_text)
    available = evidence_numbers(evidence_text)
    for raw in wanted:
        value = float(raw)
        decimals = len(raw.split(".")[1]) if "." in raw else 0
        tolerance = 0.5 * 10**-decimals
        if not any(abs(candidate - value) <= tolerance for candidate in available):
            return False
    return True


def _failed(source):
    status = str(source.get("status") or "")
    return bool(source.get("failed")) or status in {"failed", "cancelled"}


def confidence(valid, invalid=()):
    """高: several checked citations across tools (or both sources); 中: at least
    one; 低: none. A Zabbix-only task can reach 高 by citing distinct queries."""
    providers = {item["provider"] for item in valid}
    tools = {(item["provider"], item["tool"]) for item in valid}
    if len(valid) >= 2 and (len(providers) >= 2 or len(tools) >= 2 and len(valid) >= 3):
        return "高" if not invalid or len(valid) >= 2 * len(invalid) else "中"
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


def answer_object(answer):
    """The model's structured answer as a dict, or None for a plain-text one.

    The prompts ask for bare JSON. Models sometimes wrap it in a code fence or
    put a heading before it ("## 诊断结果" + a fenced block); the object is then
    taken from the fence, or from the first "{" to the last "}", and only when
    it carries one of the answer fields, so prose quoting JSON stays prose.
    Raw line breaks inside strings are accepted (``strict=False``): models
    write a multi-line "cause" that way, and strict JSON rejects it. A bracket
    the model lost or an output cut short is closed; failing that, each answer
    field whose own value is whole is taken on its own.
    """
    text = str(answer or "").strip()
    try:
        parsed = json.loads(
            re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", text),
            strict=False,
        )
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    candidates = [match.group(1) for match in FENCED.finditer(text)]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate, strict=False)
        except ValueError:
            continue
        if isinstance(parsed, dict) and any(key in parsed for key in ANSWER_FIELDS):
            return parsed
    if start < 0:
        return None
    for candidate in (*candidates, text[start:]):
        repaired = _closed(candidate)
        try:
            parsed = json.loads(repaired, strict=False) if repaired else None
        except ValueError:
            continue
        if isinstance(parsed, dict):
            parsed = _hoisted(parsed)
            if any(key in parsed for key in ANSWER_FIELDS):
                return parsed
    return _salvaged(text[start:])


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


def check(answer, index):
    """Return {valid, invalid, confidence, method, facts} or None when nothing is cited.

    `index` maps evidence ids to {"provider", "tool", "text", "status", "failed"}
    as the model saw them.
    """
    parsed = answer_object(answer)
    if parsed is not None and isinstance(parsed.get("evidence"), list):
        valid, invalid = [], []
        for item in parsed["evidence"][:20]:
            if not isinstance(item, dict):
                continue
            ident = str(item.get("id", "")).strip().upper()
            quote = str(item.get("quote", "")).strip()[:200]
            source = index.get(ident)
            if not source:
                reason = "证据编号不存在"
            elif _failed(source):
                reason = "引用的是失败或未完成的采集结果"
            elif not _grounded(quote, source["text"]):
                reason = "证据中找不到引用的数值或原文"
            else:
                valid.append(
                    {
                        "id": ident,
                        "quote": quote,
                        "provider": source["provider"],
                        "tool": source["tool"],
                    }
                )
                continue
            invalid.append({"id": ident, "quote": quote, "reason": reason})
        result = {
            "method": "quote",
            "valid": valid,
            "invalid": invalid,
            "confidence": confidence(valid, invalid),
        }
        facts = _check_facts(parsed, {item["id"] for item in valid})
        if facts:
            result["facts"] = facts
        return result
    # Plain-text answers: check that cited ids exist (no quotes to verify).
    cited = list(
        dict.fromkeys("E" + m.group(1) for m in CITED_ID.finditer(str(answer)))
    )
    if not cited:
        return None
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
            "reason": "证据编号不存在"
            if ident not in index
            else "引用的是失败或未完成的采集结果",
        }
        for ident in cited
        if ident not in index or _failed(index[ident])
    ]
    return {
        "method": "reference",
        "valid": valid,
        "invalid": invalid,
        "confidence": confidence(valid, invalid),
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
        f"依据可信度：{result['confidence']}（平台核对引用后评定："
        "多条有效引用且覆盖不同数据源或查询为高，有有效引用为中，没有为低）",
    ]
    for item in result["valid"]:
        source = PROVIDER_LABELS.get(item["provider"], item["provider"])
        quote = f"：“{item['quote']}”" if item["quote"] else ""
        lines.append(f"- {item['id']} {source} / {item['tool']}{quote}")
    if result["invalid"]:
        lines.append("未通过核对、已剔除的引用：")
        lines.extend(
            f"- {item['id']}{('：“' + item['quote'] + '”') if item['quote'] else ''}（{item['reason']}）"
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
