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
PROVIDER_LABELS = {"ssh_mcp": "SSH MCP", "zabbix_mcp": "Zabbix MCP"}
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
PATH_STATUS = {"确认", "推断", "假设"}


def _numbers(text):
    return [match.group(0) for match in NUMBER.finditer(str(text))]


def _measurements(value, key=None):
    """Numbers of an evidence document, skipping identifier fields.

    Strings keep every number they contain (a log line's "Killed process
    4242" is evidence); only the listed identifier keys are left out.
    """
    if isinstance(value, dict):
        found = []
        for name, item in value.items():
            if str(name) in IDENTIFIER_KEYS:
                continue
            found.extend(_measurements(item, name))
        return found
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(_measurements(item, key))
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


def _parse(answer):
    try:
        parsed = json.loads(
            re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", answer.strip())
        )
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _check_facts(parsed, index, valid_ids):
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
        "confirmed": groups["confirmed"],
        "probable": groups["probable"],
        "hypotheses": groups["hypotheses"],
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

    `index` maps evidence ids to {"provider", "tool", "text", "status"} as the
    model saw them.
    """
    parsed = _parse(answer)
    if parsed is not None and isinstance(parsed.get("evidence"), list):
        valid, invalid = [], []
        for item in parsed["evidence"][:20]:
            if not isinstance(item, dict):
                continue
            ident = str(item.get("id", "")).strip().upper()
            quote = str(item.get("quote", "")).strip()[:200]
            source = index.get(ident)
            if not source:
                invalid.append(
                    {"id": ident, "quote": quote, "reason": "证据编号不存在"}
                )
            elif _failed(source):
                invalid.append(
                    {
                        "id": ident,
                        "quote": quote,
                        "reason": "引用的是失败或未完成的采集结果",
                    }
                )
            elif not _grounded(quote, source["text"]):
                invalid.append(
                    {
                        "id": ident,
                        "quote": quote,
                        "reason": "证据中找不到引用的数值或原文",
                    }
                )
            else:
                valid.append(
                    {
                        "id": ident,
                        "quote": quote,
                        "provider": source["provider"],
                        "tool": source["tool"],
                    }
                )
        result = {
            "method": "quote",
            "valid": valid,
            "invalid": invalid,
            "confidence": confidence(valid, invalid),
        }
        facts = _check_facts(parsed, index, {item["id"] for item in valid})
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


SSH_STATUS = {
    "used": "已使用",
    "available": "可用",
    "unused": "已授权但本次未调用",
    "not_applicable": "不适用",
    "unavailable": "不可用",
    "not_ready": "主机未就绪",
    "disabled": "未启用",
    "unreachable": "连接失败",
    "unauthorized": "未授权",
}
PATH_LABELS = {
    "zabbix+ssh": "Zabbix 历史 + SSH 实时联合分析",
    "zabbix-only": "仅 Zabbix 监控数据",
    "ssh-only": "仅 SSH 实时数据",
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


def scope(index, target, capabilities=None):
    """Target, collection time, queried windows, sources and capabilities, rendered
    by the platform so the final model round does not have to restate them."""
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
            + (
                "（" + capabilities["path_reason"] + "）"
                if capabilities.get("path_reason")
                else ""
            )
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
            + f"（{first}{'–' + last if last != first else ''}，详见证据与工具执行记录）"
        )
    notes = []
    for provider in ("zabbix_mcp", "ssh_mcp"):
        state = capabilities.get(provider)
        if not isinstance(state, dict):
            continue
        status = state.get("status")
        if status in (None, "used"):
            continue
        text = f"{PROVIDER_LABELS[provider]}{SSH_STATUS.get(status, status)}"
        if state.get("reason"):
            text += "：" + str(state["reason"])
        notes.append(text)
    if capabilities.get("unauthorized_tools"):
        notes.append(
            "令牌未授权的 SSH 工具："
            + "、".join(capabilities["unauthorized_tools"][:8])
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
