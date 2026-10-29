"""Small, evidence-faithful model views of large MCP records.

Original sanitized tool results are written to diagnostic_evidence unchanged.
Only the model context receives a preview, never the authoritative report.
"""

from collections import defaultdict
from datetime import datetime
import json
from math import isfinite
import re
import time
from zoneinfo import ZoneInfo

BEIJING = ZoneInfo("Asia/Shanghai")
FRESH_SECONDS = 600

# A schema cut mid-JSON cannot be called correctly; discovery gets its own budget
# and drops whole tools instead (four Zabbix schemas are roughly 14k characters).
SCHEMA_CHARS = 16000
SAMPLE_SIZES = (8, 4, 2, 0)
RECORD_LIMITS = (20, 10, 5)
PROCESS_ROWS = 15
UNRESOLVED_MACRO = re.compile(r"\{[$#]?[A-Z][A-Z0-9_.]*\}")


def _positive(value):
    try:
        return not isinstance(value, bool) and float(value) > 0
    except (TypeError, ValueError):
        return False


def trimmed_processes(outcome):
    """Keep the first busy process rows; idle kernel threads at 0 % are noise.

    The SSH service already orders rows by the metric in question, and the
    full list stays in the stored evidence.
    """
    data = outcome.get("data") if isinstance(outcome, dict) else None
    summary = data.get("summary") if isinstance(data, dict) else None
    rows = summary.get("processes") if isinstance(summary, dict) else None
    if not isinstance(rows, list) or len(rows) <= PROCESS_ROWS:
        return outcome
    busy = [
        row
        for row in rows
        if not isinstance(row, dict)
        or any(
            _positive(row.get(key))
            for key in ("cpu_interval", "cpu_percent", "memory_percent")
        )
    ][:PROCESS_ROWS]
    return {
        **outcome,
        "data": {
            **data,
            "summary": {
                **summary,
                "processes": busy,
                "processes_shown": len(busy),
                "processes_total": len(rows),
                "processes_note": f"仅展示前 {len(busy)} 个有占用的进程（共 {len(rows)} 个）；完整列表在任务证据中",
            },
        },
    }


def _fits(value, max_chars):
    return max_chars is None or len(json.dumps(value, ensure_ascii=False)) <= max_chars


def _numbers(records, fields):
    """Summarize only finite numeric measurements, not arbitrary text fields."""
    stats = {}
    for field in fields:
        values = []
        for row in records:
            if not isinstance(row, dict):
                continue
            raw = row.get(field)
            if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
                continue
            try:
                value = float(raw)
            except (ValueError, OverflowError):
                continue
            if isfinite(value):
                values.append(value)
        if values:
            stats[field] = {
                "numeric_count": len(values),
                "min": min(values),
                "max": max(values),
                "avg": round(sum(values) / len(values), 4),
            }
    return stats


def _series(itemid, rows, metrics, size):
    """Statistics cover every row; ``size`` evenly spaced samples keep the endpoints."""
    last = len(rows) - 1
    picks = (
        sorted({0, last} | {round(i * last / (size - 1)) for i in range(size)})
        if size >= 2
        else []
    )
    sample = [
        {key: value for key, value in rows[i].items() if key != "itemid"} for i in picks
    ]
    return {
        "itemid": itemid,
        "record_count": len(rows),
        "numeric_summary": _numbers(rows, metrics),
        "sample_records": sample,
        "sample_only": len(sample) < len(rows),
    }


def fit_definitions(outcome, max_chars=SCHEMA_CHARS):
    """Return whole tool schemas within the budget and name the ones left out."""
    tools = outcome.get("tools") if isinstance(outcome, dict) else None
    if not isinstance(tools, list) or _fits(outcome, max_chars):
        return outcome
    kept, omitted = [], []
    for tool in tools:
        if not isinstance(tool, dict) or "parameters" not in tool:
            kept.append(tool)
        elif _fits({"tools": kept + [tool]}, max_chars - 400):
            kept.append(tool)
        else:
            omitted.append(str(tool.get("name", "")))
    return {
        **{key: value for key, value in outcome.items() if key != "tools"},
        "tools": kept,
        "omitted_tools": omitted,
        "note": "以下工具定义因长度未展示，请用 names 精确获取：" + "、".join(omitted),
    }


def model_view(provider, tool, outcome, max_chars=None):
    """Remove duplicate text/records and summarize large history arrays.

    Samples must be labelled as partial; do not treat samples as a complete
    series, and keep all original evidence in the encrypted task store.
    With ``max_chars`` the view shrinks samples or rows to fit, so every series
    keeps its statistics instead of being cut out of the middle later.
    """
    if tool == "list_mcp_tools":
        return fit_definitions(outcome, max_chars or SCHEMA_CHARS)
    if provider == "ssh_mcp":
        return trimmed_processes(outcome)
    if (
        provider != "zabbix_mcp"
        or not isinstance(outcome, dict)
        or not isinstance(outcome.get("records"), list)
        or outcome.get("is_error")
    ):
        return outcome
    records = outcome["records"]
    if not records:
        return outcome
    result = {
        key: value for key, value in outcome.items() if key not in ("records", "data")
    }
    result["total_records"] = len(records)
    if tool in {"history_get", "trend_get"}:
        groups = defaultdict(list)
        for row in records:
            if isinstance(row, dict):
                groups[str(row.get("itemid", "unknown"))].append(row)
        metrics = (
            ("value",)
            if tool == "history_get"
            else ("value_min", "value_avg", "value_max")
        )
        result["note"] = (
            "统计值由本次完整采集记录计算，样本并非全部历史点；完整证据在任务记录中"
        )
        for size in SAMPLE_SIZES:
            result["series"] = [
                _series(itemid, rows, metrics, size)
                for itemid, rows in list(groups.items())[:8]
            ]
            if _fits(result, max_chars):
                break
    else:
        for limit in RECORD_LIMITS:
            result["records"] = records[:limit]
            if len(records) > limit:
                result["sample_only"] = True
                result["note"] = (
                    f"仅展示前 {limit} 条记录；请缩小 Zabbix 查询条件以确认未展示项"
                )
            if _fits(result, max_chars):
                break
    return result


def derive_signals(collected):
    """Deterministic cross-checks over prefetched evidence for the model.

    `collected` holds (provider, tool, raw outcome, evidence id). Uses the raw
    outcome, not the size-limited view, so trimmed rows still count.
    """
    signals, latest = [], {}
    clocks, clock_evidence = [], None
    for provider, tool, outcome, evidence_id in collected:
        if not isinstance(outcome, dict):
            continue
        if tool == "item_get":
            for row in outcome.get("records") or []:
                if isinstance(row, dict) and row.get("key_"):
                    latest[row["key_"]] = (row.get("lastvalue"), evidence_id)
                if isinstance(row, dict) and str(row.get("lastclock", "")).isdigit():
                    clocks.append(int(row["lastclock"]))
                    clock_evidence = clock_evidence or evidence_id
        elif provider == "ssh_mcp" and isinstance(outcome.get("data"), dict):
            for finding in outcome["data"].get("findings") or []:
                if isinstance(finding, dict) and finding.get("level") in {
                    "warning",
                    "critical",
                }:
                    signals.append(
                        {
                            "source": "ssh_mcp",
                            "evidence_id": evidence_id,
                            **{
                                key: finding.get(key)
                                for key in (
                                    "level",
                                    "metric",
                                    "value",
                                    "threshold",
                                    "hint",
                                )
                            },
                        }
                    )

    # Whether the host's items are still being collected: for "agent not
    # available" alerts this separates a dead host from a stopped agent, and
    # SSH is not an option on Windows or network devices.
    if len(clocks) >= 3:
        now = int(time.time())
        fresh = sum(1 for clock in clocks if now - clock <= FRESH_SECONDS)
        newest = max(clocks)
        signals.append(
            {
                "source": "zabbix_mcp",
                "evidence_id": clock_evidence,
                "level": "warning" if fresh == 0 else "info",
                "metric": "collection_freshness",
                "value": {
                    "items": len(clocks),
                    "updated_within_10m": fresh,
                    "newest_lastclock_local": datetime.fromtimestamp(
                        newest, BEIJING
                    ).isoformat(),
                },
                "hint": (
                    f"该主机 {len(clocks)} 个监控项全部停止更新，最后一次采集在 "
                    f"{datetime.fromtimestamp(newest, BEIJING).strftime('%H:%M:%S')}"
                    "：整机不可达或 Zabbix 到该主机的采集链路中断，而不只是单个监控项"
                    if fresh == 0
                    else f"该主机 {fresh}/{len(clocks)} 个监控项在最近 10 分钟内仍有新数据：主机或采集链路至少部分可用，问题更可能在未更新的那部分（如 agent 服务本身）"
                ),
            }
        )

    def number(key):
        try:
            return float(latest[key][0])
        except (KeyError, TypeError, ValueError):
            return None

    load5, cores, util = (
        number("system.cpu.load[all,avg5]"),
        number("system.cpu.num"),
        number("system.cpu.util"),
    )
    if (
        load5 is not None
        and cores
        and util is not None
        and load5 / cores >= 1.5
        and util < 50
    ):
        signals.append(
            {
                "source": "zabbix_mcp",
                "evidence_id": latest["system.cpu.util"][1],
                "level": "warning",
                "metric": "load_cpu_divergence",
                "value": {
                    "load_per_core_5m": round(load5 / cores, 2),
                    "cpu_util_percent": round(util, 2),
                },
                "hint": "Zabbix 最新值：每核 5 分钟负载偏高但 CPU 利用率不高，负载可能来自 D 状态任务或宿主机 CPU 争抢，而不是计算繁忙",
            }
        )
    return signals[:10]


def model_alert(event):
    """Alert fields for the model without unexpanded Zabbix macros.

    Problem notifications carry {EVENT.RECOVERY.*} literally; they hold no evidence.
    """
    return {
        key: value
        for key, value in (event or {}).items()
        if not (isinstance(value, str) and UNRESOLVED_MACRO.fullmatch(value.strip()))
    }
