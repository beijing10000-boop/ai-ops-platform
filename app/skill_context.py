"""Small, evidence-faithful model views of large MCP records.

Original sanitized tool results are written to diagnostic_evidence unchanged.
Only the model context receives a preview, never the authoritative report.
"""

from collections import Counter, defaultdict
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
# Lists inside SSH results that may be shortened for the model, longest first
# (the stored evidence keeps every row).
SSH_LIST_KEYS = (
    "entries",
    "samples",
    "lines",
    "rows",
    "matched",
    "units",
    "listening",
    "listeners",
    "top_processes",
    "history",
    "timeline",
    "codes",
    "processes",
    "uris",
    "ips",
    "uas",
    "top_messages",
    "top_requests",
    "top_clients",
    "top_upstreams",
    "xx_flags",
)
# Inventories of objects (processes, units, sockets) whose rows may lose their
# bulkiest fields before any row is dropped. Log and sample lists are not
# here: their text is the evidence, so they lose rows instead.
WIDE_ROW_LISTS = ("processes", "top_processes", "units", "listening", "listeners")
# Never dropped from such rows: what identifies the object and, for a JVM,
# what it runs, its heap limits and its resident memory (a memory alert is
# answered by RSS against -Xmx; ps fields are otherwise the first to go).
ROW_KEPT = {
    "pid",
    "name",
    "application",
    "unit",
    "comm",
    "port",
    "main",
    "heap",
    "rss_KiB",
}
# Rows at or below this average size are lean; past it rows are cut instead.
ROW_CHARS = 160
# Log tool replies are ranked lists (error templates, routes, exceptions) and
# time series; a series keeps evenly spaced points, a ranked list its head.
LOG_SERIES = {"trend", "buckets", "timeline"}
# (items per list, characters per string), tried in order until the view fits.
LOG_STEPS = ((20, 400), (10, 240), (5, 160), (3, 120), (1, 80))


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


def _shrink_lists(value, keep):
    """Copy of ``value`` with every listed list cut to ``keep`` items and a note."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in SSH_LIST_KEYS and isinstance(item, list) and len(item) > keep:
                result[key] = [_shrink_lists(x, keep) for x in item[:keep]]
                result[key + "_omitted"] = len(item) - keep
            elif key in SSH_LIST_KEYS and isinstance(item, dict):
                result[key] = {
                    k: (v[:keep] if isinstance(v, list) and len(v) > keep else v)
                    for k, v in item.items()
                }
            else:
                result[key] = _shrink_lists(item, keep)
        return result
    if isinstance(value, list):
        return [_shrink_lists(x, keep) for x in value]
    return value


def _row_sizes(value, sizes):
    """Characters per field over the rows of WIDE_ROW_LISTS ("" counts rows)."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in WIDE_ROW_LISTS and isinstance(item, list):
                for row in item:
                    if isinstance(row, dict):
                        sizes[""] += 1
                        for field, data in row.items():
                            sizes[field] += len(field) + len(
                                json.dumps(data, ensure_ascii=False)
                            )
            else:
                _row_sizes(item, sizes)
    elif isinstance(value, list):
        for item in value:
            _row_sizes(item, sizes)


def _map_rows(value, change):
    """Copy of ``value`` whose WIDE_ROW_LISTS rows went through ``change``."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in WIDE_ROW_LISTS and isinstance(item, list):
                result[key] = [
                    change(row) if isinstance(row, dict) else row for row in item
                ]
            else:
                result[key] = _map_rows(item, change)
        return result
    if isinstance(value, list):
        return [_map_rows(x, change) for x in value]
    return value


def _set_members(row):
    """``row`` without null or empty members, nested ones included."""
    result = {}
    for key, item in row.items():
        if isinstance(item, dict):
            item = _set_members(item)
        if item not in (None, "", [], {}):
            result[key] = item
    return result


def _noted(view, emptied, dropped):
    """``view`` with a note on what its rows leave out."""
    left_out = ["值为空的字段（未设置或未采集到）"] if emptied else []
    if dropped:
        left_out.append("字段：" + "、".join(dropped))
    if not left_out:
        return view
    return {
        **view,
        "fields_note": "为列出全部行，每行省略了"
        + "及".join(left_out)
        + "；完整内容在任务证据中",
    }


def _slim_rows(view, max_chars):
    """Keep every row of wide inventories: leave out members that are not set,
    then drop the bulkiest row fields, largest total first, until the view
    with its note fits or rows are lean. Thirteen Java processes would
    otherwise leave room for ten: each heap carries four unset options and
    each row its command line, log paths and -XX flags."""
    slim = _map_rows(view, _set_members)
    emptied, view = slim != view, slim
    sizes = Counter()
    _row_sizes(view, sizes)
    rows = sizes.pop("", 0)
    remaining, dropped = sum(sizes.values()), []
    for field, total in sizes.most_common():
        if (
            _fits(_noted(view, emptied, dropped), max_chars)
            or not rows
            or remaining / rows <= ROW_CHARS
        ):
            break
        if field in ROW_KEPT:
            continue
        dropped.append(field)
        remaining -= total
        view = _map_rows(view, lambda row: {k: v for k, v in row.items() if k != field})
    return _noted(view, emptied, dropped)


def ssh_view(outcome, max_chars):
    """SSH results keep their structure: drop raw text, then shorten lists.

    A JSON document cut in the middle cannot be cited; the model gets whole
    findings/summary objects with shortened lists and an ``_omitted`` count.
    """
    view = trimmed_processes(outcome)
    if _fits(view, max_chars):
        return view
    data = view.get("data") if isinstance(view, dict) else None
    if isinstance(data, dict) and ("output" in data or "stderr" in data):
        view = {
            **view,
            "data": {k: v for k, v in data.items() if k not in ("output", "stderr")},
        }
        view["data"]["output_note"] = "原文已省略，完整内容在任务证据中"
        if _fits(view, max_chars):
            return view
    view = _slim_rows(view, max_chars)
    if _fits(view, max_chars):
        return view
    # As many rows as fit; even one row per list may not, and that view is the
    # smallest.
    for keep in range(20, 0, -1):
        shorter = {
            **_shrink_lists(view, keep),
            "view_note": "列表已按模型视图上限截短；完整证据在任务记录中",
        }
        if _fits(shorter, max_chars):
            break
    return shorter


def _log_cut(value, keep, chars):
    """Copy with every list cut to ``keep`` items and every string to ``chars``
    characters; ``<key>_omitted`` counts the items left out."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if isinstance(item, list) and len(item) > keep:
                if key in LOG_SERIES and keep >= 2:
                    last = len(item) - 1
                    rows = [
                        item[i]
                        for i in sorted(
                            {round(n * last / (keep - 1)) for n in range(keep)}
                        )
                    ]
                else:
                    rows = item[:keep]
                result[key] = [_log_cut(row, keep, chars) for row in rows]
                result[key + "_omitted"] = len(item) - len(rows)
            else:
                result[key] = _log_cut(item, keep, chars)
        return result
    if isinstance(value, list):
        return [_log_cut(item, keep, chars) for item in value]
    if isinstance(value, str) and len(value) > chars:
        return value[:chars] + "…"
    return value


def log_view(outcome, max_chars):
    """Log replies keep whole entries: shorter lists and sample lines rather
    than a JSON document cut in the middle, which could not be cited."""
    if _fits(outcome, max_chars):
        return outcome
    # The note counts against the limit too (a view that only fits without
    # it would be cut in the middle after all).
    note = "列表与日志原文已按模型视图上限截短；完整证据在任务记录中"
    for keep, chars in LOG_STEPS:
        view = {**_log_cut(outcome, keep, chars), "view_note": note}
        if _fits(view, max_chars):
            break
    return view


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


def _clock(row):
    try:
        return int(row.get("clock"))
    except (TypeError, ValueError, AttributeError):
        return None


def _local(stamp):
    return datetime.fromtimestamp(stamp, BEIJING).strftime("%Y-%m-%d %H:%M:%S")


def _segment(rows, metric):
    values = _numbers(rows, (metric,)).get(metric)
    if not values:
        return None
    clocks = [c for c in (_clock(r) for r in rows) if c is not None]
    return {
        "count": values["numeric_count"],
        "min": values["min"],
        "avg": values["avg"],
        "max": values["max"],
        **({"from": _local(min(clocks)), "to": _local(max(clocks))} if clocks else {}),
    }


def _series(itemid, rows, metrics, size, event_clock=None):
    """Statistics cover every row; ``size`` evenly spaced samples keep the endpoints.

    With the alert moment the series is also split into before/after segments,
    so the model can state whether the value rose at the alert or earlier.
    """
    last = len(rows) - 1
    picks = (
        sorted({0, last} | {round(i * last / (size - 1)) for i in range(size)})
        if size >= 2
        else []
    )
    sample = []
    for i in picks:
        row = {key: value for key, value in rows[i].items() if key != "itemid"}
        clock = _clock(rows[i])
        if clock is not None:
            row["local_time"] = _local(clock)
        sample.append(row)
    result = {
        "itemid": itemid,
        "record_count": len(rows),
        "numeric_summary": _numbers(rows, metrics),
        "sample_records": sample,
        "sample_only": len(sample) < len(rows),
    }
    clocks = [c for c in (_clock(r) for r in rows) if c is not None]
    if clocks:
        result["covered"] = {"from": _local(min(clocks)), "to": _local(max(clocks))}
    if event_clock and metrics == ("value",) and clocks:
        before = [r for r in rows if (_clock(r) or 0) < event_clock]
        after = [r for r in rows if (_clock(r) or 0) >= event_clock]
        segments = {
            "alert_at": _local(event_clock),
            "before": _segment(before, "value"),
            "after": _segment(after, "value"),
        }
        nearest = min(rows, key=lambda r: abs((_clock(r) or 0) - event_clock))
        segments["at_alert"] = {
            "value": nearest.get("value"),
            "local_time": _local(_clock(nearest)),
        }
        result["alert_split"] = segments
    return result


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


def model_view(provider, tool, outcome, max_chars=None, event_clock=None):
    """Remove duplicate text/records and summarize large history arrays.

    Samples must be labelled as partial; do not treat samples as a complete
    series, and keep all original evidence in the encrypted task store.
    With ``max_chars`` the view shrinks samples or rows to fit, so every series
    keeps its statistics instead of being cut out of the middle later.
    """
    if tool == "list_mcp_tools":
        return fit_definitions(outcome, max_chars or SCHEMA_CHARS)
    if provider == "ssh_mcp":
        return ssh_view(outcome, max_chars)
    if provider == "logs":
        return log_view(outcome, max_chars)
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
        if outcome.get("limit_reached"):
            result["note"] += "；本次返回达到行数上限，covered 为实际覆盖区间"
        for size in SAMPLE_SIZES:
            result["series"] = [
                _series(itemid, rows, metrics, size, event_clock)
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


def _zabbix_signal(evidence_id, metric, value, hint, level="warning"):
    return {
        "source": "zabbix_mcp",
        "evidence_id": evidence_id,
        "level": level,
        "metric": metric,
        "value": value,
        "hint": hint,
    }


def _history_signals(collected, event_clock):
    """Alert window versus 7-day baseline and before/after the alert moment."""
    signals = []
    history = {}
    trend = {}
    for provider, tool, outcome, evidence_id in collected:
        if provider != "zabbix_mcp" or not isinstance(outcome, dict):
            continue
        series = {"history_get": history, "trend_get": trend}.get(tool)
        if series is None or outcome.get("is_error"):
            continue
        for row in outcome.get("records") or []:
            if isinstance(row, dict):
                ident = str(row.get("itemid", ""))
                series.setdefault(ident, {"rows": [], "evidence_id": evidence_id})
                series[ident]["rows"].append(row)
    for ident, item in history.items():
        rows = item["rows"]
        window = _numbers(rows, ("value",)).get("value")
        if not window or window["numeric_count"] < 3:
            continue
        base = _numbers(trend.get(ident, {}).get("rows", []), ("value_avg",)).get(
            "value_avg"
        )
        if base and base["avg"] > 0:
            ratio = window["avg"] / base["avg"]
            value = {
                "itemid": ident,
                "window_avg": round(window["avg"], 4),
                "baseline_avg": round(base["avg"], 4),
                "ratio": round(ratio, 2),
            }
            if ratio >= 1.5:
                signals.append(
                    _zabbix_signal(
                        item["evidence_id"],
                        "alert_vs_baseline",
                        value,
                        f"监控项 {ident} 告警窗口均值是近 7 天小时均值的 {ratio:.1f} 倍：属于突发升高而非常态",
                    )
                )
            elif ratio <= 1.1:
                signals.append(
                    _zabbix_signal(
                        item["evidence_id"],
                        "alert_vs_baseline",
                        value,
                        f"监控项 {ident} 告警窗口均值与近 7 天基线接近（{ratio:.2f} 倍）：长期处于该水平，更可能是容量或阈值问题",
                        level="info",
                    )
                )
        if event_clock:
            before = _segment(
                [r for r in rows if (_clock(r) or 0) < event_clock], "value"
            )
            after = _segment(
                [r for r in rows if (_clock(r) or 0) >= event_clock], "value"
            )
            if before and after and before["count"] >= 2 and after["count"] >= 2:
                value = {
                    "itemid": ident,
                    "before_avg": round(before["avg"], 4),
                    "after_avg": round(after["avg"], 4),
                }
                if before["avg"] > 0 and after["avg"] / before["avg"] >= 1.5:
                    signals.append(
                        _zabbix_signal(
                            item["evidence_id"],
                            "rise_at_alert",
                            value,
                            f"监控项 {ident} 告警后均值是告警前的 {after['avg'] / before['avg']:.1f} 倍：异常在告警时刻附近开始",
                            level="info",
                        )
                    )
                elif before["max"] > 0 and before["avg"] >= 0.9 * after["avg"]:
                    signals.append(
                        _zabbix_signal(
                            item["evidence_id"],
                            "elevated_before_alert",
                            value,
                            f"监控项 {ident} 告警前 30 分钟已处于相近水平：问题早于告警时刻出现，触发只是跨过阈值",
                            level="info",
                        )
                    )
    return signals


def _event_signals(collected):
    for provider, tool, outcome, evidence_id in collected:
        if provider != "zabbix_mcp" or tool != "event_get":
            continue
        if not isinstance(outcome, dict) or outcome.get("is_error"):
            continue
        problems = [
            row
            for row in outcome.get("records") or []
            if isinstance(row, dict) and str(row.get("value")) == "1"
        ]
        if len(problems) >= 3:
            return [
                _zabbix_signal(
                    evidence_id,
                    "recurrence",
                    {"problem_events_24h": len(problems)},
                    f"该触发器近 24 小时触发了 {len(problems)} 次：反复抖动或阈值贴近常态，应核对基线与阈值而不只是本次峰值",
                )
            ]
    return []


def _log_signals(collected):
    """Alert-window error logs against the previous window of the same length,
    and error templates first seen in the window (from log_overview)."""
    signals = []
    for provider, tool, outcome, evidence_id in collected:
        if provider != "logs" or tool != "log_overview":
            continue
        data = outcome.get("data") if isinstance(outcome, dict) else None
        if not isinstance(data, dict) or outcome.get("is_error"):
            continue
        errors, before = data.get("errors"), data.get("previous_window_errors")
        if (
            type(errors) is int
            and type(before) is int
            and errors >= max(10, 2 * before)
        ):
            signals.append(
                {
                    "source": "logs",
                    "evidence_id": evidence_id,
                    "level": "warning",
                    "metric": "error_surge",
                    "value": {"errors": errors, "previous_window_errors": before},
                    "hint": (
                        f"告警窗口错误日志 {errors} 条，是上一等长窗口（{before} 条）的 {errors / before:.1f} 倍"
                        if before
                        else f"告警窗口错误日志 {errors} 条，上一等长窗口没有错误日志"
                    )
                    + "：错误与告警同期出现，核对错误模板与告警时刻的先后",
                }
            )
        new = [
            row
            for row in data.get("top_errors") or []
            if isinstance(row, dict) and row.get("new") is True
        ]
        if new:
            signals.append(
                {
                    "source": "logs",
                    "evidence_id": evidence_id,
                    "level": "info",
                    "metric": "new_error_templates",
                    "value": {
                        "count": len(new),
                        "templates": [
                            str(row.get("template") or "")[:120] for row in new[:3]
                        ],
                    },
                    "hint": f"窗口内有 {len(new)} 个首次出现的错误模板：新出现的错误比一直存在的错误更可能与本次告警相关",
                }
            )
    return signals


def derive_signals(collected, event_clock=None):
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
                            **(
                                {"source_action": finding["source_action"]}
                                if finding.get("source_action")
                                else {}
                            ),
                        }
                    )

    # Whether the host's items are still being collected: for "agent not
    # available" alerts this separates a dead host from a stopped agent, and
    # SSH is not an option on Windows or network devices.
    if len(clocks) >= 3:
        now = int(time.time())
        fresh = sum(1 for clock in clocks if now - clock <= FRESH_SECONDS)
        newest = datetime.fromtimestamp(max(clocks), BEIJING)
        signals.append(
            _zabbix_signal(
                clock_evidence,
                "collection_freshness",
                {
                    "items": len(clocks),
                    "updated_within_10m": fresh,
                    "newest_lastclock_local": newest.isoformat(),
                },
                f"该主机 {len(clocks)} 个监控项全部停止更新，最后一次采集在 "
                f"{newest.strftime('%H:%M:%S')}"
                "：整机不可达或 Zabbix 到该主机的采集链路中断，而不只是单个监控项"
                if fresh == 0
                else f"该主机 {fresh}/{len(clocks)} 个监控项在最近 10 分钟内仍有新数据：主机或采集链路至少部分可用，问题更可能在未更新的那部分（如 agent 服务本身）",
                level="warning" if fresh == 0 else "info",
            )
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
            _zabbix_signal(
                latest["system.cpu.util"][1],
                "load_cpu_divergence",
                {
                    "load_per_core_5m": round(load5 / cores, 2),
                    "cpu_util_percent": round(util, 2),
                },
                "Zabbix 最新值：每核 5 分钟负载偏高但 CPU 利用率不高，负载可能来自 D 状态任务或宿主机 CPU 争抢，而不是计算繁忙",
            )
        )
    for key, (value, evidence_id) in latest.items():
        try:
            figure = float(value)
        except (TypeError, ValueError):
            continue
        if key.startswith("vm.memory.utilization") and figure >= 90:
            signals.append(
                _zabbix_signal(
                    evidence_id,
                    "memory_utilization",
                    {"key": key, "percent": round(figure, 2)},
                    "Zabbix 最新内存利用率已超过 90%：核对 RSS 排行与 OOM 记录",
                )
            )
        elif key.startswith("vfs.fs") and "pused" in key and figure >= 90:
            signals.append(
                _zabbix_signal(
                    evidence_id,
                    "filesystem_utilization",
                    {"key": key, "percent": round(figure, 2)},
                    "文件系统使用率超过 90%：核对增长来源与目录占用",
                )
            )
    signals.extend(_history_signals(collected, event_clock))
    signals.extend(_event_signals(collected))
    signals.extend(_log_signals(collected))
    return signals[:14]


def model_alert(event):
    """Alert fields for the model without unexpanded Zabbix macros.

    Problem notifications carry {EVENT.RECOVERY.*} literally; they hold no evidence.
    """
    return {
        key: value
        for key, value in (event or {}).items()
        if not (isinstance(value, str) and UNRESOLVED_MACRO.fullmatch(value.strip()))
    }
