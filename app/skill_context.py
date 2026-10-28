"""Small, evidence-faithful model views of large MCP records.

Original sanitized tool results are written to diagnostic_evidence unchanged.
Only the model context receives a preview, never the authoritative report.
"""

from collections import defaultdict
from math import isfinite


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


def model_view(provider, tool, outcome):
    """Remove duplicate text/records and summarize large history arrays.

    Samples must be labelled as partial; do not treat samples as a complete
    series, and keep all original evidence in the encrypted task store.
    """
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
        result["series"] = []
        for itemid, rows in list(groups.items())[:8]:
            # Keep endpoints plus a few intermediate observations.
            selected = sorted(
                {0, len(rows) - 1} | {round(i * (len(rows) - 1) / 7) for i in range(8)}
            )
            sample = [rows[i] for i in selected]
            metrics = (
                ("value",)
                if tool == "history_get"
                else ("value_min", "value_avg", "value_max")
            )
            result["series"].append(
                {
                    "itemid": itemid,
                    "record_count": len(rows),
                    "numeric_summary": _numbers(rows, metrics),
                    "sample_records": sample,
                    "sample_only": len(sample) < len(rows),
                }
            )
        result["note"] = (
            "统计值由本次完整采集记录计算，样本并非全部历史点；完整证据在任务记录中"
        )
    else:
        result["records"] = records[:20]
        if len(records) > 20:
            result["sample_only"] = True
            result["note"] = "仅展示前 20 条记录；请缩小 Zabbix 查询条件以确认未展示项"
    return result
