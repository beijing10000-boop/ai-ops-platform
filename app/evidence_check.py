"""Code-checked evidence citations and rule-capped confidence for diagnosis reports.

Every MCP result the model sees carries an evidence id (E1, E2, ...). The final
answer cites ids with a short quote; a citation counts only when the id exists
and every number in the quote appears in that evidence (at the quote's own
precision), so a value cannot be attributed to evidence that does not contain
it. Confidence is derived from the valid citations, never from the model.
"""

from datetime import datetime
import json
import re
from zoneinfo import ZoneInfo

BEIJING = ZoneInfo("Asia/Shanghai")
NUMBER = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?")
CITED_ID = re.compile(r"\bE(\d{1,3})\b")
PROVIDER_LABELS = {"ssh_mcp": "SSH MCP", "zabbix_mcp": "Zabbix MCP"}


def _numbers(text):
    return [match.group(0) for match in NUMBER.finditer(str(text))]


def _grounded(quote, evidence_text):
    """All numbers of the quote occur in the evidence; otherwise text containment."""
    wanted = _numbers(quote)
    if not wanted:
        squeeze = lambda value: re.sub(r"[\s\"'{}\[\]:,，：]", "", str(value))  # noqa: E731
        return len(squeeze(quote)) >= 2 and squeeze(quote) in squeeze(evidence_text)
    available = [float(value) for value in _numbers(evidence_text)]
    for raw in wanted:
        value = float(raw)
        decimals = len(raw.split(".")[1]) if "." in raw else 0
        tolerance = 0.5 * 10**-decimals
        if not any(abs(candidate - value) <= tolerance for candidate in available):
            return False
    return True


def confidence(valid):
    providers = {item["provider"] for item in valid}
    if len(valid) >= 2 and len(providers) >= 2:
        return "高"
    return "中" if valid else "低"


def check(answer, index):
    """Return {valid, invalid, confidence, method} or None when nothing is cited.

    `index` maps evidence ids to {"provider", "tool", "text"} as the model saw them.
    """
    try:
        parsed = json.loads(
            re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", answer.strip())
        )
    except (AttributeError, TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("evidence"), list):
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
        return {
            "method": "quote",
            "valid": valid,
            "invalid": invalid,
            "confidence": confidence(valid),
        }
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
        if ident in index
    ]
    return {
        "method": "reference",
        "valid": valid,
        "invalid": [
            {"id": ident, "quote": "", "reason": "证据编号不存在"}
            for ident in cited
            if ident not in index
        ],
        "confidence": confidence(valid),
    }


def scope(index, target):
    """Target, collection time, queried windows and sources, rendered by the platform
    so the final model round does not have to restate them."""
    if not index:
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
        counts[label] = counts.get(label, 0) + 1
    first, last = next(iter(index)), next(reversed(index))
    lines.append(
        "- 证据来源："
        + "、".join(f"{label} {count} 条" for label, count in counts.items())
        + f"（{first}{'–' + last if last != first else ''}，详见证据与工具执行记录）"
    )
    return "\n".join(lines)


def render(result):
    """Markdown section appended to the report; empty when nothing was cited."""
    if not result:
        return ""
    lines = [
        "证据核对",
        f"依据可信度：{result['confidence']}（平台核对引用后评定："
        "两类数据源各有有效引用为高，有有效引用为中，没有为低）",
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
    return "\n".join(lines)
