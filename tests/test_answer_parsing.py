"""Structured answers wrapped in a heading or fence are still structured."""

import json

from app import worker
from app.evidence_check import answer_object, check
from app.mcp_runtime import readable_report_answer

ANSWER = {
    "cause": "1 核主机 5 分钟负载 2.19，超过每核阈值 1.5（E1）。",
    "action": ["核查告警前后的进程", "修复 SSH 诊断通道"],
    "analysis": "CPU 利用率仅 22.12%，iowait 接近 0（E1）。",
    "evidence": [{"id": "E1", "quote": "2.19"}],
}
# Seen in production (v1.3.0): a heading before the fenced JSON object.
HEADED = "## 诊断结果\n\n```json\n" + json.dumps(ANSWER, ensure_ascii=False) + "\n```"


def test_structured_answer_found_after_a_heading_or_in_a_fence():
    bare = json.dumps(ANSWER, ensure_ascii=False)
    for text in (
        bare,
        "```json\n" + bare + "\n```",
        HEADED,
        "以下是结论：\n" + bare + "\n以上。",
    ):
        assert answer_object(text) == ANSWER, text[:30]


def test_raw_line_breaks_inside_strings_still_parse():
    """Production (v1.4.0): the model broke "cause" across lines inside the
    JSON string. Strict JSON rejected the whole answer, so the Feishu card
    showed the first line of the raw JSON as its conclusion and the fallback
    action instead of the model's."""
    raw = (
        '{"host_groups": ["Linux servers"], "cause": "PostgreSQL 多进程持续消耗 CPU：\n\n'
        '1. 5 分钟负载 3.43（E1）\n2. CPU 利用率 92%（E2）", '
        '"action": ["核查慢查询"], "analysis": "负载与 CPU 同步上升（E1）。"}'
        "\n\n诊断范围\n- E1 Zabbix MCP / history_get"
    )
    parsed = answer_object(raw)
    assert parsed["cause"].startswith("PostgreSQL") and "\n2. CPU" in parsed["cause"]
    assert parsed["action"] == ["核查慢查询"]
    card = worker.card_summary(parsed)
    assert "核查慢查询" in card and "host_groups" not in card
    assert readable_report_answer(raw).startswith("诊断结论\n")


def test_answer_with_a_lost_bracket_or_cut_short_still_parses():
    """Production (v1.4.1, a memory alert): the model never closed "findings",
    so "evidence" landed inside it and the outer object stayed open; the card
    showed a line of raw JSON in bytes with evidence ids, and a generic
    suggestion instead of the model's six."""
    lost = (
        '{"host_groups": "Linux servers", "cause": "可用内存仅 1587232768 B（E5，E7）。", '
        '"action": ["核对 13 个 JVM 的 -Xmx 之和"], "analysis": "逐步抬升（E8）。", '
        '"findings": {"confirmed": [{"statement": "可用 9.44%", "evidence": ["E5"]}], '
        '"hypotheses": [], '
        '"evidence": [{"id": "E5", "quote": "lastvalue 90.559619"}]}'
        "\n\n诊断范围（平台生成）\n- 目标：host"
    )
    parsed = answer_object(lost)
    assert parsed["action"] == ["核对 13 个 JVM 的 -Xmx 之和"]
    # "evidence" is back at the top level, so the citations are still checked.
    assert parsed["evidence"] == [{"id": "E5", "quote": "lastvalue 90.559619"}]
    assert "evidence" not in parsed["findings"]
    index = {
        "E5": {
            "provider": "zabbix_mcp",
            "tool": "item_get",
            "text": "lastvalue 90.559619",
        }
    }
    assert [item["id"] for item in check(lost, index)["valid"]] == ["E5"]
    assert worker.card_summary(parsed) == (
        "**诊断结论**\n可用内存仅 1.48 GiB。\n\n**处理建议**\n1. 核对 13 个 JVM 的 -Xmx 之和"
    )
    # Output cut short inside a later field keeps the fields before it.
    cut = (
        '{"cause": "/ 使用率 91.20%（E1）。", "action": ["清理 /var/log 下的旧日志"], '
        '"analysis": "近 7 天每天增长约 1'
    )
    parsed = answer_object(cut)
    assert parsed["cause"] == "/ 使用率 91.20%（E1）。"
    assert parsed["action"] == ["清理 /var/log 下的旧日志"]
    # A stray quote breaks one field; the whole ones are still taken.
    stray = (
        '{"cause": "内存不足（E5）。", "action": ["重启 dsp-api"], '
        '"analysis": "他说"内存"不足", "findings": {}}'
    )
    assert answer_object(stray) == {
        "cause": "内存不足（E5）。",
        "action": ["重启 dsp-api"],
    }


def test_prose_quoting_json_stays_prose():
    assert answer_object("纯文本结论") is None
    assert answer_object('日志里有 {"level": "error"} 一行') is None
    assert answer_object("") is None and answer_object(None) is None


def test_headed_answer_renders_as_report_and_checks_citations():
    report = readable_report_answer(HEADED)
    assert report.startswith("诊断结论\n") and "处理建议" in report
    assert "```" not in report and "## 诊断结果" not in report
    index = {
        "E1": {"provider": "zabbix_mcp", "tool": "history_get", "text": "load 2.19"}
    }
    assert [item["id"] for item in check(HEADED, index)["valid"]] == ["E1"]


def test_unstructured_card_skips_headings_and_fences():
    text = worker.card_summary(
        {
            "cause": "分析结果需要人工复核",
            "action": "请检查告警相关指标及服务日志",
            "analysis": "## 诊断结果\n\n```\nAI 模型请求超时；模型未完成最终诊断。",
            "_unstructured": True,
            "_diagnostic_status": "partial",
        }
    )
    assert "**诊断结论**\nAI 模型请求超时；模型未完成最终诊断。\n" in text
