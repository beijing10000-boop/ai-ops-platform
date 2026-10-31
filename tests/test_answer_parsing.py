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
