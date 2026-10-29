"""Evidence ids, code-checked citations and derived cross-check signals."""

import json

from app import evidence_check
from app.skill_context import derive_signals

INDEX = {
    "E1": {
        "provider": "ssh_mcp",
        "tool": "ssh_diagnose_cpu",
        "text": json.dumps(
            {"evidence_id": "E1", "data": {"load_1": 6.25, "cpu_busy_percent": 12.4}}
        ),
    },
    "E2": {
        "provider": "zabbix_mcp",
        "tool": "item_get",
        "text": json.dumps(
            {
                "evidence_id": "E2",
                "records": [{"key_": "system.cpu.num", "lastvalue": "4"}],
            }
        ),
    },
}


def answer(*evidence):
    return json.dumps(
        {
            "cause": "负载偏高",
            "evidence": [dict(zip(("id", "quote"), e)) for e in evidence],
        },
        ensure_ascii=False,
    )


def test_quote_numbers_must_occur_in_the_cited_evidence():
    result = evidence_check.check(
        answer(("E1", "load_1 6.25"), ("E1", "CPU 忙碌 12%"), ("E1", "load 9.8")), INDEX
    )
    assert result["method"] == "quote"
    # 12 is the quote's own precision for 12.4; 9.8 appears nowhere.
    assert [item["quote"] for item in result["valid"]] == [
        "load_1 6.25",
        "CPU 忙碌 12%",
    ]
    assert result["invalid"] == [
        {"id": "E1", "quote": "load 9.8", "reason": "证据中找不到引用的数值或原文"}
    ]
    assert result["confidence"] == "中"


def test_number_cited_from_the_wrong_evidence_is_rejected():
    # 6.25 is real, but only in E1; attributing it to E2 does not count.
    result = evidence_check.check(answer(("E2", "load 6.25"), ("E5", "4")), INDEX)
    assert result["valid"] == []
    assert [item["reason"] for item in result["invalid"]] == [
        "证据中找不到引用的数值或原文",
        "证据编号不存在",
    ]
    assert result["confidence"] == "低"


def test_confidence_is_high_only_with_two_providers():
    result = evidence_check.check(
        answer(("E1", "6.25"), ("E2", "system.cpu.num")), INDEX
    )
    assert result["confidence"] == "高"
    one_source = evidence_check.check(answer(("E1", "6.25"), ("E1", "12.4")), INDEX)
    assert one_source["confidence"] == "中"


def test_plain_text_answers_are_checked_by_reference():
    result = evidence_check.check("负载 6.25（E1），核数见 E2，另见 E9。", INDEX)
    assert result["method"] == "reference"
    assert [item["id"] for item in result["valid"]] == ["E1", "E2"]
    assert result["invalid"][0]["id"] == "E9"
    assert evidence_check.check("没有引用任何证据。", INDEX) is None


def test_rendered_section_lists_valid_and_rejected_citations():
    text = evidence_check.render(
        evidence_check.check(answer(("E1", "6.25"), ("E1", "9.8")), INDEX)
    )
    assert text.startswith("证据核对\n依据可信度：中")
    assert "- E1 SSH MCP / ssh_diagnose_cpu：“6.25”" in text
    assert "未通过核对、已剔除的引用" in text and "9.8" in text
    assert evidence_check.render(None) == ""


def test_scope_lists_target_collection_time_windows_and_sources():
    index = {
        "E1": {"provider": "ssh_mcp", "at": 1793237680, "window": None},
        "E2": {
            "provider": "zabbix_mcp",
            "at": 1793237700,
            "window": (1793236766, 1793237695),
        },
        "E3": {"provider": "zabbix_mcp", "at": 1793237710, "window": None},
    }
    text = evidence_check.scope(index, {"host_name": "db-01", "host_id": "11230"})
    assert text.splitlines() == [
        "诊断范围（平台生成）",
        "- 目标：db-01（Zabbix Host ID 11230）",
        "- 采集时间（北京时间）：2026-10-29 09:34:40 – 2026-10-29 09:35:10",
        "- Zabbix 历史查询窗口（北京时间）：2026-10-29 09:19:26 – 2026-10-29 09:34:55",
        "- 证据来源：SSH MCP 1 条、Zabbix MCP 2 条（E1–E3，详见证据与工具执行记录）",
    ]
    assert evidence_check.scope({}, {"host_name": "db-01"}) == ""


def test_alert_suggestion_lists_become_numbered_text():
    from app.mcp_runtime import readable_report_answer

    text = readable_report_answer(
        json.dumps(
            {"cause": "负载偏高（E2）", "action": ["核对批处理", "", "补查增量"]}
        )
    )
    assert text == "诊断结论\n负载偏高（E2）\n\n处理建议\n1. 核对批处理\n2. 补查增量"


def test_signals_surface_ssh_findings_and_zabbix_load_divergence():
    items = {
        "records": [
            {"key_": "system.cpu.load[all,avg5]", "lastvalue": "7.2"},
            {"key_": "system.cpu.num", "lastvalue": "4"},
            {"key_": "system.cpu.util", "lastvalue": "18.5"},
        ]
    }
    cpu = {
        "status": "success",
        "data": {
            "findings": [
                {"level": "info", "metric": "load_1"},
                {
                    "level": "warning",
                    "metric": "load_cpu_divergence",
                    "value": 1.8,
                    "threshold": 1.5,
                    "hint": "负载高但 CPU 不忙",
                },
            ]
        },
    }
    signals = derive_signals(
        [
            ("ssh_mcp", "ssh_diagnose_cpu", cpu, "E2"),
            ("zabbix_mcp", "item_get", items, "E3"),
        ]
    )
    assert [(s["source"], s["evidence_id"], s["metric"]) for s in signals] == [
        ("ssh_mcp", "E2", "load_cpu_divergence"),
        ("zabbix_mcp", "E3", "load_cpu_divergence"),
    ]
    assert signals[1]["value"] == {"load_per_core_5m": 1.8, "cpu_util_percent": 18.5}


def test_no_divergence_signal_when_the_cpu_is_actually_busy():
    items = {
        "records": [
            {"key_": "system.cpu.load[all,avg5]", "lastvalue": "7.2"},
            {"key_": "system.cpu.num", "lastvalue": "4"},
            {"key_": "system.cpu.util", "lastvalue": "96"},
        ]
    }
    assert derive_signals([("zabbix_mcp", "item_get", items, "E1")]) == []
    # Missing core count: no ratio, no signal, no error.
    partial = {"records": [{"key_": "system.cpu.util", "lastvalue": "5"}]}
    assert derive_signals([("zabbix_mcp", "item_get", partial, "E1")]) == []
