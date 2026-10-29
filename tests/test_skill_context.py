"""Protect model context compacting from loss of authoritative MCP evidence."""

import json

from app.skill_context import fit_definitions, model_alert, model_view


def test_zabbix_history_uses_numeric_summary_and_no_duplicate_data_copy():
    payload = {
        "is_error": False,
        "data": "duplicate raw JSON data " * 300,
        "records": [
            {"itemid": "30", "clock": str(1000 + i * 60), "value": str(i)}
            for i in range(120)
        ],
        "truncated": True,
    }
    output = model_view("zabbix_mcp", "history_get", payload)
    assert output["total_records"] == 120
    assert "data" not in output
    assert output["series"][0]["record_count"] == 120
    assert output["series"][0]["numeric_summary"]["value"]["min"] == 0
    assert output["series"][0]["numeric_summary"]["value"]["max"] == 119
    assert output["series"][0]["sample_only"]
    assert len(output["series"][0]["sample_records"]) <= 8
    assert len(payload["records"]) == 120
    assert "duplicate" in payload["data"]


def test_multi_item_history_summarizes_each_item_without_leaking_metadata():
    rows = [
        {"itemid": "20", "clock": "123", "value": "not numeric"},
        {"itemid": "20", "clock": "124", "value": "3.5"},
        {"itemid": "21", "clock": "123", "value": "12.0"},
    ]
    result = model_view(
        "zabbix_mcp", "history_get", {"records": rows, "is_error": False}
    )
    assert [r["itemid"] for r in result["series"]] == ["20", "21"]
    assert result["series"][0]["numeric_summary"]["value"]["numeric_count"] == 1


def test_zabbix_nonhistory_truncation_is_explicit_and_errors_are_unchanged():
    value = {"records": [{"itemid": str(i)} for i in range(50)], "data": "same"}
    result = model_view("zabbix_mcp", "item_get", value)
    assert len(result["records"]) == 20
    assert result["total_records"] == 50
    assert result["sample_only"] is True
    assert len(value["records"]) == 50
    error = {"is_error": True, "records": [], "data": "connection failed"}
    assert model_view("zabbix_mcp", "history_get", error) is error
    ssh = {"records": [{"cpu": 20}], "data": "source"}
    assert model_view("ssh_mcp", "ssh_diagnose_cpu", ssh) is ssh


def test_trend_numeric_fields_and_non_numeric_values_do_not_fabricate_metrics():
    history = {
        "records": [
            {"itemid": "4", "value_min": "2", "value_avg": "5", "value_max": "10"},
            {"itemid": "4", "value_min": "3", "value_avg": "6", "value_max": "12"},
        ],
        "data": "duplicate",
    }
    result = model_view("zabbix_mcp", "trend_get", history)
    metrics = result["series"][0]["numeric_summary"]
    assert metrics["value_max"]["max"] == 12
    assert metrics["value_min"]["min"] == 2
    assert metrics["value_avg"]["avg"] == 5.5


def test_history_view_shrinks_samples_to_fit_and_keeps_every_series():
    # Five load/CPU items over 15 minutes used to exceed 4000 characters; the
    # middle cut then dropped the fourth series (iowait) and forced a re-query.
    rows = [
        {
            "itemid": str(item),
            "clock": str(1793236793 + i * 60),
            "clock_local": f"2026-10-29T09:{19 + i:02d}:53+08:00",
            "value": str(2.5 + i / 10),
        }
        for i in range(16)
        for item in (144053, 144054, 144060, 144062, 144065)
    ]
    output = model_view(
        "zabbix_mcp", "history_get", {"records": rows, "is_error": False}, 4000
    )
    assert len(json.dumps(output, ensure_ascii=False)) <= 4000
    assert [s["itemid"] for s in output["series"]] == [
        "144053",
        "144054",
        "144060",
        "144062",
        "144065",
    ]
    for series in output["series"]:
        assert series["numeric_summary"]["value"]["numeric_count"] == 16
        assert series["sample_only"] and len(series["sample_records"]) < 8
        assert all("itemid" not in row for row in series["sample_records"])
    roomy = model_view("zabbix_mcp", "history_get", {"records": rows}, 100000)
    assert len(roomy["series"][0]["sample_records"]) == 8


def test_record_view_shrinks_rows_to_fit_the_budget():
    rows = [{"itemid": str(i), "name": "Load average " * 10} for i in range(30)]
    output = model_view("zabbix_mcp", "item_get", {"records": rows}, 3000)
    assert len(json.dumps(output, ensure_ascii=False)) <= 3000
    assert len(output["records"]) in (10, 5) and output["sample_only"]
    assert "前 " + str(len(output["records"])) + " 条" in output["note"]


def test_schema_discovery_keeps_whole_tools_and_names_the_rest():
    schema = {"type": "object", "properties": {"x": {"description": "y" * 3000}}}
    outcome = {
        "tools": [
            {"name": name, "description": "", "parameters": schema}
            for name in ("item_get", "history_get", "event_get")
        ]
    }
    fitted = fit_definitions(outcome, 7000)
    assert [tool["name"] for tool in fitted["tools"]] == ["item_get", "history_get"]
    assert fitted["tools"][1]["parameters"] == schema
    assert fitted["omitted_tools"] == ["event_get"] and "event_get" in fitted["note"]
    assert len(json.dumps(fitted, ensure_ascii=False)) <= 7000
    assert model_view("zabbix_mcp", "list_mcp_tools", outcome, 100000) is outcome
    names = {"tools": [{"name": f"ssh_diagnose_{i}"} for i in range(40)]}
    assert fit_definitions(names, 200)["tools"] == names["tools"]


def test_model_alert_drops_only_unexpanded_zabbix_macros():
    event = {
        "event_id": "6619496",
        "recovery_date": "{EVENT.RECOVERY.DATE}",
        "recovery_id": " {EVENT.RECOVERY.ID} ",
        "user_macro": "{$CPU.LOAD.MAX}",
        "event_duration": "0s",
        "message": "恢复时间：{EVENT.RECOVERY.TIME}\n监控数据：3.28",
    }
    assert model_alert(event) == {
        "event_id": "6619496",
        "event_duration": "0s",
        "message": "恢复时间：{EVENT.RECOVERY.TIME}\n监控数据：3.28",
    }
    assert "recovery_date" in event and model_alert(None) == {}


def test_ssh_process_lists_keep_busy_rows_only_and_leave_the_evidence_whole():
    rows = [
        {"pid": i, "name": "postgres", "cpu_percent": 13.0 - i, "memory_percent": 28.0}
        for i in range(10)
    ]
    rows += [
        {"pid": 100 + i, "name": "kworker", "cpu_percent": 0.0, "memory_percent": 0.0}
        for i in range(30)
    ]
    rows.append({"pid": 999, "name": "java", "cpu_percent": 0.0, "cpu_interval": 45.5})
    outcome = {"is_error": False, "data": {"summary": {"processes": rows}}}
    shown = model_view("ssh_mcp", "ssh_diagnose_processes", outcome)["data"]["summary"]
    assert [row["pid"] for row in shown["processes"]] == [*range(10), 999]
    assert (shown["processes_shown"], shown["processes_total"]) == (11, 41)
    assert len(outcome["data"]["summary"]["processes"]) == 41
    small = {"data": {"summary": {"processes": rows[:5]}}}
    assert model_view("ssh_mcp", "ssh_diagnose_processes", small) is small
