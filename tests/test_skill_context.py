"""Protect model context compacting from loss of authoritative MCP evidence."""

from app.skill_context import model_view


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
