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


def test_collection_freshness_signal_separates_dead_hosts_from_stopped_agents(
    monkeypatch,
):
    from types import SimpleNamespace
    from app import skill_context

    now = 1_793_274_921  # 2026-10-29 19:55:21 Beijing time
    monkeypatch.setattr(skill_context, "time", SimpleNamespace(time=lambda: now))

    def items(*ages):
        return {
            "records": [
                {"itemid": str(i), "key_": f"k{i}", "lastclock": str(now - age)}
                for i, age in enumerate(ages)
            ]
        }

    [stale] = skill_context.derive_signals(
        [("zabbix_mcp", "item_get", items(1700, 1650, 1600), "E8")]
    )
    assert stale["metric"] == "collection_freshness" and stale["level"] == "warning"
    assert stale["evidence_id"] == "E8"
    assert stale["value"] == {
        "items": 3,
        "updated_within_10m": 0,
        "newest_lastclock_local": "2026-10-29T19:28:41+08:00",
    }
    assert "全部停止更新" in stale["hint"] and "19:28:41" in stale["hint"]
    [mixed] = skill_context.derive_signals(
        [("zabbix_mcp", "item_get", items(1700, 60, 30), "E2")]
    )
    assert mixed["level"] == "info" and mixed["value"]["updated_within_10m"] == 2
    assert "2/3" in mixed["hint"]
    # Too few items to say anything about the host.
    assert (
        skill_context.derive_signals([("zabbix_mcp", "item_get", items(60, 30), "E2")])
        == []
    )


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


def java_row(index):
    """One process of a Java inventory, shaped like production rows (~1000 chars)."""
    name = f"svc-{index:02d}"
    jar = f"/data/jar/{name}/{name}_445.jar"
    flags = [
        "-XX:+UseG1GC",
        "-XX:+HeapDumpOnOutOfMemoryError",
        f"-XX:HeapDumpPath=/data/logs/dump/{name}/",
    ]
    return {
        "pid": 30000 + index,
        "user": "root",
        "elapsed_seconds": 106000,
        "rss_KiB": 1500000 - index * 1000,
        "cpu_percent": 1.5,
        "mem_percent": 9.4,
        "threads": 120,
        "fds": 300,
        "fd_limit": 65535,
        "unit": "supervisord.service",
        "container": None,
        "cwd": f"/data/jar/{name}",
        "exe": "/usr/local/jdk1.8.0_271/bin/java",
        "java_version": "1.8.0_271",
        "implementor": "Oracle Corporation",
        "main": {"kind": "jar", "name": jar},
        "application": f"{name}_445",
        "profiles": ["prod"],
        "heap": {"xms": "256m", "xmx": "1024m", "max_metaspace": "256m"},
        "gc": {"collector": "G1", "gc_log": None, "xx_flags": flags},
        "logs": {
            "configured": [f"logging.file.name=/data/logs/app-{name}.log"],
            "open_files": [
                f"/data/logs/app-{name}.log",
                f"/data/logs/error-{name}.log",
                f"/data/logs/{name}/dledger/dledger.log",
            ],
        },
        "cgroup_memory_limit_bytes": None,
        "system_properties_count": 6,
        "command_preview": " ".join(
            ["java -jar -Xms256m -Xmx1024m", *flags, *flags, *flags, jar]
        )[:400],
        "args_truncated": False,
    }


def test_wide_inventory_rows_lose_bulky_fields_before_rows():
    """Thirteen Java processes in a 6000-character view: every process stays
    listed with its identity, heap and memory; command lines and log paths go.
    Production (v1.3.0) showed the model one process out of thirteen."""
    rows = [java_row(index) for index in range(13)]
    outcome = {
        "is_error": False,
        "data": {
            "status": "success",
            "summary": {"title": "Java 进程", "java_processes": 13, "processes": rows},
            "output": "raw " * 900,
        },
    }
    view = model_view("ssh_mcp", "ssh_diagnose_java", outcome, max_chars=6000)
    assert len(json.dumps(view, ensure_ascii=False)) <= 6000
    shown = view["data"]["summary"]["processes"]
    assert [row["pid"] for row in shown] == [row["pid"] for row in rows]
    for row in shown:
        assert {"pid", "application", "unit"} <= set(row)
        assert "command_preview" not in row and "logs" not in row
    assert "command_preview" in view["fields_note"]
    assert "rss_KiB" in shown[0] and shown[0]["heap"]["xmx"] == "1024m"
    # The stored evidence is untouched.
    assert "command_preview" in outcome["data"]["summary"]["processes"][0]


def test_log_rows_keep_their_text_and_lose_rows_instead():
    entries = [
        {"time": f"2026-10-31T07:0{i % 10}:00", "message": "kernel: oom " + "x" * 400}
        for i in range(40)
    ]
    outcome = {"data": {"summary": {"entries": entries}}}
    view = model_view("ssh_mcp", "ssh_diagnose_syslog", outcome, max_chars=6000)
    shown = view["data"]["summary"]["entries"]
    assert 0 < len(shown) < 40 and all("message" in row for row in shown)
    assert "fields_note" not in view
