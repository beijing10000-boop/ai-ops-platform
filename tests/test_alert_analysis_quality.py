"""2026-11 alert-analysis review: what the model was missing or tripped over in
80 real alert analyses (AP walk "采集中断" alerts that never saw the item's
10-second interval, agent availability read as "2 = available", windows the
tools refused, linked alerts nobody looked at)."""

import json
import time

import pytest

from app import alert_history, main, skill_mcp
from app.integrations import zabbix
from app.orchestrator import tasks
from app.skill_context import _with_meanings, derive_signals, model_view
from app.skill_runtime import fill_arguments, mount_point


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")


# --- Zabbix: diagnostic fields, flags, per-object search, answerable windows ---


def test_collection_state_and_trigger_expression_are_readable():
    args = zabbix.validate_args(
        "item_get",
        {
            "hostids": ["11187"],
            "triggerids": ["81743"],
            "output": ["itemid", "key_", "delay", "type", "state", "error", "status"],
            "selectValueMap": ["name", "mappings"],
        },
        host_id="11187",
    )
    assert args["selectValueMap"] == ["name", "mappings"]
    trigger = zabbix.validate_args(
        "trigger_get",
        {
            "triggerids": ["81743"],
            "output": ["triggerid", "expression", "comments", "opdata"],
            "expandExpression": True,
        },
        host_id="11187",
    )
    assert trigger["expandExpression"] is True
    # Interface availability and its error, for "agent is not available".
    zabbix.validate_args(
        "hostinterface_get",
        {"hostids": ["1"], "output": ["available", "error", "errors_from"]},
        host_id="1",
    )
    # Credentials stay out of reach.
    for name, field in (("item_get", "snmp_community"), ("item_get", "password")):
        with pytest.raises(ValueError):
            zabbix.validate_args(name, {"output": [field]})
    with pytest.raises(ValueError, match="true 或 false"):
        zabbix.validate_args("trigger_get", {"expandExpression": "yes"})


def test_default_item_output_includes_state_and_error_only():
    args = zabbix.validate_args("item_get", {"hostids": ["1"]}, host_id="1")
    assert "state" in args["output"] and "error" in args["output"]
    assert "delay" not in args["output"]


def test_search_fields_follow_the_object():
    with pytest.raises(ValueError, match="invalid search fields"):
        zabbix.validate_args("item_get", {"filter": {"host": "ac-01"}})
    zabbix.validate_args("host_get", {"filter": {"host": "ac-01"}})
    zabbix.validate_args("trigger_get", {"search": {"description": "nodata"}})
    schema = zabbix.input_schema("item_get")
    assert "host" not in schema["properties"]["filter"]["propertyNames"]["enum"]
    assert schema["properties"]["selectValueMap"]["items"]["enum"]
    assert zabbix.input_schema("trigger_get")["properties"]["expandExpression"] == {
        "type": "boolean"
    }


def test_history_window_is_fitted_not_refused():
    end = 1_794_387_968
    fitted, note = zabbix.fit_window(
        "history_get",
        {"itemids": ["1"], "time_from": end - 7 * 86400, "time_till": end},
    )
    assert fitted["time_from"] == end - 86400 and "trend_get" in note
    # Bounds given in reverse (seen live: time_from after time_till).
    fitted, note = zabbix.fit_window(
        "history_get", {"itemids": ["1"], "time_from": end, "time_till": end - 600}
    )
    assert (fitted["time_from"], fitted["time_till"]) == (end - 600, end)
    assert "对调" in note
    same = {"itemids": ["1"], "time_from": end - 600, "time_till": end}
    assert zabbix.fit_window("history_get", same) == (same, None)
    assert zabbix.fit_window("trend_get", same) == (same, None)


# --- Model arguments in the shape the tool's schema asks for ---------------------


def test_arguments_fit_the_remote_schema():
    schema = {
        "properties": {
            "around": {"type": "string"},
            "minutes": {"type": "integer", "minimum": 1, "maximum": 120},
            "limit": {"type": "integer"},
            "host_id": {"type": "integer"},
        }
    }
    fitted, notes = skill_mcp.fit_arguments(
        {"around": 1794382130, "minutes": 240, "host_id": "307", "limit": 20}, schema
    )
    assert fitted == {
        "around": "1794382130",
        "minutes": 120,
        "host_id": 307,
        "limit": 20,
    }
    assert len(notes) == 3
    # A ceiling the SSH catalog knows but the classic schema omits.
    fitted, notes = skill_mcp.fit_arguments(
        {"minutes": 240},
        {"properties": {"minutes": {"type": "integer"}}},
        {"minutes": 120},
    )
    assert fitted == {"minutes": 120} and notes
    # Nothing to fit: unchanged, no note.
    assert skill_mcp.fit_arguments({"limit": 5}, schema) == ({"limit": 5}, [])


# --- Value maps, recurrence, event age, device events ----------------------------


AGENT_MAP = {
    "name": "Zabbix agent availability",
    "mappings": [
        {"type": "0", "value": "0", "newvalue": "not available"},
        {"type": "0", "value": "1", "newvalue": "available"},
        {"type": "0", "value": "2", "newvalue": "unknown"},
    ],
}


def test_item_rows_spell_out_their_value_map():
    row = _with_meanings(
        {
            "itemid": "9",
            "key_": "zabbix[host,agent,available]",
            "lastvalue": "2",
            "valuemap": AGENT_MAP,
        }
    )
    assert row["lastvalue_text"] == "unknown"
    assert row["value_meanings"] == {
        "0": "not available",
        "1": "available",
        "2": "unknown",
    }
    assert "valuemap" not in row
    # An item without a map (Zabbix returns []) just loses the empty field.
    assert _with_meanings({"itemid": "1", "valuemap": []}) == {"itemid": "1"}
    view = model_view(
        "zabbix_mcp",
        "item_get",
        {
            "is_error": False,
            "records": [{"itemid": "9", "lastvalue": "1", "valuemap": AGENT_MAP}],
        },
    )
    assert view["records"][0]["lastvalue_text"] == "available"


def test_state_change_reads_the_value_map():
    now = int(time.time())
    collected = [
        (
            "zabbix_mcp",
            "item_get",
            {
                "records": [
                    {
                        "itemid": "9",
                        "key_": "zabbix[host,agent,available]",
                        "valuemap": AGENT_MAP,
                    }
                ]
            },
            "E2",
        ),
        (
            "zabbix_mcp",
            "history_get",
            {
                "records": [
                    {"itemid": "9", "clock": str(now - 600), "value": "2"},
                    {"itemid": "9", "clock": str(now - 540), "value": "0"},
                    {"itemid": "9", "clock": str(now - 60), "value": "1"},
                ]
            },
            "E5",
        ),
    ]
    signal = next(
        s for s in derive_signals(collected, now - 500) if s["metric"] == "state_change"
    )
    assert signal["value"]["latest_text"] == "available"
    assert signal["value"]["last_change"]["from_text"] == "not available"
    assert "2（unknown）" not in signal["hint"]  # the last change is 0 → 1
    assert "0（not available）" in signal["hint"] and "1（available）" in signal["hint"]


def events(now, *pairs, open_problem=None):
    """event_get rows: (minutes ago, minutes it lasted) per recovered problem."""
    rows, n = [], 100
    for ago, lasted in pairs:
        n += 2
        start = now - ago * 60
        rows.append(
            {
                "eventid": str(n),
                "clock": str(start),
                "value": "1",
                "r_eventid": str(n + 1),
            }
        )
        rows.append(
            {
                "eventid": str(n + 1),
                "clock": str(start + lasted * 60),
                "value": "0",
                "r_eventid": "0",
            }
        )
    if open_problem:
        rows.append(
            {
                "eventid": open_problem[0],
                "clock": str(open_problem[1]),
                "value": "1",
                "r_eventid": "0",
            }
        )
    return {"records": rows}


def test_recurrence_counts_the_week_and_how_long_each_lasted():
    now = int(time.time())
    collected = [
        (
            "zabbix_mcp",
            "event_get",
            events(now, (30, 2), (600, 4), (3000, 3), (6000, 10)),
            "E3",
        )
    ]
    signal = next(s for s in derive_signals(collected) if s["metric"] == "recurrence")
    value = signal["value"]
    assert value["problem_events_7d"] == 4 and value["problem_events_24h"] == 2
    assert value["recovered"] == 4
    assert value["median_duration_minutes"] == 4.0
    assert value["max_duration_minutes"] == 10.0
    assert "根治" in signal["hint"]
    # Two problems in a week is not a recurring problem.
    quiet = [("zabbix_mcp", "event_get", events(now, (30, 2), (3000, 3)), "E3")]
    assert not [s for s in derive_signals(quiet) if s["metric"] == "recurrence"]


def test_an_old_open_problem_says_how_old():
    now = int(time.time())
    started = now - 13 * 86400 - 3600
    collected = [
        (
            "zabbix_mcp",
            "event_get",
            events(now, open_problem=("6340669", started)),
            "E3",
        )
    ]
    signal = next(
        s
        for s in derive_signals(collected, started, event_id="6340669")
        if s["metric"] == "event_age"
    )
    assert signal["value"]["recovered"] is False
    assert "13 天" in signal["hint"] and "下线" in signal["hint"]
    # A fresh alert gets no age signal.
    assert not [
        s
        for s in derive_signals(collected, now - 120, event_id="6340669")
        if s["metric"] == "event_age"
    ]


def test_device_problem_events_become_a_signal():
    outcome = {
        "data": {
            "categories": [
                {
                    "category": "cpu_defend",
                    "name": "上送 CPU 报文被限速丢弃（CPCAR）",
                    "c": 6,
                    "problem": True,
                },
                {
                    "category": "wlan_sta",
                    "name": "无线终端上下线 / 认证",
                    "c": 80,
                    "problem": False,
                },
            ]
        }
    }
    signal = next(
        s
        for s in derive_signals([("logs", "log_network_events", outcome, "E9")])
        if s["metric"] == "device_problem_events"
    )
    assert signal["value"] == {"cpu_defend": 6} and signal["evidence_id"] == "E9"
    assert "CPCAR" in signal["hint"]


# --- Disk alerts: the directory scan gets the alert's mount ----------------------


def test_directory_scan_takes_the_alert_mount():
    assert mount_point(["vfs.fs.dependent.size[/,pused]"]) == "/"
    assert (
        mount_point(["vfs.fs.size[/data,pused]", "vfs.fs.size[/data,free]"]) == "/data"
    )
    assert mount_point(['vfs.fs.size["/var/lib/docker",pused]']) == "/var/lib/docker"
    # Not scannable (SSH MCP refuses it) or not one mount: no prefetch.
    assert mount_point(["vfs.fs.size[/app,pused]"]) is None
    assert mount_point(["vfs.fs.size[C:,pused]"]) is None
    assert mount_point(["vfs.fs.size[/data,pused]", "vfs.fs.size[/,pused]"]) is None
    schema = {"properties": {"host_id": {}, "root": {}, "expected_revision": {}}}
    base = {"host_id": 3, "expected_revision": 2}
    assert fill_arguments(schema, base, clock=None, now=0, root="/data") == {
        **base,
        "root": "/data",
    }
    assert fill_arguments(schema, base, clock=None, now=0) is None


# --- Linked alerts and earlier analyses of the same trigger ---------------------


def store(event, minutes_ago, value="1"):
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_name,host_name,severity,"
            "event_json,received_at) VALUES (?,?,?,?,?,?,datetime('now', ?))",
            (
                event["event_id"],
                value,
                event["event_name"],
                event["host_name"],
                int(event["severity"]),
                json.dumps(event),
                f"-{minutes_ago} minutes",
            ),
        )


def alert(
    event_id,
    host="11187",
    trigger="81743",
    name="AP 指标 SNMP 采集中断",
    host_name="ac-01",
):
    return {
        "event_id": event_id,
        "event_value": "1",
        "severity": "4",
        "host_id": host,
        "trigger_id": trigger,
        "host_name": host_name,
        "event_name": name,
    }


def test_alert_history_lists_linked_alerts_and_earlier_conclusions(isolated):
    now = int(time.time())
    current = alert("900")
    store(current, 0)
    store(alert("901", host="11186", host_name="ac-02"), 3)  # another AC, same moment
    store(
        alert("902", host="11186", host_name="ac-02"), 3, value="0"
    )  # its recovery row
    store(alert("903", host="20000", host_name="far-away"), 120)  # outside ±15 min
    store(
        alert("904", trigger="70000", name="Interface Gi0/0/1 down"), 300
    )  # same host
    store(alert("905"), 600)  # the same trigger, analysed before
    with main.connection() as db:
        db.execute(
            "INSERT INTO diagnostic_tasks(task_id,trace_id,kind,source,actor,event_id,"
            "diagnostic_type,profile,request,status,report,completed_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,datetime('now','-9 hours'))",
            (
                "a" * 32,
                "b" * 32,
                "analysis",
                "alert",
                "system",
                "905",
                "bottleneck",
                "standard",
                tasks.encode({}),
                "success",
                tasks.encode(
                    {
                        "answer": "诊断结论\nSNMP 报文被 CPCAR 限速丢弃，walk 超时。\n\n处理建议\n"
                        "1. 调大采集间隔\n2. 提高 CPCAR\n\n诊断范围（平台生成）\n- 目标：x"
                    }
                ),
            ),
        )
    found = alert_history.context(current, now)
    assert [row["host"] for row in found["related_alerts"]] == ["ac-02"]
    assert found["same_host_24h"][0]["alert"] == "Interface Gi0/0/1 down"
    earlier = found["previous_analyses"][0]
    assert earlier["cause"] == "SNMP 报文被 CPCAR 限速丢弃，walk 超时。"
    assert earlier["actions"] == ["1. 调大采集间隔", "2. 提高 CPCAR"]
    assert "不能用证据编号引用" in found["notice"]
    # Analysed as of a moment before that analysis concluded: not listed.
    earlier_view = alert_history.context(current, now - 10 * 3600) or {}
    assert "previous_analyses" not in earlier_view


def test_a_resource_alert_lists_only_the_same_trigger_elsewhere(isolated):
    """Other hosts' memory or disk alerts say nothing about this host's CPU;
    the same CPU alert on several hosts at once does, and so does a storm."""
    now = int(time.time())
    cpu = "Linux: Load average is too high"
    current = alert("920", host="1", trigger="11", name=cpu, host_name="app-1")
    store(current, 0)
    store(alert("921", host="2", trigger="12", name=cpu, host_name="app-2"), 2)
    for n in range(3, 8):
        store(
            alert(
                f"92{n}",
                host=str(n),
                trigger="13",
                name="Linux: High memory",
                host_name=f"db-{n}",
            ),
            1,
        )
    found = alert_history.context(current, now)
    assert [row["host"] for row in found["related_alerts"]] == ["app-2"]
    assert found["other_hosts_alerting"] == 6
    # An availability alert also lists other hosts' availability alerts.
    down = alert(
        "930",
        host="40",
        trigger="41",
        name="Huawei VRP: Unavailable by ICMP ping",
        host_name="sw-1",
    )
    store(down, 0)
    store(
        alert(
            "931",
            host="42",
            trigger="43",
            name="Linux: Zabbix agent is not available",
            host_name="vm-9",
        ),
        1,
    )
    linked = alert_history.context(down, now)
    assert "vm-9" in [row["host"] for row in linked["related_alerts"]]
    assert "db-3" not in [row["host"] for row in linked["related_alerts"]]


def test_alert_history_is_left_out_without_records(isolated):
    current = alert("910")
    store(current, 0)
    assert alert_history.context(current, int(time.time())) is None
    assert alert_history.context({"event_id": "1"}, int(time.time())) is None
