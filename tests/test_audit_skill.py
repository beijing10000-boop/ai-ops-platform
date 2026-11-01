"""Regression tests for the 2026-11 Skill / evidence audit fixes.

Signals judged in both directions, state items by their change moments,
derived signal numbers citable under their evidence id, collection freshness
only for availability alerts, Java and service Skills limited to Linux, port
checks classified as service alerts, SSH views whose repeated findings no
longer crowd out process rows, the Skill body without its front matter, one
capacity unit and process trimming by the fields SSH MCP sends. Skill
administration is in test_audit_skill_admin.py.
"""

import json
from types import SimpleNamespace

import pytest

from app import evidence_check, main, skill_context, skill_store as skills
from app.diagnostics.playbooks import classify_keys
from app.skill_context import derive_signals, model_view

P = "/api/v1/platform/skills"
CLOCK = 1_793_274_921  # 2026-10-29 19:55:21 Beijing time


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def history(itemid, before, after, points=10):
    """Alert-window rows: `points` values before the alert, then after it."""
    rows = [
        {"itemid": itemid, "clock": str(CLOCK - (points - i) * 60), "value": str(v)}
        for i, v in enumerate(before if isinstance(before, list) else [before] * points)
    ]
    rows += [
        {"itemid": itemid, "clock": str(CLOCK + i * 60), "value": str(v)}
        for i, v in enumerate(after if isinstance(after, list) else [after] * points)
    ]
    return {"records": rows}


def trend(itemid, avg):
    return {
        "records": [
            {"itemid": itemid, "clock": str(CLOCK - hour * 3600), "value_avg": str(avg)}
            for hour in range(1, 25)
        ]
    }


def items(*pairs):
    return {"records": [{"itemid": ident, "key_": key} for ident, key in pairs]}


def metrics(signals, itemid=None):
    return [
        s["metric"]
        for s in signals
        if itemid is None or (s.get("value") or {}).get("itemid") == itemid
    ]


# --- OPS-SKILL-01: both directions, state items, counters ----------------------------


def test_a_fall_below_the_baseline_is_not_read_as_close_to_it():
    """Available memory at a quarter of its 7-day level used to read "close to
    the baseline, a capacity or threshold question" plus "already at that
    level before the alert"."""
    collected = [
        ("zabbix_mcp", "item_get", items(("11", "vm.memory.size[pavailable]")), "E1"),
        ("zabbix_mcp", "history_get", history("11", 12, 6), "E2"),
        ("zabbix_mcp", "trend_get", trend("11", 36), "E3"),
    ]
    signals = derive_signals(collected, CLOCK)
    assert metrics(signals) == ["drop_vs_baseline", "drop_at_alert"]
    drop, at_alert = signals
    assert drop["evidence_id"] == "E2" and drop["level"] == "warning"
    assert drop["value"] == {
        "itemid": "11",
        "window_avg": 9.0,
        "baseline_avg": 36.0,
        "ratio": 0.25,
    }
    assert "vm.memory.size[pavailable]（11）" in drop["hint"]
    assert "越低越差" in drop["hint"] and "接近" not in drop["hint"]
    assert at_alert["value"]["ratio"] == 0.5


@pytest.mark.parametrize(
    "baseline,expected",
    [
        (10.0, ["alert_vs_baseline"]),  # 0.95: close to the baseline
        (11.5, []),  # 0.83: neither close nor a clear fall
        (4.0, ["alert_vs_baseline"]),  # 2.38: a surge
    ],
)
def test_only_a_ratio_near_one_counts_as_close_to_the_baseline(baseline, expected):
    collected = [
        ("zabbix_mcp", "history_get", history("12", 9.5, 9.5), "E1"),
        ("zabbix_mcp", "trend_get", trend("12", baseline), "E2"),
    ]
    assert metrics(derive_signals(collected)) == expected


@pytest.mark.parametrize(
    "before,after,expected",
    [
        (50, 52, "elevated_before_alert"),  # within 10 %
        (50, 40, None),  # 0.8: fell, but not clearly
        (40, 10, "drop_at_alert"),  # the old rule called this "elevated before"
        (30, 50, "rise_at_alert"),
        (0, 5, "rise_at_alert"),  # from nothing
        (0, 0, None),
    ],
)
def test_before_and_after_the_alert_are_judged_in_both_directions(
    before, after, expected
):
    signals = derive_signals(
        [("zabbix_mcp", "history_get", history("13", before, after), "E1")], CLOCK
    )
    assert metrics(signals) == ([expected] if expected else [])
    if (before, after) == (0, 5):
        assert "告警前均值为 0" in signals[0]["hint"]
        assert "ratio" not in signals[0]["value"]
    if expected == "elevated_before_alert":
        assert "若它是告警指标" in signals[0]["hint"]


def test_availability_items_report_when_their_state_changed():
    collected = [
        (
            "zabbix_mcp",
            "item_get",
            items(
                ("21", "icmpping"),
                ("22", "agent.ping"),
                ("23", "zabbix[host,agent,available]"),
                ("24", "net.if.status[ifIndex.3]"),
                ("25", "icmppingsec"),
                ("26", "agent.ping"),
            ),
            "E1",
        ),
        ("zabbix_mcp", "history_get", history("21", 1, 0), "E2"),
        ("zabbix_mcp", "history_get", history("22", 1, 1), "E2"),
        ("zabbix_mcp", "history_get", history("23", 1, 2), "E2"),
        (
            "zabbix_mcp",
            "history_get",
            history("24", 1, [2, 2, 1, 1, 1, 1, 1, 1, 1, 1]),
            "E2",
        ),
        ("zabbix_mcp", "history_get", history("25", 0.002, 0.009), "E2"),
        # agent.ping sends 1 or nothing: no rows after the alert.
        ("zabbix_mcp", "history_get", history("26", 1, []), "E2"),
        ("zabbix_mcp", "trend_get", trend("21", 1.0), "E3"),
    ]
    signals = derive_signals(collected, CLOCK)
    # No averages or ratios for states: icmpping 1 -> 0 is not "0.5 x baseline".
    assert metrics(signals, "21") == ["state_change"]
    down = signals[0]
    assert down["value"] == {
        "itemid": "21",
        "key": "icmpping",
        "changes": 1,
        "latest": 0,
        "latest_at": "2026-10-29 20:04:21",
        "last_change": {"from": 1, "to": 0, "local_time": "2026-10-29 19:55:21"},
    }
    assert (
        "由 1 变为 0" in down["hint"] and "告警时刻 2026-10-29 19:55:21" in down["hint"]
    )
    steady = next(s for s in signals if s["value"].get("itemid") == "22")
    assert (
        steady["value"]["changes"] == 0 and "一直为 1，状态没有变化" in steady["hint"]
    )
    agent = next(s for s in signals if s["value"].get("itemid") == "23")
    assert agent["value"]["last_change"]["to"] == 2
    flap = next(s for s in signals if s["value"].get("itemid") == "24")
    assert flap["value"]["changes"] == 2 and flap["value"]["latest"] == 1
    # ICMP response time is a level, not a state.
    assert metrics(signals, "25") == ["rise_at_alert"]
    gone = next(s for s in signals if s["value"].get("itemid") == "26")
    assert gone["value"]["latest_at"] == "2026-10-29 19:54:21"
    assert (
        "告警时刻之后没有新数据" in gone["hint"] and "状态没有变化" not in gone["hint"]
    )


def test_counters_that_only_grow_get_no_level_signals():
    uptime = history(
        "31", [100000 + i * 60 for i in range(10)], [100600 + i * 60 for i in range(10)]
    )
    collected = [
        ("zabbix_mcp", "item_get", items(("31", "system.uptime")), "E1"),
        ("zabbix_mcp", "history_get", uptime, "E2"),
        ("zabbix_mcp", "trend_get", trend("31", 95000), "E3"),
    ]
    assert derive_signals(collected, CLOCK) == []


# --- OPS-SKILL-02: derived numbers are citable --------------------------------------


def shown(ident, provider, tool, outcome):
    """An evidence index entry as the runtime keeps it: the model's view."""
    view = model_view(provider, tool, outcome, 4000, CLOCK)
    return {
        "provider": provider,
        "tool": tool,
        "text": json.dumps({"evidence_id": ident, **view}, ensure_ascii=False),
    }


def test_signal_numbers_are_citable_under_their_evidence_id():
    latest = {
        "records": [
            {"itemid": "41", "key_": "system.cpu.load[all,avg5]", "lastvalue": "7.2"},
            {"itemid": "42", "key_": "system.cpu.num", "lastvalue": "4"},
            {"itemid": "43", "key_": "system.cpu.util", "lastvalue": "18.5"},
        ]
    }
    collected = [
        ("zabbix_mcp", "item_get", latest, "E1"),
        ("zabbix_mcp", "history_get", history("41", 2.0, 9.0), "E2"),
        ("zabbix_mcp", "trend_get", trend("41", 2.2), "E3"),
        ("ssh_mcp", "ssh_diagnose_cpu", {"data": {"load_1": 6.25}}, "E4"),
    ]
    index = {ident: shown(ident, p, tool, out) for p, tool, out, ident in collected}
    signals = derive_signals(collected, CLOCK)
    assert {"load_cpu_divergence", "alert_vs_baseline", "rise_at_alert"} <= set(
        metrics(signals)
    )
    # Load per core (7.2 / 4), window average against the baseline (5.5 /
    # 2.2) and after against before (9 / 2): numbers no tool returned.
    quotes = [
        ("E1", "每核负载 1.8"),
        ("E2", "告警窗口均值是基线的 2.5 倍"),
        ("E2", "告警后是告警前的 4.5 倍"),
    ]
    answer = json.dumps(
        {"cause": "负载升高", "evidence": [{"id": i, "quote": q} for i, q in quotes]},
        ensure_ascii=False,
    )
    # Before the signals are attached, their derived numbers are in no evidence.
    assert evidence_check.check(answer, index)["valid"] == []
    evidence_check.attach_signals(index, signals)
    result = evidence_check.check(answer, index)
    assert [item["quote"] for item in result["valid"]] == [q for _, q in quotes]
    # Only under the signal's own evidence id, and identifiers never ground.
    wrong = json.dumps(
        {
            "cause": "x",
            "evidence": [
                {"id": "E4", "quote": "每核负载 1.8"},
                {"id": "E2", "quote": "监控项 41"},
            ],
        },
        ensure_ascii=False,
    )
    assert evidence_check.check(wrong, index)["valid"] == []


def test_attaching_signals_ignores_unknown_ids_and_text():
    index = {"E1": {"provider": "zabbix_mcp", "tool": "item_get", "text": "{}"}}
    evidence_check.attach_signals(
        index,
        [
            {"evidence_id": "E9", "value": {"count": 3}},
            {"evidence_id": None, "value": 1},
            {"evidence_id": "E1", "value": {"key": "vm.memory.size[2]", "items": 7}},
            "not a signal",
        ],
    )
    assert index["E1"]["signals"] == [{"key": "vm.memory.size[2]", "items": 7}]
    assert "E9" not in index
    # Strings of a signal value (keys, times, templates) ground nothing.
    answer = json.dumps(
        {"evidence": [{"id": "E1", "quote": "7 个"}, {"id": "E1", "quote": "2"}]}
    )
    result = evidence_check.check(answer, index)
    assert [item["quote"] for item in result["valid"]] == ["7 个"]


# --- OPS-SKILL-03: collection freshness ----------------------------------------------


@pytest.fixture
def frozen(monkeypatch):
    monkeypatch.setattr(skill_context, "time", SimpleNamespace(time=lambda: CLOCK))


def clocks(*stamps):
    return {
        "records": [
            {"itemid": str(i), "key_": f"k{i}", "lastclock": str(stamp)}
            for i, stamp in enumerate(stamps)
        ]
    }


def test_collection_freshness_is_for_availability_alerts_only(frozen):
    stale = [("zabbix_mcp", "item_get", clocks(*[CLOCK - 1700] * 3), "E1")]
    assert derive_signals(stale, diagnostic_type="cpu") == []
    assert derive_signals(stale, diagnostic_type="memory") == []
    for kind in ("unreachable", None):
        [signal] = derive_signals(stale, diagnostic_type=kind)
        assert signal["metric"] == "collection_freshness"


def test_collection_freshness_counts_each_item_once(frozen):
    trigger = clocks(CLOCK - 30, CLOCK - 1700)
    every = clocks(CLOCK - 30, CLOCK - 1700, CLOCK - 1650, 0)
    # The same two items come back from both item_get calls; lastclock 0 is an
    # item that never delivered data.
    [signal] = derive_signals(
        [
            ("zabbix_mcp", "item_get", trigger, "E1"),
            ("zabbix_mcp", "item_get", every, "E2"),
        ],
        diagnostic_type="unreachable",
    )
    assert signal["evidence_id"] == "E1"
    assert (signal["value"]["items"], signal["value"]["updated_within_10m"]) == (3, 1)
    assert "1/3" in signal["hint"]


def test_items_all_still_updating_do_not_point_at_the_agent(frozen):
    [signal] = derive_signals(
        [("zabbix_mcp", "item_get", clocks(CLOCK - 30, CLOCK - 60, CLOCK - 90), "E1")],
        diagnostic_type="unreachable",
    )
    assert signal["level"] == "info"
    assert "全部仍有新数据" in signal["hint"] and "采集链路目前正常" in signal["hint"]
    assert "agent 服务本身" not in signal["hint"]


# --- OPS-SKILL-04: Java and service guidance only for Linux hosts --------------------


@pytest.mark.parametrize("name", ["platform-java", "platform-service"])
def test_ssh_guidance_skills_do_not_reach_windows_or_network_tasks(name):
    package = skills.managed_package(name)
    assert package["devices"] == ["linux", "unknown"]
    kind = package["types"][0]
    assert skills.applies(package, kind, "linux") and skills.applies(package, kind)
    assert not skills.applies(package, kind, "windows")
    assert not skills.applies(package, kind, "network")
    assert skills.prefetch_plan([package], "alert", kind, "windows")["ssh"] == []


# --- OPS-SKILL-06: port and service checks are service alerts ------------------------


@pytest.mark.parametrize(
    "key,current,expected",
    [
        ("net.tcp.service[tcp,,3306]", "service", "service"),
        ("net.tcp.service[tcp,,3306]", "bottleneck", "service"),
        ("net.tcp.port[,8080]", "bottleneck", "service"),
        ("net.tcp.service[http,,80]", "service", "nginx"),
        ("net.tcp.service[ssh]", "bottleneck", "unreachable"),
        ("net.tcp.listen[8080]", "bottleneck", "network"),
        ("net.if.in[eth0]", "service", "network"),
    ],
)
def test_port_checks_classify_as_service(key, current, expected):
    assert classify_keys([key], current)[0] == expected


# --- OPS-SKILL-07: repeated findings do not crowd out rows ---------------------------

UNSET = (
    "启动命令未设置 -Xmx 或 -XX:MaxRAMPercentage：JVM 默认最大堆取物理内存或容器限制的 1/4，"
    "容器内或同机多实例时容易 OOM 或互相挤占；也可能通过 JAVA_TOOL_OPTIONS 设置，"
    "用 ssh_diagnose_jvm 的 vm_flags 确认实际 MaxHeapSize"
)


def jvm(index):
    """A Java inventory row of SSH MCP v0.8.0 started without -Xmx."""
    name = f"svc-{index:02d}"
    return {
        "pid": 30000 + index,
        "user": "app",
        "elapsed_seconds": 106000,
        "rss_KiB": 1500000 - index * 1000,
        "cpu_percent": 0.0,
        "mem_percent": 4.6,
        "threads": 120,
        "unit": "supervisord.service",
        "main": f"{name}.jar",
        "jar_path": f"/data/jar/{name}/{name}.jar",
        "application": name,
        "heap": {
            "xms": None,
            "xmx": None,
            "xss": None,
            "max_ram_percentage": None,
            "max_metaspace": None,
            "max_direct": None,
        },
    }


def test_repeated_findings_do_not_crowd_out_java_rows():
    """Thirteen JVMs without -Xmx: thirteen identical 250-character hints left
    room for one process in the standard 4000-character view."""
    rows = [jvm(index) for index in range(13)]
    findings = [
        {
            "level": "warning",
            "metric": "heap_max_unset",
            "value": {"pid": row["pid"], "application": row["application"]},
            "threshold": "-Xmx 或 -XX:MaxRAMPercentage",
            "hint": UNSET,
        }
        for row in rows
    ]
    findings.append(
        {
            "level": "info",
            "metric": "many_java_processes",
            "value": 13,
            "threshold": 5,
            "hint": "同一主机运行 ≥5 个 Java 进程",
        }
    )
    outcome = {
        "is_error": False,
        "data": {
            "status": "success",
            "summary": {"java_processes": 13, "processes": rows},
            "findings": findings,
        },
    }
    view = model_view("ssh_mcp", "ssh_diagnose_java", outcome, max_chars=4000)
    assert len(json.dumps(view, ensure_ascii=False)) <= 4000
    shown = view["data"]["summary"]["processes"]
    assert [row["pid"] for row in shown] == [row["pid"] for row in rows]
    assert all(row["rss_KiB"] for row in shown)
    merged, single = view["data"]["findings"]
    assert merged["metric"] == "heap_max_unset" and merged["count"] == 13
    assert merged["values"][12] == {"pid": 30012, "application": "svc-12"}
    assert merged["hint"] == UNSET and "value" not in merged
    assert single["metric"] == "many_java_processes" and single["value"] == 13
    # The stored evidence keeps every finding as SSH MCP sent it.
    assert len(outcome["data"]["findings"]) == 14
    # Signals read the raw result: every JVM's finding is still there.
    assert len(derive_signals([("ssh_mcp", "ssh_diagnose_java", outcome, "E1")])) == 13


def test_findings_are_shortened_with_a_count_as_a_last_resort():
    findings = [
        {"level": "warning", "metric": f"m{i}", "value": i, "hint": "x" * 150}
        for i in range(40)
    ]
    outcome = {"data": {"summary": {"title": "t"}, "findings": findings}}
    view = model_view("ssh_mcp", "ssh_diagnose_health", outcome, max_chars=3000)
    assert len(json.dumps(view, ensure_ascii=False)) <= 3000
    kept = view["data"]["findings"]
    assert 0 < len(kept) < 40
    assert view["data"]["findings_omitted"] == 40 - len(kept)


# --- trimmed_processes (SSH-DIAG-13, SSH-NGX-09) -------------------------------------


def process_view(rows, **summary):
    outcome = {"data": {"summary": {"processes": rows, **summary}}}
    return model_view("ssh_mcp", "ssh_diagnose_java", outcome)["data"]["summary"]


def test_idle_jvms_holding_memory_are_kept():
    rows = [
        {"pid": i, "name": "kworker", "cpu_percent": 0.0, "memory_percent": 0.0}
        for i in range(10)
    ]
    # Java rows say mem_percent; a big idle JVM shows 0.0 lifetime CPU.
    rows += [
        {"pid": 100 + i, "cpu_percent": 0.0, "mem_percent": 0.0, "rss_KiB": 900000}
        for i in range(5)
    ]
    rows += [{"pid": 200 + i, "cpu_percent": 0.0, "mem_percent": 6.5} for i in range(5)]
    summary = process_view(rows)
    assert [row["pid"] for row in summary["processes"]] == [
        *range(100, 105),
        *range(200, 205),
    ]
    assert (summary["processes_shown"], summary["processes_total"]) == (10, 20)


def test_a_process_busy_in_the_last_second_is_kept_by_pid():
    rows = [
        {"pid": i, "name": "kworker", "cpu_percent": 0.0, "memory_percent": 0.0}
        for i in range(20)
    ]
    summary = process_view(
        rows,
        cpu_interval=[
            {"pid": 7, "cpu_percent_1s": 87.0, "name": "java"},
            {"pid": 8, "cpu_percent_1s": 0.0, "name": "sshd"},
        ],
    )
    assert [row["pid"] for row in summary["processes"]] == [7]


def test_the_nginx_master_is_never_trimmed():
    workers = [
        {"pid": 2000 + i, "role": "worker", "rss_KiB": 52000, "cpu_percent": 1.0}
        for i in range(20)
    ]
    master = {"pid": 2100, "role": "master", "rss_KiB": 0, "cpu_percent": 0.0}
    summary = process_view([*workers, master])
    pids = [row["pid"] for row in summary["processes"]]
    assert pids == [*range(2000, 2015), 2100]
    assert summary["processes_shown"] == 16 and "master" in summary["processes_note"]
    # Rows still wide after their bulkiest fields went keep their role.
    wide = [
        {**row, "unit": "nginx-" + "u" * 170 + ".service", "command": "x" * 110}
        for row in [*workers[:12], master]
    ]
    outcome = {"data": {"summary": {"processes": wide}}}
    view = model_view("ssh_mcp", "ssh_diagnose_nginx", outcome, max_chars=1500)
    rows = view["data"]["summary"]["processes"]
    assert rows and all("role" in row for row in rows)
    assert "command" in view["fields_note"]


# --- OPS-SKILL-14: the model gets the Skill body -------------------------------------


def test_skill_body_leaves_the_front_matter_to_the_platform():
    package = skills.managed_package("platform-linux")
    body = skills.skill_body(package)
    assert body == package["instructions"] and body.startswith("# Linux 主机诊断")
    assert "prefetch:" not in body and "devices:" not in body
    # A row without `instructions` (older snapshots) has its file cut instead.
    legacy = {"files": {"SKILL.md": package["files"]["SKILL.md"]}}
    assert skills.skill_body(legacy) == body
    plain = {"files": {"SKILL.md": "没有元数据的正文\n"}}
    assert skills.skill_body(plain) == "没有元数据的正文"


# --- OPS-SKILL-15: one capacity unit --------------------------------------------------


def test_base_skill_names_one_capacity_unit_and_quotes_unconverted():
    text = skills.managed_package("platform-base")["instructions"]
    assert "MiB 或 GiB" not in text
    assert "容量用 GiB" in text and "不换算单位" in text
    # The signals the base Skill names exist in both directions.
    for name in ("drop_vs_baseline", "drop_at_alert", "state_change"):
        assert name in text
