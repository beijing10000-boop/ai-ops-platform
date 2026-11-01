"""Prefetch budget, evidence accounting and SSH call limits (audit 2026-11)."""

import json
import time

import pytest

from app import main, mcp_runtime, skill_runtime
from test_acceptance_scenarios import (
    LINUX_HOST,
    SSH,
    Model,
    Zabbix,
    alert_clock,
    answer,
    event_for,
    item,
    reply,
    rig,
    run_alert,
    ssh_calls,
    step,
)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def cpu_alert(clock):
    return Zabbix(
        LINUX_HOST,
        [item("201", "system.cpu.load[all,avg5]", 12.4)],
        [
            item("202", "system.cpu.util", 18.5),
            item("203", "system.cpu.util[,iowait]", 41.3),
        ],
        [{"eventid": "880001", "clock": str(clock), "value": "1", "name": "load"}],
        {
            "201": step(clock, 3.0, 12.0),
            "202": step(clock, 15.0, 18.0),
            "203": step(clock, 2.0, 41.0),
        },
        {"201": (1.0, 2.5, 4.0), "202": (5.0, 15.0, 30.0), "203": (0.5, 2.0, 6.0)},
    )


def layered(monkeypatch, **extra):
    """More settings over the ones rig() serves."""
    base = mcp_runtime.read_setting
    monkeypatch.setattr(
        mcp_runtime, "read_setting", lambda key: extra.get(key) or base(key)
    )


def budgets(**profiles):
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('ai_profile_budgets',?,0)",
            (json.dumps(profiles),),
        )


def charged(zbx, ssh):
    """Prefetch evidence calls: every Zabbix query and SSH diagnostic, not the
    identity lookup that binds the SSH asset."""
    return len(zbx.calls) + len(
        [name for name, _ in ssh_calls(ssh) if name != "ssh_resolve_host"]
    )


CPU_ALERT = "Linux: Load average is too high"


def test_quick_profile_prefetches_the_alert_window_and_the_live_state(monkeypatch):
    clock = alert_clock()
    zbx, ssh = cpu_alert(clock), SSH({})
    rig(monkeypatch, zbx, ssh)
    layered(monkeypatch, ai_analysis_profile="quick")
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论"))
    )
    assert task["profile"] == "quick"
    # With 8 calls (3 kept for the model) stage A/B used them all.
    assert "ssh_collect" in [name for name, _ in ssh_calls(ssh)]
    assert {"history_get", "trend_get"} <= {name for name, _ in zbx.calls}
    assert charged(zbx, ssh) <= 10 - 3


def test_prefetch_never_spends_beyond_its_share_and_says_what_it_skipped(
    monkeypatch,
):
    clock = alert_clock()
    zbx, ssh = cpu_alert(clock), SSH({})
    rig(monkeypatch, zbx, ssh)
    # 6 calls, 2 kept for the model: 4 for prefetch, stage A takes 3.
    budgets(standard={"calls": 6, "follow_up_calls": 2})
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论"))
    )
    report = task["report"]
    assert charged(zbx, ssh) <= 6 - 2
    skipped = [
        entry["tool"]
        for entry in report["coverage"]["skipped"]
        if entry["reason"] == skill_runtime.PREFETCH_SHORT
    ]
    # The alert window goes first (stage B's item search leaves it a call);
    # what did not fit is listed, not dropped.
    assert "history_get" in {name for name, _ in zbx.calls}
    assert {"item_get", "ssh_collect", "trend_get"} <= set(skipped)
    assert any("预采集次数不足" in hit for hit in report["budget"]["limits_hit"])


def test_resolving_the_ssh_asset_alone_is_not_ssh_evidence(monkeypatch):
    clock = alert_clock()
    failing = {"status": "failed", "error": "连接被拒绝", "error_code": "failed"}
    zbx = cpu_alert(clock)
    ssh = SSH({}, delay=0)
    original = ssh.call_tool

    async def call_tool(name, args):
        if name == "ssh_collect":
            ssh.calls.append((name, dict(args)))
            return reply({"host_id": args["host_id"], "action": "collect", **failing})
        return await original(name, args)

    ssh.call_tool = call_tool
    rig(monkeypatch, zbx, ssh)
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论"))
    )
    capabilities = task["report"]["capabilities"]
    assert capabilities["diagnostic_path"] == "zabbix-only"
    assert capabilities["ssh_mcp"]["status"] != "used"


def test_a_bundle_step_that_failed_inside_a_success_envelope_is_a_gap(monkeypatch):
    """SSH MCP before v0.9 kept ssh_collect "success" when a step failed."""
    clock = alert_clock()
    zbx = cpu_alert(clock)
    ssh = SSH(
        {
            "ssh_diagnose_pressure": {
                "status": "partial",
                "exit_code": 1,
                "summary": {},
                "findings": [],
            }
        }
    )
    original = ssh.call_tool

    async def call_tool(name, args):
        response = await original(name, args)
        if name == "ssh_collect":
            response.structuredContent["status"] = "success"
        return response

    ssh.call_tool = call_tool
    rig(monkeypatch, zbx, ssh)
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论"))
    )
    failed = task["report"]["coverage"]["failed"]
    assert any(
        entry["tool"] == "ssh_collect" and "pressure" in entry["reason"]
        for entry in failed
    )
    assert task["status"] == "partial"


def test_a_window_capped_short_of_the_alert_is_said_and_uses_the_catalog_limit(
    monkeypatch,
):
    """Classic SSH tools carry the minutes ceiling only in the catalog params."""
    clock = int(time.time()) - 3 * 3600
    zbx = Zabbix(
        LINUX_HOST,
        [item("301", "vm.memory.utilization", 97.0)],
        [],
        [{"eventid": "880001", "clock": str(clock), "value": "1", "name": "mem"}],
        {"301": step(clock, 60.0, 97.0)},
        {"301": (40.0, 60.0, 80.0)},
    )
    ssh = SSH({})
    original = ssh.call_tool

    async def call_tool(name, args):
        response = await original(name, args)
        if name == "ssh_list_tool_catalog":
            for entry in response.structuredContent["result"]:
                if entry["id"] == "collect":
                    entry["params"].append({"name": "minutes", "maximum": 120})
        return response

    ssh.call_tool = call_tool
    rig(monkeypatch, zbx, ssh)
    task, _ = run_alert(
        event_for("Linux: High memory utilization", "71002", clock),
        Model(lambda r: answer("结论")),
    )
    bundle = next(args for name, args in ssh_calls(ssh) if name == "ssh_collect")
    assert bundle["minutes"] == 120
    limited = task["report"]["coverage"]["limited"]
    assert limited and "未覆盖告警时刻" in limited[0]["reason"]
    assert any(
        "未覆盖告警时刻" in hit for hit in task["report"]["budget"]["limits_hit"]
    )


def test_an_invalid_model_call_is_not_an_evidence_gap(monkeypatch):
    clock = alert_clock()
    zbx, ssh = cpu_alert(clock), SSH({})
    rig(monkeypatch, zbx, ssh)
    from test_acceptance_scenarios import Call

    rounds = [
        lambda r: answer(
            "",
            [
                Call(
                    "c1",
                    "call_mcp_tool",
                    {"provider": "zabbix_mcp", "name": "made_up_tool", "arguments": {}},
                )
            ],
        ),
        lambda r: answer("结论"),
    ]
    task, _ = run_alert(event_for(CPU_ALERT, "71001", clock), Model(*rounds))
    report = task["report"]
    assert not any(
        "made_up_tool" in entry["tool"] for entry in report["coverage"]["failed"]
    )
    assert not any("made_up_tool" in text for text in report["limitations"])


@pytest.mark.parametrize(
    "budget",
    [
        # SSH MCP v0.9 (FastMCP): an optional integer keeps its bounds in anyOf.
        {
            "anyOf": [
                {"type": "integer", "minimum": 10, "maximum": 120},
                {"type": "null"},
            ],
            "default": None,
        },
        {"type": "integer", "minimum": 10, "maximum": 120},
    ],
)
def test_ssh_calls_carry_a_time_budget_when_the_service_takes_one(monkeypatch, budget):
    clock = alert_clock()
    zbx, ssh = cpu_alert(clock), SSH({})
    listed = ssh.list_tools

    async def list_tools():
        result = await listed()
        for tool in result.tools:
            if tool.name == "ssh_collect":
                tool.inputSchema["properties"]["timeout_seconds"] = budget
        return result

    ssh.list_tools = list_tools
    rig(monkeypatch, zbx, ssh)
    layered(monkeypatch, ssh_mcp_timeout_seconds="60")
    run_alert(event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论")))
    bundle = next(args for name, args in ssh_calls(ssh) if name == "ssh_collect")
    # The service answers inside the platform's own 60 s call timeout.
    assert 10 <= bundle["timeout_seconds"] <= 50


def test_ssh_calls_without_a_time_budget_parameter_are_unchanged(monkeypatch):
    clock = alert_clock()
    zbx, ssh = cpu_alert(clock), SSH({})
    rig(monkeypatch, zbx, ssh)
    run_alert(event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论")))
    bundle = next(args for name, args in ssh_calls(ssh) if name == "ssh_collect")
    assert "timeout_seconds" not in bundle


def test_trend_baseline_asks_only_for_items_that_fit_one_page():
    rows = [
        {"itemid": str(100 + n), "key_": f"vfs.fs.size[/d{n},pused]", "value_type": "0"}
        for n in range(8)
    ]
    jobs = skill_runtime.history_jobs(
        ["vfs.fs.*"], [{"records": rows}], event={}, now=int(time.time())
    )
    trend = next(job for job in jobs if job[1] == "trend_get")
    assert len(trend[2]["itemids"]) == skill_runtime.TREND_ITEMS == 5
    # 5 items x 168 hourly rows fit the 1000-row page.
    assert skill_runtime.TREND_ITEMS * 7 * 24 <= skill_runtime.HISTORY_ROWS


def test_uptime_is_not_given_a_baseline_ratio():
    assert skill_runtime.CONSTANT_KEYS.match("system.uptime")
