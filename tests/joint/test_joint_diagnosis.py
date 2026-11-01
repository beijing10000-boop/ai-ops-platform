"""Joint: one alert diagnosis through the platform with the real SSH MCP and
log MCP services (Zabbix and the model are scripted).

The SSH asset resolves but its host refuses the connection, and the log
store is down unless a real one is configured: the task must still finish,
keep the Zabbix evidence, and say exactly which source failed and why.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest
from joint_providers import READY
from test_acceptance_scenarios import (
    Model,
    Zabbix,
    alert_clock,
    answer,
    event_for,
    item,
    step,
)

from app import main, mcp_runtime, worker
from app.integrations import zabbix
from app.orchestrator import tasks


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def test_alert_with_real_ssh_and_log_services_degrades_and_says_why(
    ssh_env, log_env, isolated, monkeypatch
):
    clock = alert_clock()
    host = {
        "hostid": READY,
        "host": "joint-ready",
        "name": "joint-ready",
        "status": "0",
        "parentTemplates": [{"templateid": "1", "name": "Linux by Zabbix agent"}],
        "interfaces": [{"type": "1", "ip": ssh_env.address, "main": "1"}],
    }
    zbx = Zabbix(
        host,
        [item("201", "system.cpu.load[all,avg5]", 12.4)],
        [item("202", "system.cpu.util", 18.5)],
        [{"eventid": "880001", "clock": str(clock), "value": "1", "name": "load"}],
        {"201": step(clock, 3.0, 12.0), "202": step(clock, 15.0, 18.0)},
        {"201": (1.0, 2.5, 4.0), "202": (5.0, 15.0, 30.0)},
    )
    config = {
        "openai_model": "fixture",
        "mcp_url": "http://zabbix.invalid/mcp",
        "ssh_mcp_enabled": "true",
        "ssh_mcp_url": ssh_env.provider.mcp_url,
        "ssh_mcp_token": ssh_env.full["token"],
        "ssh_mcp_timeout_seconds": "60",
        "log_mcp_url": log_env.provider.mcp_url,
        "log_mcp_token": log_env.full["token"],
    }
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))

    class Connect:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return zbx

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(zabbix, "connect", Connect)
    model = Model(
        lambda request: answer(
            json.dumps(
                {
                    "cause": "负载升高，实时证据不可用。",
                    "action": ["恢复 SSH 连通后复查进程"],
                    "analysis": "仅依据 Zabbix 历史。",
                },
                ensure_ascii=False,
            )
        )
    )
    event = event_for("Linux: Load average is too high", "71001", clock, host_id=READY)
    _, usage = asyncio.run(
        mcp_runtime.run(
            worker.alert_instructions(),
            json.dumps({"alert": event}, ensure_ascii=False),
            client=SimpleNamespace(responses=SimpleNamespace(create=model.create)),
            event=event,
            return_usage=True,
        )
    )
    task = tasks.get(usage["task_id"])
    report = task["report"]
    capabilities, coverage = report["capabilities"], report["coverage"]
    # It finished on the evidence it had; the failures are stated, not hidden.
    assert task["status"] == "partial"
    assert capabilities["device_type"] == "linux"
    assert capabilities["diagnostic_path"] == "zabbix-only"
    assert "history_get" in coverage["collected"]
    # The SSH asset resolved; the host refused the session: an evidence gap.
    assert any(entry["tool"] == "ssh_collect" for entry in coverage["failed"])
    assert capabilities["ssh_mcp"]["status"] != "used"
    # Logs: with the store down the source cannot be confirmed — a capability
    # note, never a gap, and the model got no log tools.
    if not log_env.store:
        assert capabilities["logs"]["status"] == "unavailable"
        assert not any(entry["tool"].startswith("log_") for entry in coverage["failed"])
    opening = json.loads(model.requests[0]["input"][0]["content"])
    assert opening["capabilities"]["ssh_mcp"]["status"] != "used"
    assert ssh_env.full["token"] not in json.dumps(report, ensure_ascii=False)
    assert log_env.full["token"] not in json.dumps(report, ensure_ascii=False)
