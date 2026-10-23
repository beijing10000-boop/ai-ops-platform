"""Deterministic model/MCP fixtures test orchestration; real transport tests are separate."""

import asyncio
import io
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import paramiko
import pytest
from app import main, inventory, mcp_runtime
from app.diagnostics import ssh
from app.orchestrator import tasks
from app.integrations.zabbix import READ_TOOLS


class Context:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *args):
        return False


class Call:
    type = "function_call"

    def __init__(self, name, args):
        self.name = name
        self.arguments = json.dumps(args)
        self.call_id = "fixture-call"

    def model_dump(self, **kwargs):
        return {
            "type": self.type,
            "name": self.name,
            "arguments": self.arguments,
            "call_id": self.call_id,
        }


@pytest.fixture
def rig(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    log = []
    responses = []
    kind = {"type": "linux"}
    settings = {
        "openai_model": "fixture",
        "mcp_url": "http://fixture.invalid/mcp",
        "ai_tool_loading": "full",
        "ai_analysis_profile": "standard",
    }
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: settings.get(key, ""))

    async def call(name, args):
        log.append(("mcp", name))
        if name == "host_get":
            data = [
                {
                    "hostid": "10",
                    "inventory": {"os": kind["type"]},
                    "tags": [{"tag": "aiops.device_type", "value": kind["type"]}],
                }
            ]
        elif name == "item_get":
            data = [
                {
                    "itemid": "20",
                    "hostid": "10",
                    "value_type": "0",
                    "key_": "system.cpu.util",
                    "lastvalue": "95",
                }
            ]
        elif name == "history_get":
            data = [
                {"itemid": "20", "clock": "100", "value": "94"},
                {"itemid": "20", "clock": "99", "value": "90"},
            ]
        else:
            data = []
        return SimpleNamespace(
            content=[SimpleNamespace(text=json.dumps(data))], isError=False
        )

    session = SimpleNamespace(
        initialize=AsyncMock(),
        list_tools=AsyncMock(
            return_value=SimpleNamespace(
                tools=[
                    SimpleNamespace(
                        name=n, inputSchema={"type": "object"}, description=n
                    )
                    for n in READ_TOOLS | {"host_delete"}
                ]
            )
        ),
        call_tool=call,
    )
    monkeypatch.setattr(
        mcp_runtime, "streamablehttp_client", lambda *a, **k: Context(("r", "w", None))
    )
    monkeypatch.setattr(mcp_runtime, "ClientSession", lambda *a, **k: Context(session))

    async def create(**kwargs):
        responses.append(kwargs)
        if len(responses) == 1:
            return SimpleNamespace(
                output=[
                    Call(
                        "diagnose_linux_host",
                        {"reason": "历史数据无法解释实时进程状态"},
                    )
                ],
                output_text="",
                usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            )
        return SimpleNamespace(
            output=[],
            output_text="依据现有证据给出建议；实时进程不直接代表历史告警原因。",
            usage={"input_tokens": 20, "output_tokens": 10, "total_tokens": 30},
        )

    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    key = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    key.write_private_key(buf)
    cid = inventory.save_credential("fixture", buf.getvalue(), "", "test")["id"]
    asset = inventory.save_asset(
        inventory.AssetInput(
            name="asset",
            zabbix_hostid="10",
            device_type="linux",
            address="172.20.1.10",
            host_key=key.get_name() + " " + key.get_base64(),
            credential_id=cid,
        ),
        "test",
    )

    def execute(asset_id, action, *args, **kwargs):
        log.append(("ssh", action))
        return {"status": "success", "output": "fixture " + action, "duration_ms": 1}

    monkeypatch.setattr(ssh, "execute", execute)
    return settings, log, responses, client, kind, asset


def run(rig, event_name="CPU usage high", **kwargs):
    settings, log, responses, client, kind, asset = rig
    result = asyncio.run(
        mcp_runtime.run(
            "中文诊断",
            "分析告警",
            client=client,
            event={"event_id": "1000", "host_id": "10", "event_name": event_name},
            return_usage=True,
            **kwargs,
        )
    )
    return result, tasks.get(result[1]["task_id"])


def test_cpu_monitoring_precedes_ssh_and_real_provider_usage_is_aggregated(rig):
    result, task = run(rig)
    log = rig[1]
    assert log.index(("mcp", "history_get")) < log.index(("ssh", "cpu"))
    assert ("ssh", "processes") in log
    assert result[1]["total"] == 45 and task["token_total"] == 45
    assert task["report"]["device_type"] == "linux" and task["status"] == "success"


@pytest.mark.parametrize("device_type", ["windows", "network", "vmware"])
def test_other_device_types_never_enter_linux_ssh(rig, device_type):
    rig[4]["type"] = device_type
    result, task = run(rig)
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert task["report"]["device_type"] == device_type
    assert all(t["name"] != "diagnose_linux_host" for t in rig[2][0]["tools"])
    assert all(t["name"] != "host_delete" for t in rig[2][0]["tools"])


def test_zabbix_unavailable_still_allows_registered_linux_evidence(rig):
    rig[0]["mcp_url"] = ""
    result, task = run(rig)
    assert ("ssh", "cpu") in rig[1]
    assert task["status"] == "partial"
    assert any("MCP" in x for x in task["report"]["limitations"])


def test_ssh_failure_keeps_zabbix_basic_analysis(rig, monkeypatch):
    def fail(*args, **kwargs):
        raise ssh.DiagnosticError("SSH 超时")

    monkeypatch.setattr(ssh, "execute", fail)
    result, task = run(rig)
    assert ("mcp", "history_get") in rig[1]
    assert task["status"] == "partial" and "依据现有证据" in task["report"]["answer"]


def test_missing_commands_are_partial_evidence_not_silent_success(rig, monkeypatch):
    monkeypatch.setattr(
        ssh,
        "execute",
        lambda *a, **k: {
            "status": "partial",
            "output": "CAPABILITY_MISSING:iostat",
            "duration_ms": 1,
        },
    )
    result, task = run(rig, "IO latency")
    assert task["status"] == "partial"
    evidence = tasks.evidence_page(task["task_id"], True)
    assert any("CAPABILITY_MISSING" in str(x["payload"]) for x in evidence)


def test_quick_mode_does_not_offer_or_execute_ssh(rig):
    rig[0]["ai_analysis_profile"] = "quick"
    result, task = run(rig)
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert task["profile"] == "quick"


def test_actual_token_threshold_stops_further_tools_without_extra_request(rig):
    rig[0]["ai_profile_budgets"] = '{"standard":{"tokens":2000}}'
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES (?,?,0)",
            ("ai_profile_budgets", rig[0]["ai_profile_budgets"]),
        )
    responses = rig[2]

    async def create(**kwargs):
        responses.append(kwargs)
        return SimpleNamespace(
            output=[Call("diagnose_linux_host", {"reason": "需要查询实时状态"})],
            output_text="",
            usage={"input_tokens": 2100, "output_tokens": 10, "total_tokens": 2110},
        )

    rig[3].responses.create = create
    result, task = run(rig)
    assert len(responses) == 1 and task["report"]["budget_exhausted"]
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert task["token_total"] == 2110  # Actual response, never an estimated cap.


def test_asset_changed_during_reasoning_revokes_deep_check(rig):
    original = rig[3].responses.create

    async def change(**kwargs):
        response = await original(**kwargs)
        with main.connection() as db:
            db.execute("UPDATE assets SET enabled=0,revision=revision+1")
        return response

    rig[3].responses.create = change
    result, task = run(rig)
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert any("配置" in x for x in task["report"]["limitations"])


def test_disk_and_service_select_relevant_fixed_actions(rig):
    result, task = run(rig, "filesystem /data 95%")
    assert [name for kind, name in rig[1] if kind == "ssh"] == ["disk"]
    assert task["diagnostic_type"] == "disk"


def test_configured_secrets_never_reach_model_inputs_or_final_report(rig, monkeypatch):
    secret = "fixture-secret-never-send"
    rig[0]["openai_api_key"] = secret
    original = mcp_runtime.zabbix.safe_result

    def result(*args, **kwargs):
        value = original(*args, **kwargs)
        value["data"] = value.get("data", "") + " " + secret
        return value

    monkeypatch.setattr(mcp_runtime.zabbix, "safe_result", result)
    captured = []

    async def create(**kwargs):
        # Serialize now: the runtime appends later output to the same input list.
        captured.append(json.dumps(kwargs, ensure_ascii=False, default=str))
        return SimpleNamespace(
            output=[Call("host_get", {"hostids": ["10"]})]
            if len(captured) == 1
            else [],
            output_text="" if len(captured) == 1 else "AI result " + secret,
            usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        )

    rig[3].responses.create = create
    answer, task = run(rig)
    assert len(captured) == 2
    assert all(secret not in request for request in captured)
    assert secret not in answer[0]
    assert secret not in json.dumps(task["report"])


def test_mcp_error_result_cannot_produce_success(rig, monkeypatch):
    monkeypatch.setattr(
        mcp_runtime.zabbix,
        "safe_result",
        lambda *a, **k: {"data": "permission denied", "is_error": True, "records": []},
    )
    _, task = run(rig)
    assert task["status"] == "partial"
    assert any("返回错误" in gap for gap in task["report"]["limitations"])
    evidence = tasks.evidence_page(task["task_id"], True)
    assert any(
        e["provider"] == "zabbix_mcp" and e["status"] == "failed" for e in evidence
    )


@pytest.mark.parametrize("final_only", [False, True])
def test_empty_model_answer_is_partial(rig, final_only):
    async def create(**kwargs):
        return SimpleNamespace(
            output=[Call("host_get", {"hostids": ["10"]})]
            if final_only and kwargs.get("tool_choice") != "none"
            else [],
            output_text="",
            usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        )

    rig[3].responses.create = create
    _, task = run(rig)
    assert task["status"] == "partial"
    assert "模型未返回" in task["report"]["answer"]
    assert any("模型未返回" in gap for gap in task["report"]["limitations"])


@pytest.mark.parametrize("failure", [RuntimeError, tasks.Cancelled, TimeoutError])
def test_interrupted_model_run_keeps_reported_usage_once(rig, failure):
    original = rig[3].responses.create

    async def create(**kwargs):
        if rig[2]:
            raise failure("fixture interruption")
        return await original(**kwargs)

    rig[3].responses.create = create
    if failure is TimeoutError:
        _, task = run(rig)
        assert task["status"] == "partial"
    else:
        with pytest.raises(failure):
            run(rig)
        task = tasks.page()["items"][0]
        assert task["status"] == (
            "cancelled" if failure is tasks.Cancelled else "failed"
        )
    assert task["token_total"] == 15
    with main.connection() as db:
        rows = db.execute(
            "SELECT token_input,token_output,token_total,rounds FROM ai_token_runs"
        ).fetchall()
    assert rows == [(10, 5, 15, 1)]


def test_timeout_before_first_response_does_not_invent_zero_usage(rig):
    async def create(**kwargs):
        raise TimeoutError("no provider response")

    rig[3].responses.create = create
    result, task = run(rig)
    assert task["status"] == "partial" and task["token_total"] is None
    assert result[1]["available"] is False
    with main.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM ai_token_runs").fetchone()[0] == 0


@pytest.mark.parametrize("state", ["0", 0, "1"])
def test_recovery_history_uses_recovery_time(state):
    event = {
        "event_value": state,
        "event_date": "2026.10.20",
        "event_time": "10:00:00",
        "recovery_date": "2026.10.20",
        "recovery_time": "12:00:00",
    }
    original = mcp_runtime.event_clock({**event, "event_value": "1"})
    assert mcp_runtime.event_clock(event) == original + (
        7200 if str(state) == "0" else 0
    )
    event["recovery_time"] = "invalid"
    assert mcp_runtime.event_clock(event) == original


def test_queued_analysis_does_not_mix_original_event_with_rebound_asset(rig):
    event = {"event_id": "1000", "host_id": "10", "event_name": "CPU usage high"}
    task, _ = tasks.create(
        {"event": event},
        asset_id=rig[5]["id"],
        event_id="1000",
        diagnostic_type="cpu",
    )
    with main.connection() as db:
        db.execute(
            "UPDATE assets SET zabbix_hostid='11',revision=revision+1 WHERE id=?",
            (rig[5]["id"],),
        )
    _, result = run(rig, task_id=task["task_id"])
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert result["status"] == "partial"
    assert any("Host ID" in gap for gap in result["report"]["limitations"])
    assert all(t["name"] != "diagnose_linux_host" for t in rig[2][0]["tools"])
