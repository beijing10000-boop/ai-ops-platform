"""Deterministic model/MCP fixtures test orchestration; real transport tests are separate."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from app import main, mcp_runtime
from app.integrations import ssh_mcp
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
        "ssh_mcp_enabled": "true",
        "ssh_mcp_url": "http://ssh-fixture.invalid/mcp",
        "ssh_mcp_token": "ssh-fixture-token",
    }
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: settings.get(key, ""))

    async def call(name, args):
        log.append(("mcp", name))
        kind.setdefault("mcp_arguments", []).append((name, args))
        if name == "host_get" and "ip" in args.get("filter", {}):
            raise AssertionError("initMAX host_get rejects filter.ip")
        if name == "host_get":
            data = [
                {
                    "hostid": "10",
                    "name": "172.20.2.101",
                    "interfaces": [{"ip": "172.20.2.101"}],
                    "inventory": {"os": kind["type"]},
                    "tags": [{"tag": "aiops.device_type", "value": kind["type"]}],
                    "hostgroups": [
                        {"groupid": "2", "name": group}
                        for group in kind.get("groups", [])
                    ],
                }
            ]
            data = kind.get("host_rows", data)
        elif name == "hostinterface_get":
            data = kind.get(
                "interface_rows",
                [
                    {"hostid": str(row["hostid"]), "ip": "172.20.2.101"}
                    for row in kind.get("host_rows", [{"hostid": "10"}])
                ],
            )
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
            data = kind.get("items", data)
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

    async def remote_call(name, args):
        if name == "ssh_resolve_host":
            log.append(("resolve", args["zabbix_hostid"]))
            payload = {
                "status": "success",
                "zabbix_hostid": "10",
                "host_id": 99,
                "revision": 5,
            }
        else:
            action = name.removeprefix("ssh_diagnose_")
            log.append(("ssh", action))
            assert args["host_id"] == 99 and args["expected_revision"] == 5
            payload = {
                "status": "success",
                "host_id": 99,
                "action": action,
                "output": "fixture " + action,
                "duration_ms": 1,
            }
            if action == "directory_usage":
                payload["action"] = "directory"
                root = args["root"]
                payload["data"] = {
                    "root": root,
                    "top_directories": [{"directory": root + "/child", "bytes": 1024}],
                }
        return SimpleNamespace(isError=False, structuredContent=payload)

    adapter = ssh_mcp.SSHMCPAdapter(SimpleNamespace(call_tool=remote_call))
    monkeypatch.setattr(ssh_mcp, "configured", lambda *a, **k: Context(adapter))
    return settings, log, responses, client, kind


def run(rig, event_name="CPU usage high", **kwargs):
    settings, log, responses, client, kind = rig
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
    assert log.count(("ssh", "cpu")) == 1  # model retry uses the cached snapshot
    assert result[1]["total"] == 45 and task["token_total"] == 45
    assert task["report"]["device_type"] == "linux" and task["status"] == "success"


def test_compatibility_final_answer_honors_cancellation_and_keeps_usage(rig):
    client = rig[3]

    async def cancel(**kwargs):
        with main.connection() as db:
            db.execute(
                "UPDATE diagnostic_tasks SET cancel_requested=1 WHERE status='running'"
            )
        return SimpleNamespace(
            output=[],
            output_text="不应保存为成功",
            usage={"input_tokens": 20, "output_tokens": 10, "total_tokens": 30},
        )

    client.responses.create = cancel
    with pytest.raises(tasks.Cancelled):
        run(rig)
    with main.connection() as db:
        assert db.execute(
            "SELECT status,token_total FROM diagnostic_tasks"
        ).fetchone() == ("cancelled", 30)


def test_compatibility_incomplete_answer_is_marked_partial(rig):
    async def incomplete(**kwargs):
        return SimpleNamespace(
            output=[],
            output_text="尚未输出完的分析",
            status="incomplete",
            incomplete_details={"reason": "max_output_tokens"},
            usage=None,
        )

    rig[3].responses.create = incomplete
    result, task = run(rig)
    assert task["status"] == "partial" and task["report"]["answer"] == result[0]
    assert any("输出" in gap for gap in task["report"]["limitations"])


@pytest.mark.parametrize("device_type", ["windows", "network", "vmware"])
def test_other_device_types_never_enter_linux_ssh(rig, device_type):
    rig[4]["type"] = device_type
    result, task = run(rig)
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert task["report"]["device_type"] == device_type
    assert all(t["name"] != "diagnose_linux_host" for t in rig[2][0]["tools"])
    assert all(t["name"] != "host_delete" for t in rig[2][0]["tools"])


def test_linux_group_auto_collects_ssh_without_model_tool_request(rig):
    # Host inventory and OS tag are unknown. Zabbix's verified Linux group
    # is sufficient to classify the host, but SSH still requires exact mapping.
    rig[4]["type"] = "unknown"
    rig[4]["groups"] = ["Linux"]
    observed = []

    async def model_only(**kwargs):
        observed.append(kwargs)
        return SimpleNamespace(
            output=[],
            output_text="已阅读 SSH 和 Zabbix 证据",
            usage={"input_tokens": 40, "output_tokens": 12, "total_tokens": 52},
        )

    rig[3].responses.create = model_only
    _, task = run(rig, "Linux: Zabbix agent is not available (for 3m)")
    assert task["report"]["device_type"] == "linux"
    assert ("resolve", "10") in rig[1]
    assert ("ssh", "system") in rig[1]
    assert rig[1].count(("ssh", "system")) == 1
    assert observed and "已自动执行的 SSH MCP" in str(observed[0]["input"])
    assert task["status"] == "success"


def test_unverified_group_label_never_triggers_ssh(rig):
    rig[4]["type"] = "unknown"
    rig[4]["groups"] = ["Not Linux", "Discovered hosts"]
    _, task = run(rig)
    assert task["report"]["device_type"] == "unknown"
    assert not any(kind in {"ssh", "resolve"} for kind, _ in rig[1])


def test_zabbix_unavailable_does_not_guess_host_type_or_ssh_target(rig):
    rig[0]["mcp_url"] = ""
    result, task = run(rig)
    assert not any(kind == "ssh" for kind, name in rig[1])
    assert task["status"] == "partial"
    assert any("MCP" in x for x in task["report"]["limitations"])


def test_ssh_failure_keeps_zabbix_basic_analysis(rig, monkeypatch):
    async def fail(*args, **kwargs):
        raise ssh_mcp.IntegrationError("SSH MCP 超时")

    monkeypatch.setattr(ssh_mcp.SSHMCPAdapter, "diagnose", fail)
    result, task = run(rig)
    assert ("mcp", "history_get") in rig[1]
    assert task["status"] == "partial" and "依据现有证据" in task["report"]["answer"]


def test_missing_commands_are_partial_evidence_not_silent_success(rig, monkeypatch):
    async def partial(*a, **k):
        return {
            "status": "partial",
            "output": "CAPABILITY_MISSING:iostat",
            "duration_ms": 1,
        }

    monkeypatch.setattr(ssh_mcp.SSHMCPAdapter, "diagnose", partial)
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
    # Automatic verified Linux snapshot is collected before model reasoning;
    # after hitting the token limit no extra tools are called.
    assert rig[1].count(("ssh", "cpu")) == 1
    assert task["token_total"] == 2110  # Actual response, never an estimated cap.


def test_mcp_disabled_during_reasoning_revokes_deep_check(rig):
    original = rig[3].responses.create

    async def change(**kwargs):
        response = await original(**kwargs)
        rig[0]["ssh_mcp_enabled"] = "false"
        return response

    rig[3].responses.create = change
    result, task = run(rig)
    # Already gathered data remains valid, but the changed MCP config
    # prevents any additional SSH calls in the AI tool round.
    assert rig[1].count(("ssh", "cpu")) == 1
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


def test_queued_analysis_ignores_legacy_asset_rebinding(rig):
    event = {"event_id": "1000", "host_id": "10", "event_name": "CPU usage high"}
    with main.connection() as db:
        aid = db.execute(
            "INSERT INTO assets(name,zabbix_hostid,device_type) VALUES ('archived','10','linux')"
        ).lastrowid
    task, _ = tasks.create(
        {"event": event}, asset_id=aid, event_id="1000", diagnostic_type="cpu"
    )
    with main.connection() as db:
        db.execute(
            "UPDATE assets SET zabbix_hostid='11',revision=revision+1 WHERE id=?",
            (aid,),
        )
    _, result = run(rig, task_id=task["task_id"])
    assert result["status"] == "success"
    assert ("resolve", "10") in rig[1] and ("ssh", "cpu") in rig[1]
    assert ("resolve", "11") not in rig[1]


def test_trusted_linux_alert_uses_remote_mapping_without_duplicate_platform_asset(rig):
    with main.connection() as db:
        db.execute("DELETE FROM assets")
    _, task = run(rig)
    assert task["status"] == "success"
    assert ("resolve", "10") in rig[1] and ("ssh", "cpu") in rig[1]


def test_mapping_failure_never_executes_or_retries_ssh(rig, monkeypatch):
    resolve = AsyncMock(side_effect=ssh_mcp.IntegrationError("重复关联"))
    monkeypatch.setattr(ssh_mcp.SSHMCPAdapter, "resolve", resolve)
    _, task = run(rig)
    assert task["status"] == "partial"
    resolve.assert_awaited_once_with("10")
    assert not any(kind == "ssh" for kind, _ in rig[1])
    assert ("mcp", "history_get") in rig[1]


def test_remote_revision_rejection_stops_remaining_actions(rig, monkeypatch):
    calls = []

    async def stale(self, binding, action, **kwargs):
        calls.append((binding.host_id, binding.revision, action))
        return {"status": "failed", "error": "Host revision changed"}

    monkeypatch.setattr(ssh_mcp.SSHMCPAdapter, "diagnose", stale)
    _, task = run(rig)
    assert task["status"] == "partial" and calls == [(99, 5, "cpu")]
    assert ("resolve", "10") in rig[1]


def test_ssh_token_from_remote_evidence_never_enters_model_or_report(rig, monkeypatch):
    secret = rig[0]["ssh_mcp_token"]
    original = ssh_mcp.SSHMCPAdapter.diagnose

    async def with_secret(self, *args, **kwargs):
        payload = await original(self, *args, **kwargs)
        return {**payload, "output": "remote " + secret, "nested": {"token": secret}}

    monkeypatch.setattr(ssh_mcp.SSHMCPAdapter, "diagnose", with_secret)
    _, task = run(rig)
    assert secret not in json.dumps(tasks.evidence_page(task["task_id"], True))
    assert secret not in json.dumps(rig[2], default=str)


def test_plain_feishu_question_resolves_ip_collects_metrics_and_five_directory_levels(
    rig,
):
    result, usage = asyncio.run(
        mcp_runtime.run(
            "中文问答",
            "看下172.20.2.101这台机器/data目录下的空间占用率，列出5层",
            client=rig[3],
            return_usage=True,
        )
    )
    task = tasks.get(usage["task_id"])
    evidence = tasks.evidence_page(task["task_id"], True)
    assert task["report"]["target"]["host_id"] == "10"
    assert task["report"]["device_type"] == "linux"
    assert rig[4]["mcp_arguments"][0] == (
        "hostinterface_get",
        {"filter": {"ip": "172.20.2.101"}, "output": ["hostid", "ip"], "limit": 100},
    )
    assert ("mcp", "item_get") in rig[1] and ("mcp", "history_get") in rig[1]
    assert ("resolve", "10") in rig[1] and ("ssh", "disk") in rig[1]
    scanned = [e["payload"] for e in evidence if e["tool"] == "directory"]
    assert [e["level"] for e in scanned] == [1, 2, 3, 4, 5]
    assert scanned[-1]["requested_root"] == "/data/child/child/child/child"
    assert task["tools"] == len(evidence) == task["report"]["budget"]["used"]["calls"]
    assert task["status"] == "success"
    assert "directory_coverage" in str(rig[2][0]["input"])


@pytest.mark.parametrize(
    "hosts",
    [
        [{"hostid": "10", "name": "172.20.2.101-extra", "inventory": {"os": "linux"}}],
        [
            {"hostid": str(n), "name": "172.20.2.101", "inventory": {"os": "linux"}}
            for n in (10, 11)
        ],
    ],
)
def test_question_does_not_bind_fuzzy_or_duplicate_zabbix_matches(rig, hosts):
    rig[4]["host_rows"] = hosts
    if len(hosts) == 1:
        rig[4]["interface_rows"] = []
    _, usage = asyncio.run(
        mcp_runtime.run(
            "问答", "查看172.20.2.101的磁盘", client=rig[3], return_usage=True
        )
    )
    task = tasks.get(usage["task_id"])
    assert task["status"] == "partial" and not task["report"]["target"]
    assert not any(kind in {"resolve", "ssh"} for kind, _ in rig[1])


def test_memory_snapshot_preserves_ssh_budget_and_does_not_fake_a_failed_kernel_call(
    rig,
):
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES ('ai_profile_budgets',?,0)",
            ('{"standard":{"calls":8}}',),
        )
    rig[4]["items"] = [
        {"itemid": str(i), "hostid": "10", "value_type": "0", "key_": "vm.memory"}
        for i in (20, 21)
    ]
    _, task = run(rig, "Linux: High swap space usage")
    evidence = tasks.evidence_page(task["task_id"], True)
    assert ("ssh", "kernel") in rig[1]
    assert len(evidence) == task["tools"] == 8
    assert all(e["status"] == "success" for e in evidence)
    assert any("部分 Zabbix 历史未查询" in gap for gap in task["report"]["limitations"])


def test_small_budget_skips_tools_without_recording_false_remote_failures(rig):
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES ('ai_profile_budgets',?,0)",
            ('{"standard":{"calls":4}}',),
        )
    _, task = run(rig, "Linux: High swap space usage")
    evidence = tasks.evidence_page(task["task_id"], True)
    assert len(evidence) == task["tools"] == 4
    assert not any(kind == "ssh" for kind, _ in rig[1])
    assert all(e["status"] == "success" for e in evidence)
    assert task["status"] == "partial" and task["report"]["budget_exhausted"]
    assert "4/4" in str(task["report"]["budget"]["reasons"])
