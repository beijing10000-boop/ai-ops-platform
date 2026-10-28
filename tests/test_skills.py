"""Skill packages, authorization, reproducible tasks and source-driven execution."""

import asyncio
import base64
from contextlib import asynccontextmanager
import io
import json
import stat
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import zipfile

import pytest
from mcp.types import Tool, ToolAnnotations
from app import main, mcp_runtime, skill_store as skills
from app.integrations import ssh_mcp, zabbix
from app.orchestrator import tasks
from app.skill_mcp import SkillMCP
from test_platform import client_for
from test_orchestrator_scenarios import Call

P = "/api/v1/platform/skills"
TEXT = "---\nname: direct-ssh\ndescription: 实时主机查询\n---\n直接查询 SSH MCP，禁止预先查询 Zabbix。"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def upload(text=TEXT, **values):
    return {
        "filename": "SKILL.md",
        "data": base64.b64encode(text.encode()).decode(),
        **values,
    }


def install(**values):
    response = client_for().post(P, json=upload(enabled=True, **values))
    assert response.status_code == 201, response.text
    return response.json()


def test_skill_crud_permissions_encryption_and_version_snapshots():
    client = client_for()
    body = upload(enabled=True, providers=["ssh_mcp"])
    assert client.post(P + "/validate", json=body).json()["ok"]
    assert client.get(P).json()["items"] == []
    row = client.post(P, json=body).json()
    assert client.post(P, json=body).status_code == 409
    assert client_for("auditor").post(P, json=body).status_code == 403
    assert (
        client_for("operator")
        .put(P + "/" + row["id"], json={"enabled": False})
        .status_code
        == 403
    )
    csrf = client.headers.pop("x-csrf-token")
    assert client.delete(P + "/" + row["id"]).status_code == 403
    client.headers["x-csrf-token"] = csrf
    old, _ = tasks.create({"question": "现在 CPU"}, source="qa")
    with main.connection() as db:
        assert (
            TEXT not in db.execute("SELECT bundle FROM platform_skills").fetchone()[0]
        )
        assert (
            "直接查询"
            not in db.execute("SELECT request FROM diagnostic_tasks").fetchone()[0]
        )
    updated = client.put(
        P + "/" + row["id"], json={"instructions": "先查看实时内存，再按需补查。"}
    ).json()
    assert updated["revision"] == 2 and updated["digest"] != row["digest"]
    assert (
        tasks.get(old["task_id"], private=True)["request"]["skills"][0]["revision"] == 1
    )
    new, _ = tasks.create({"question": "new"}, source="qa")
    assert (
        tasks.get(new["task_id"], private=True)["request"]["skills"][0]["revision"] == 2
    )
    assert (
        client.get("/api/v1/platform/tasks/" + old["task_id"]).json()["skills"][0][
            "revision"
        ]
        == 1
    )
    assert zipfile.is_zipfile(
        io.BytesIO(client.get(P + "/" + row["id"] + "/export").content)
    )
    client.put(P + "/" + row["id"], json={"enabled": False})
    after, _ = tasks.create({"question": "disabled"})
    assert tasks.get(after["task_id"], private=True)["request"]["skills"] == []
    assert client.delete(P + "/" + row["id"]).status_code == 200
    assert (
        tasks.get(old["task_id"], private=True)["request"]["skills"][0]["files"][
            "SKILL.md"
        ]
        == TEXT
    )


def test_skill_scopes_priority_and_bundled_template():
    install(scopes=["qa"], priority=1)
    second = upload(
        TEXT.replace("direct-ssh", "alert-triage"),
        enabled=True,
        scopes=["alert"],
        priority=2,
    )
    assert client_for().post(P, json=second).status_code == 201
    assert [row["name"] for row in skills.snapshot({}, "qa")] == ["direct-ssh"]
    assert [
        row["name"] for row in skills.snapshot({"event": {"event_id": "1"}}, "feishu")
    ] == ["alert-triage"]
    assert skills.snapshot({}, "web") == []
    raw = client_for().get(P + "/template").content
    parsed = skills.parse_package("template.zip", base64.b64encode(raw))
    assert parsed["name"] == "ops-mcp-readonly" and len(parsed["files"]) == 4
    assert "ssh_resolve_target" in parsed["instructions"]


@pytest.mark.parametrize(
    "text",
    [
        "no metadata",
        TEXT.replace("name: direct-ssh", "name: direct-ssh\nname: duplicate"),
        TEXT.replace("name: direct-ssh", "name: &id direct-ssh").replace(
            "description: 实时主机查询", "description: *id"
        ),
        TEXT.replace("direct-ssh", "../outside"),
        TEXT.replace("实时主机查询", "!!python/object:subprocess.Popen {}"),
    ],
)
def test_invalid_skill_frontmatter_is_rejected(text):
    assert client_for().post(P + "/validate", json=upload(text)).status_code == 422


@pytest.mark.parametrize(
    "path,symlink",
    [
        ("../outside.txt", False),
        ("/outside.md", False),
        ("scripts/run.py", False),
        ("references/link.md", True),
    ],
)
def test_zip_traversal_scripts_and_symlinks_never_extract(path, symlink):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("SKILL.md", TEXT)
        info = zipfile.ZipInfo(path)
        if symlink:
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "untrusted")
    result = client_for().post(
        P + "/validate",
        json={
            "filename": "unsafe.zip",
            "data": base64.b64encode(raw.getvalue()).decode(),
        },
    )
    assert result.status_code == 422


def test_skill_web_submission_does_not_prequery_zabbix(monkeypatch):
    install(scopes=["web"], providers=["ssh_mcp"])
    remote = AsyncMock(side_effect=AssertionError("must not call Zabbix"))
    monkeypatch.setattr("app.platform_api.live_hosts", remote)
    monkeypatch.setattr("app.platform_api.enqueue_task", lambda _: None)
    body = {"question": "查询 172.20.2.101 现在 CPU", "zabbix_hostid": "10913"}
    client = client_for()
    assert client.post("/api/v1/platform/tasks/validate", json=body).status_code == 200
    assert client.post("/api/v1/platform/tasks", json=body).status_code == 202
    assert remote.await_count == 0


def remote_tool(name, props, required=()):
    return Tool(
        name=name,
        inputSchema={
            "type": "object",
            "properties": props,
            "required": list(required),
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    )


class Session:
    def __init__(self):
        self.calls = []
        self.tools = [
            remote_tool(
                "ssh_resolve_target", {"address": {"type": "string"}}, ["address"]
            ),
            remote_tool(
                "ssh_diagnose_cpu",
                {
                    "host_id": {"type": "integer"},
                    "expected_revision": {"type": "integer"},
                },
                ["host_id"],
            ),
        ]

    async def list_tools(self):
        return SimpleNamespace(tools=self.tools, nextCursor=None)

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        data = (
            {
                "status": "success",
                "host_id": 7,
                "address": "172.20.2.101",
                "revision": 3,
                "name": "linux-live",
                "zabbix_hostid": "10913",
            }
            if name == "ssh_resolve_target"
            else {
                "status": "success",
                "host_id": 7,
                "action": "cpu",
                "data": {"load": 0.5},
            }
        )
        return SimpleNamespace(structuredContent=data, content=[], isError=False)


@pytest.fixture
def rig(monkeypatch):
    session = Session()
    config = {
        "openai_model": "fixture",
        "ssh_mcp_enabled": "true",
        "ssh_mcp_url": "http://ssh.invalid/mcp",
        "ssh_mcp_token": "never-expose-token",
        "ssh_mcp_timeout_seconds": "90",
    }
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield SimpleNamespace(session=session)

    monkeypatch.setattr(ssh_mcp, "configured", connect)
    monkeypatch.setattr(
        zabbix,
        "connect",
        lambda *_: (_ for _ in ()).throw(
            AssertionError("Zabbix connection is forbidden in SSH-only Skill")
        ),
    )
    return session, config


def response(*calls, text=""):
    return SimpleNamespace(
        output=list(calls),
        output_text=text,
        usage=SimpleNamespace(input_tokens=20, output_tokens=10, total_tokens=30),
    )


def test_skill_selects_direct_ssh_without_zabbix_and_preserves_actual_usage(rig):
    session, _ = rig
    row = install(providers=["ssh_mcp"])
    responses = [
        response(Call("list_mcp_tools", {"provider": "ssh_mcp"})),
        response(
            Call(
                "call_mcp_tool",
                {
                    "provider": "ssh_mcp",
                    "name": "ssh_resolve_target",
                    "arguments": {"address": "172.20.2.101"},
                },
            )
        ),
        response(
            Call(
                "call_mcp_tool",
                {
                    "provider": "ssh_mcp",
                    "name": "ssh_diagnose_cpu",
                    "arguments": {"host_id": 7},
                },
            )
        ),
        response(text="当前 CPU 正常，依据 SSH 当前采集；没有查询历史。"),
    ]
    create = AsyncMock(side_effect=responses)
    text, usage = asyncio.run(
        mcp_runtime.run(
            "中文报告",
            "查询 172.20.2.101 现在 CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    assert "CPU" in text and usage["total"] == 120
    assert [name for name, args in session.calls] == [
        "ssh_resolve_target",
        "ssh_diagnose_cpu",
    ]
    assert session.calls[-1][1]["expected_revision"] == 3
    task = tasks.get(usage["task_id"])
    assert task["status"] == "success" and task["report"]["execution_mode"] == "skill"
    assert task["report"]["skills"][0]["digest"] == row["digest"]
    assert task["report"]["target"]["ssh_host_id"] == 7
    assert task["report"]["budget"]["used"]["calls"] == 3
    assert "直接查询 SSH" in create.call_args_list[0].kwargs["instructions"]
    with main.connection() as db:
        assert db.execute("SELECT token_total FROM ai_token_runs").fetchone()[0] == 120


def test_skill_timeout_retains_successful_mcp_evidence(rig):
    import httpx
    from openai import APITimeoutError

    install(providers=["ssh_mcp"])
    request = httpx.Request("POST", "https://example.invalid")
    create = AsyncMock(
        side_effect=[
            response(Call("list_mcp_tools", {"provider": "ssh_mcp"})),
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_resolve_target",
                        "arguments": {"address": "172.20.2.101"},
                    },
                )
            ),
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_diagnose_cpu",
                        "arguments": {"host_id": 7},
                    },
                )
            ),
            APITimeoutError(request=request),
            APITimeoutError(request=request),
        ]
    )
    answer, usage = asyncio.run(
        mcp_runtime.run(
            "请分析",
            "查询 172.20.2.101 现在 CPU",
            return_usage=True,
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
        )
    )
    task = tasks.get(usage["task_id"])
    assert task["status"] == "partial"
    assert task["report"]["model_error"] == "ModelTimeout"
    assert "ssh_diagnose_cpu" in answer
    assert usage["total"] == 90
    assert any("超时" in gap for gap in task["report"]["limitations"])


def test_generic_bridge_rejects_unresolved_wrong_target_writes_and_changed_revision(
    rig,
):
    session, config = rig

    async def run():
        async with SkillMCP(
            lambda key: config.get(key, ""),
            ["ssh_mcp"],
            deadline=time.monotonic() + 20,
            target=("ip", "172.20.2.101"),
        ) as bridge:
            with pytest.raises(ValueError, match="未核验"):
                await bridge.call("ssh_mcp", "ssh_diagnose_cpu", {"host_id": 7})
            await bridge.call(
                "ssh_mcp", "ssh_resolve_target", {"address": "172.20.2.102"}
            )
            assert not bridge.bindings
            await bridge.call(
                "ssh_mcp", "ssh_resolve_target", {"address": "172.20.2.101"}
            )
            with pytest.raises(ValueError, match="revision"):
                await bridge.call(
                    "ssh_mcp",
                    "ssh_diagnose_cpu",
                    {"host_id": 7, "expected_revision": 99},
                )
            with pytest.raises(ValueError, match="Schema"):
                await bridge.call(
                    "ssh_mcp", "ssh_diagnose_cpu", {"host_id": 7, "command": "whoami"}
                )
            with pytest.raises(ValueError, match="只读"):
                await bridge.call("ssh_mcp", "ssh_execute", {"command": "whoami"})
            with pytest.raises(ValueError, match="未获准"):
                await bridge.catalog("zabbix_mcp")
            config["ssh_mcp_token"] = "rotated"
            with pytest.raises(ValueError, match="变更"):
                await bridge.call("ssh_mcp", "ssh_diagnose_cpu", {"host_id": 7})

    asyncio.run(run())
    assert len(session.calls) == 2


def test_skill_tool_budget_and_cancelled_tasks_keep_reports(rig):
    install(providers=["ssh_mcp"])
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('ai_profile_budgets',?,0)",
            (json.dumps({"standard": {"calls": 1}}),),
        )
    create = AsyncMock(
        side_effect=[
            response(Call("list_mcp_tools", {"provider": "ssh_mcp"})),
            response(text="工具预算不足，只取得目录，未采集主机。"),
        ]
    )
    _, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    assert create.call_args_list[-1].kwargs["tool_choice"] == "none"
    assert tasks.get(usage["task_id"])["tools"] == 1
    task, _ = tasks.create({"question": "CPU"})
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET cancel_requested=1 WHERE task_id=?",
            (task["task_id"],),
        )
    with pytest.raises(tasks.AlreadyRunning):
        asyncio.run(
            mcp_runtime.run(
                "report", "CPU", task_id=task["task_id"], client=SimpleNamespace()
            )
        )


def test_native_ssh_logs_still_require_logs_read():
    task, _ = tasks.create({"question": "logs"})
    tasks.evidence(
        task["task_id"],
        "ssh_mcp",
        "ssh_diagnose_system_errors",
        {"data": "private log line"},
    )
    assert tasks.evidence_page(task["task_id"])[0]["payload"]["restricted"]
    assert "private log line" in str(
        tasks.evidence_page(task["task_id"], include_logs=True)
    )


def test_history_skill_calls_zabbix_only_and_adapts_initmax_arguments(monkeypatch):
    install(providers=["zabbix_mcp"])
    log = []
    config = {"openai_model": "fixture", "mcp_url": "http://zabbix.invalid/mcp"}
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))
    monkeypatch.setattr(
        ssh_mcp,
        "configured",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not connect SSH")),
    )

    class ZabbixSession:
        async def list_tools(self):
            return SimpleNamespace(
                tools=[
                    remote_tool(
                        name,
                        {
                            "output": {"type": "string"},
                            "extra_params": {"type": "object"},
                        },
                    )
                    for name in ("item_get", "history_get")
                ],
                nextCursor=None,
            )

        async def call_tool(self, name, args):
            log.append((name, args))
            assert isinstance(args["output"], str)
            rows = (
                [{"itemid": "20", "hostid": "10", "value_type": "0", "lastvalue": "95"}]
                if name == "item_get"
                else [{"itemid": "20", "clock": "100", "value": "95"}]
            )
            return SimpleNamespace(
                structuredContent={"result": rows}, content=[], isError=False
            )

    @asynccontextmanager
    async def connect(*args):
        yield ZabbixSession()

    monkeypatch.setattr(zabbix, "connect", connect)
    create = AsyncMock(
        side_effect=[
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "zabbix_mcp",
                        "name": "item_get",
                        "arguments": {"hostids": ["10"]},
                    },
                )
            ),
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "zabbix_mcp",
                        "name": "history_get",
                        "arguments": {
                            "itemids": ["20"],
                            "history": 0,
                            "time_from": 1,
                            "time_till": 200,
                        },
                    },
                )
            ),
            response(
                text='{"cause":"历史 CPU 峰值 95","action":"人工核验","analysis":"Zabbix 历史证据","human_required":true}'
            ),
        ]
    )
    text, usage = asyncio.run(
        mcp_runtime.run(
            "输出告警 JSON",
            "查询过去 CPU 峰值",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    assert json.loads(text)["cause"] == "历史 CPU 峰值 95"
    assert [name for name, args in log] == ["item_get", "history_get"]
    assert log[0][1]["extra_params"]["hostids"] == ["10"]
    query_context = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert query_context["current_timestamp"] > 0
    assert query_context["current_time"].endswith("+08:00")
    assert "分析与依据" in tasks.get(usage["task_id"])["report"]["answer"]


def test_skill_cancellation_after_model_response_saves_usage_and_stops_tools(rig):
    session, _ = rig
    install(providers=["ssh_mcp"])
    task, _ = tasks.create({"question": "CPU"})

    async def cancel(**kwargs):
        with main.connection() as db:
            db.execute(
                "UPDATE diagnostic_tasks SET cancel_requested=1 WHERE task_id=?",
                (task["task_id"],),
            )
        return response(Call("list_mcp_tools", {"provider": "ssh_mcp"}))

    with pytest.raises(tasks.Cancelled):
        asyncio.run(
            mcp_runtime.run(
                "report",
                "CPU",
                task_id=task["task_id"],
                client=SimpleNamespace(responses=SimpleNamespace(create=cancel)),
            )
        )
    stopped = tasks.get(task["task_id"])
    assert stopped["status"] == "cancelled" and stopped["token_total"] == 30
    assert session.calls == []


def test_readiness_check_reports_missing_tools_without_host_queries(rig, monkeypatch):
    session, config = rig
    config["feishu_admin_open_ids"] = "ou_super"
    monkeypatch.setattr(main, "read_setting", lambda key: config.get(key, ""))
    row = install(providers=["ssh_mcp"])
    client = client_for()
    client.put(
        P + "/" + row["id"],
        json={
            "instructions": "先调用 `ssh_resolve_target` 再调用 `ssh_diagnose_directory_usage`。"
        },
    )
    result = client.post(P + "/" + row["id"] + "/verify", json={}).json()
    assert not result["ok"]
    assert result["results"][0]["missing"] == ["ssh_diagnose_directory_usage"]
    assert session.calls == []


def test_partial_native_evidence_is_a_partial_report(rig, monkeypatch):
    session, _ = rig
    install(providers=["ssh_mcp"])
    original = session.call_tool

    async def call(name, args):
        result = await original(name, args)
        if name == "ssh_diagnose_cpu":
            result.structuredContent["status"] = "partial"
        return result

    monkeypatch.setattr(session, "call_tool", call)
    create = AsyncMock(
        side_effect=[
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_resolve_target",
                        "arguments": {"address": "172.20.2.101"},
                    },
                )
            ),
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_diagnose_cpu",
                        "arguments": {"host_id": 7},
                    },
                )
            ),
            response(text="取得部分 CPU 证据，需要补充核验。"),
        ]
    )
    _, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "172.20.2.101 CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    report = tasks.get(usage["task_id"])
    assert report["status"] == "partial"
    assert any(
        "ssh_diagnose_cpu" in gap and "部分" in gap
        for gap in report["report"]["limitations"]
    )


def test_malformed_skill_call_is_reported_and_remaining_calls_continue(rig):
    install(providers=["ssh_mcp"])
    malformed = Call("call_mcp_tool", {})
    malformed.arguments = '{"provider":'
    create = AsyncMock(
        side_effect=[
            response(malformed, Call("list_mcp_tools", {"provider": "ssh_mcp"})),
            response(text="参数有误，仅取得工具目录，未采集主机。"),
        ]
    )
    _, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "查询 CPU",
            return_usage=True,
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
        )
    )
    task = tasks.get(usage["task_id"])
    assert task["status"] == "partial" and task["tools"] == 1
    outputs = [
        part
        for part in create.call_args.kwargs["input"]
        if part.get("type") == "function_call_output"
    ]
    assert "error" in json.loads(outputs[0]["output"])
    assert json.loads(outputs[1]["output"])["tools"]


def test_skill_cancellation_during_final_answer_is_not_saved_as_success(rig):
    install(providers=["ssh_mcp"])
    task, _ = tasks.create({"question": "CPU"})

    async def cancel(**kwargs):
        with main.connection() as db:
            db.execute(
                "UPDATE diagnostic_tasks SET cancel_requested=1 WHERE task_id=?",
                (task["task_id"],),
            )
        return response(text="不应作为成功报告保存")

    with pytest.raises(tasks.Cancelled):
        asyncio.run(
            mcp_runtime.run(
                "report",
                "CPU",
                task_id=task["task_id"],
                client=SimpleNamespace(responses=SimpleNamespace(create=cancel)),
            )
        )
    stopped = tasks.get(task["task_id"])
    assert stopped["status"] == "cancelled" and stopped["token_total"] == 30


def test_incomplete_skill_model_answer_is_retained_but_marked_partial(rig):
    install(providers=["ssh_mcp"])
    partial = response(text="尚未输出完的分析")
    partial.status = "incomplete"
    partial.incomplete_details = SimpleNamespace(reason="max_output_tokens")
    create = AsyncMock(return_value=partial)
    answer, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "CPU",
            return_usage=True,
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
        )
    )
    task = tasks.get(usage["task_id"])
    assert task["status"] == "partial" and task["report"]["answer"] == answer
    assert any("输出" in gap for gap in task["report"]["limitations"])


@pytest.mark.parametrize("target", [("hostid", "10"), ("ip", "172.20.2.101")])
@pytest.mark.parametrize("duplicate", [False, True])
def test_skill_zabbix_target_metadata_comes_only_from_unique_returned_host(
    monkeypatch, target, duplicate
):
    config = {"mcp_url": "http://zabbix.invalid/mcp"}
    calls = []

    class MonitoringSession:
        async def list_tools(self):
            return SimpleNamespace(
                tools=[
                    remote_tool(
                        name,
                        {
                            "output": {"type": "string"},
                            "extra_params": {"type": "object"},
                        },
                    )
                    for name in ("hostinterface_get", "host_get")
                ],
                nextCursor=None,
            )

        async def call_tool(self, name, args):
            calls.append(name)
            row = (
                {"hostid": "10", "ip": "172.20.2.101"}
                if name == "hostinterface_get"
                else {
                    "hostid": "10",
                    "name": "monitoring-linux",
                    "inventory": {"os": "Rocky Linux"},
                }
            )
            return SimpleNamespace(
                structuredContent={
                    "result": [row, dict(row, hostid="11")] if duplicate else [row]
                },
                content=[],
                isError=False,
            )

    @asynccontextmanager
    async def connect(*args):
        yield MonitoringSession()

    monkeypatch.setattr(zabbix, "connect", connect)

    async def run():
        async with SkillMCP(
            lambda key: config.get(key, ""),
            ["zabbix_mcp"],
            deadline=time.monotonic() + 20,
            target=target,
        ) as bridge:
            if target[0] == "ip":
                await bridge.call(
                    "zabbix_mcp", "hostinterface_get", {"filter": {"ip": target[1]}}
                )
            await bridge.call(
                "zabbix_mcp", "host_get", {"hostids": ["10"], "selectInventory": ["os"]}
            )
            if duplicate:
                assert not bridge.target_metadata
            else:
                assert bridge.target_metadata["host_id"] == "10"
                assert bridge.target_metadata["host_name"] == "monitoring-linux"
                assert bridge.target_metadata["device_type"] == "linux"
            assert "ssh_mcp" not in bridge.sessions

    asyncio.run(run())
    assert calls == (
        ["hostinterface_get", "host_get"] if target[0] == "ip" else ["host_get"]
    )
