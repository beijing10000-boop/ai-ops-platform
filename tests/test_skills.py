"""Skill packages, authorization, reproducible tasks and source-driven execution."""

import asyncio
import base64
from contextlib import asynccontextmanager
import io
import json
import re
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

P = "/api/v1/platform/skills"


class Call:
    """A model function_call item as returned by the Responses API."""

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
    # Only the platform-maintained base Skill exists before any import.
    [base] = client.get(P).json()["items"]
    assert base["name"] == "platform-base" and base["managed"] and base["enabled"]
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
            TEXT
            not in db.execute(
                "SELECT bundle FROM platform_skills WHERE name='direct-ssh'"
            ).fetchone()[0]
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
    # With the custom Skill disabled, the scope falls back to the base Skill.
    assert [
        s["name"]
        for s in tasks.get(after["task_id"], private=True)["request"]["skills"]
    ] == ["platform-base"]
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
    # No custom Skill covers Web diagnosis, so the base Skill serves it.
    assert [row["name"] for row in skills.snapshot({}, "web")] == ["platform-base"]
    raw = client_for().get(P + "/template").content
    parsed = skills.parse_package("template.zip", base64.b64encode(raw))
    assert parsed["name"] == "ops-custom" and list(parsed["files"]) == ["SKILL.md"]
    assert "补充" in parsed["description"]
    base = skills.base_package()
    assert base["name"] == "platform-base" and len(base["files"]) == 4
    assert "ssh_resolve_target" in base["instructions"]
    assert "trend_get" in base["instructions"]
    assert "load_cpu_divergence" in base["instructions"]
    assert "sortfield" in base["files"]["references/zabbix-tools.md"]


# Every tool name the bundled templates mention must exist, or verification fails.
SSH_TOOLS = {
    "ssh_resolve_target",
    "ssh_resolve_host",
    "ssh_list_hosts",
    "ssh_test_connection",
    "ssh_triage",
    *(
        "ssh_diagnose_" + action
        for action in (
            "cpu memory processes memory_processes pressure resource_limits disk io "
            "mounts block_devices network sockets peer_connections peer_traffic "
            "tcp_states system health capabilities failed_services "
            "service_inventory timers time_sync containers container_stats "
            "system_errors oom security_status service logs kernel directory_usage"
        ).split()
    ),
}
PLATFORM_TOOLS = {"list_mcp_tools", "call_mcp_tool", "read_skill_resource"}


@pytest.mark.parametrize("template", ["platform-base", "custom-example"])
def test_templates_only_reference_existing_tools(template):
    text = "\n".join(skills.template_files(template).values())
    referenced = set(re.findall(r"`((?:ssh|list|call|read)_[a-z_]+|[a-z]+_get)`", text))
    assert referenced <= SSH_TOOLS | set(zabbix.READ_TOOLS) | PLATFORM_TOOLS, (
        referenced - SSH_TOOLS - set(zabbix.READ_TOOLS) - PLATFORM_TOOLS
    )


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
    body = {"question": "查询 198.51.100.21 现在 CPU", "zabbix_hostid": "10913"}
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
                "address": "198.51.100.21",
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
                    "arguments": {"address": "198.51.100.21"},
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
            "查询 198.51.100.21 现在 CPU",
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
                        "arguments": {"address": "198.51.100.21"},
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
            "查询 198.51.100.21 现在 CPU",
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
            target=("ip", "198.51.100.21"),
        ) as bridge:
            with pytest.raises(ValueError, match="未核验"):
                await bridge.call("ssh_mcp", "ssh_diagnose_cpu", {"host_id": 7})
            await bridge.call(
                "ssh_mcp", "ssh_resolve_target", {"address": "198.51.100.22"}
            )
            assert not bridge.bindings
            await bridge.call(
                "ssh_mcp", "ssh_resolve_target", {"address": "198.51.100.21"}
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
    directory_calls = []
    config = {"openai_model": "fixture", "mcp_url": "http://zabbix.invalid/mcp"}
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))
    monkeypatch.setattr(
        ssh_mcp,
        "configured",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not connect SSH")),
    )

    class ZabbixSession:
        async def list_tools(self):
            directory_calls.append(True)
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
                    "list_mcp_tools",
                    {"provider": "zabbix_mcp", "names": ["item_get", "history_get"]},
                )
            ),
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
    assert len(directory_calls) == 1
    assert (
        len(
            [
                r
                for r in tasks.evidence_page(usage["task_id"])
                if r["tool"] == "list_tools"
            ]
        )
        == 1
    )
    assert log[0][1]["extra_params"]["hostids"] == ["10"]
    stored = [
        r["payload"]
        for r in tasks.evidence_page(usage["task_id"])
        if r["tool"] in {"item_get", "history_get"}
    ]
    # Rows are kept once; the identical `data` text copy is not stored again.
    assert stored and all(p["records"] and "data" not in p for p in stored)
    query_context = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert query_context["current_timestamp"] > 0
    assert query_context["current_time"].endswith("+08:00")
    answer = tasks.get(usage["task_id"])["report"]["answer"]
    assert "分析与依据" in answer
    # The model's explicit history window is reported by the platform.
    assert (
        "- Zabbix 历史查询窗口（北京时间）：1970-01-01 08:00:01 – 1970-01-01 08:03:20"
        in answer
    )
    assert "- 证据来源：Zabbix MCP 2 条（E1–E2" in answer


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
                        "arguments": {"address": "198.51.100.21"},
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
            "198.51.100.21 CPU",
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


@pytest.mark.parametrize("target", [("hostid", "10"), ("ip", "198.51.100.21")])
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
                {"hostid": "10", "ip": "198.51.100.21"}
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


def tool_outputs(create):
    return [
        json.loads(item["output"])
        for item in create.call_args_list[-1].kwargs["input"]
        if item.get("type") == "function_call_output"
    ]


def test_delivered_schema_is_not_rediscovered_or_counted(rig):
    install(providers=["ssh_mcp"])
    create = AsyncMock(
        side_effect=[
            response(
                Call(
                    "list_mcp_tools",
                    {"provider": "ssh_mcp", "names": ["ssh_diagnose_cpu"]},
                )
            ),
            # Same tool by exact query: a different signature, same schema.
            response(
                Call(
                    "list_mcp_tools",
                    {"provider": "ssh_mcp", "query": "ssh_diagnose_cpu"},
                )
            ),
            response(text="只取得工具定义，未采集主机。"),
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
    first, second = tool_outputs(create)
    assert first["tools"][0]["name"] == "ssh_diagnose_cpu"
    assert "parameters" in first["tools"][0]
    assert second["already_loaded"] is True and second["names"] == ["ssh_diagnose_cpu"]
    task = tasks.get(usage["task_id"])
    assert task["tools"] == 1 and task["report"]["budget"]["used"]["calls"] == 1
    sent = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert sent["question"] == "CPU"


def test_budget_reports_forced_final_round_and_token_overrun(rig):
    install(providers=["ssh_mcp"])
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('ai_profile_budgets',?,0)",
            (json.dumps({"standard": {"rounds": 2, "tokens": 2000}}),),
        )

    def heavy(*calls, text=""):
        result = response(*calls, text=text)
        result.usage = SimpleNamespace(
            input_tokens=1200, output_tokens=100, total_tokens=1300
        )
        return result

    create = AsyncMock(
        side_effect=[
            heavy(Call("list_mcp_tools", {"provider": "ssh_mcp"})),
            heavy(text="只列出了工具目录，未采集主机。"),
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
    task = tasks.get(usage["task_id"])
    spent = task["report"]["budget"]
    # Budget limits are reported truthfully but are not diagnostic gaps.
    assert task["status"] == "success" and task["report"]["limitations"] == []
    assert spent["reasons"] == [] and spent["used"]["tokens"] == 2600
    assert spent["exhausted"] and task["report"]["budget_exhausted"]
    assert spent["limits_hit"] == [
        "已到最后一轮（上限 2 轮），本轮只总结",
        "Token 用量 2600 超过预算 2000（总结轮仍需发送完整上下文）",
    ]


def test_alert_is_sent_once_without_unexpanded_macros(rig):
    install(providers=["ssh_mcp"])
    event = {
        "event_id": "6619496",
        "event_value": "1",
        "event_source": "0",
        "event_name": "Linux: Load average is too high (per CPU load over 1.5 for 5m)",
        "severity": "3",
        "host_id": "10913",
        "host_ip": "198.51.100.21",
        "recovery_date": "{EVENT.RECOVERY.DATE}",
        "recovery_id": "{EVENT.RECOVERY.ID}",
    }
    create = AsyncMock(return_value=response(text='{"cause": "负载偏高"}'))
    asyncio.run(
        mcp_runtime.run(
            "JSON",
            json.dumps({"alert": event}, ensure_ascii=False),
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            event=event,
        )
    )
    sent = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert "question" not in sent
    assert sent["alert"]["event_name"] == event["event_name"]
    assert "recovery_date" not in sent["alert"] and "recovery_id" not in sent["alert"]
    assert event["recovery_date"] == "{EVENT.RECOVERY.DATE}"


def base_row():
    return next(row for row in client_for().get(P).json()["items"] if row["managed"])


def test_base_skill_is_installed_and_refreshed_but_keeps_admin_choices(monkeypatch):
    base = base_row()
    assert base["scopes"] == ["alert", "qa", "web"] and base["mode"] == "base"
    assert (
        client_for()
        .put(P + "/" + base["id"], json={"enabled": False, "priority": 7})
        .status_code
        == 200
    )
    changed = {
        **skills.base_package(),
        "files": {
            **skills.base_package()["files"],
            "SKILL.md": skills.base_package()["files"]["SKILL.md"] + "\n新版规则。\n",
        },
    }
    monkeypatch.setattr(skills, "base_package", lambda: changed)
    refreshed = base_row()
    assert refreshed["digest"] == skills.digest(changed["files"])
    assert refreshed["revision"] == base["revision"] + 2
    # An upgrade replaces the text but not where or whether it runs.
    assert refreshed["enabled"] is False and refreshed["priority"] == 7
    assert "新版规则" in skills.get(refreshed["id"])["instructions"]
    assert base_row()["revision"] == refreshed["revision"]  # unchanged copy: no-op


def test_base_skill_text_is_read_only_and_cannot_be_deleted_or_shadowed():
    base, client = base_row(), client_for()
    assert (
        client.put(P + "/" + base["id"], json={"instructions": "改写"}).status_code
        == 409
    )
    assert (
        client.put(P + "/" + base["id"], json={"mode": "standalone"}).status_code == 409
    )
    assert client.delete(P + "/" + base["id"]).status_code == 409
    shadow = upload(TEXT.replace("direct-ssh", "platform-base"), enabled=True)
    assert client.post(P, json={**shadow, "replace_existing": True}).status_code == 409
    assert base_row()["revision"] == base["revision"]


def test_standalone_skill_replaces_base_and_supplement_loads_with_it():
    client = client_for()
    supplement = upload(
        TEXT.replace("direct-ssh", "site-rules"),
        enabled=True,
        scopes=["web"],
        mode="supplement",
    )
    assert client.post(P, json=supplement).status_code == 201
    install(scopes=["qa"])  # default mode: standalone
    assert [r["name"] for r in skills.snapshot({}, "web")] == [
        "site-rules",
        "platform-base",
    ]
    assert [r["name"] for r in skills.snapshot({}, "qa")] == ["direct-ssh"]
    assert [
        r["name"] for r in skills.snapshot({"event": {"event_id": "9"}}, "alert")
    ] == ["platform-base"]
    row = next(r for r in client.get(P).json()["items"] if r["name"] == "site-rules")
    assert row["mode"] == "supplement"
    client.put(P + "/" + row["id"], json={"mode": "standalone"})
    assert [r["name"] for r in skills.snapshot({}, "web")] == ["site-rules"]


def test_scope_without_any_enabled_skill_fails_explicitly(rig):
    client_for().put(P + "/" + base_row()["id"], json={"enabled": False})
    create = AsyncMock()
    answer, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    task = tasks.get(usage["task_id"])
    assert task["status"] == "failed" and task["error_type"] == "NoSkillEnabled"
    assert "启用" in answer and not create.called


def test_secrets_never_reach_the_model_or_the_report(rig):
    session, config = rig
    install(providers=["ssh_mcp"])
    config["openai_api_key"] = "sk-never-expose-api-key"
    leaked = config["ssh_mcp_token"] + " / " + config["openai_api_key"]

    async def call_tool(name, args):
        session.calls.append((name, args))
        data = (
            {
                "status": "success",
                "host_id": 7,
                "address": "198.51.100.21",
                "revision": 3,
                "name": "linux-live",
                "zabbix_hostid": "10913",
            }
            if name == "ssh_resolve_target"
            else {"status": "success", "host_id": 7, "note": "token " + leaked}
        )
        return SimpleNamespace(structuredContent=data, content=[], isError=False)

    session.call_tool = call_tool
    create = AsyncMock(
        side_effect=[
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_resolve_target",
                        "arguments": {"address": "198.51.100.21"},
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
            response(text="结论，原文含 " + leaked),
        ]
    )
    answer, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "查询 198.51.100.21 现在 CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    model_inputs = json.dumps(
        [call.kwargs for call in create.call_args_list], default=str
    )
    report = json.dumps(tasks.get(usage["task_id"])["report"], ensure_ascii=False)
    for secret in (config["ssh_mcp_token"], config["openai_api_key"]):
        assert secret not in model_inputs
        assert secret not in report and secret not in answer


PREFETCH = (
    "---\nname: alert-prefetch\ndescription: 告警预采集\nprefetch:\n"
    "- scopes: [alert]\n  types: [cpu]\n  ssh: [ssh_diagnose_cpu]\n"
    "  schemas: [ssh_diagnose_cpu]\n---\n按预采集结果分析 CPU 告警。"
)


@pytest.mark.parametrize(
    "rule",
    [
        "- scopes: [alert]\n  types: [cpu]\n  ssh: [ssh_diagnose_logs]",
        "- scopes: [alert]\n  types: [cpu]\n  shell: [id]",
        "- scopes: [everywhere]\n  types: [cpu]",
        "- scopes: [alert]\n  types: [made-up]",
        "- scopes: [alert]\n  types: [cpu]\n  zabbix_items: ['key; rm -rf']",
        "- scopes: [alert]\n  types: [cpu]\n  schemas: [raw_api_call]",
    ],
)
def test_invalid_prefetch_rules_are_rejected(rule):
    text = TEXT.replace("---\n直接", "prefetch:\n" + rule + "\n---\n直接")
    assert client_for().post(P + "/validate", json=upload(text)).status_code == 422


def test_prefetch_rules_survive_web_edits_and_only_match_their_scope():
    row = client_for().post(P, json=upload(PREFETCH, enabled=True)).json()
    edited = client_for().put(
        P + "/" + row["id"], json={"instructions": "改写后的说明。"}
    )
    assert edited.status_code == 200
    saved = skills.get(row["id"])
    assert saved["instructions"] == "改写后的说明。"
    assert saved["prefetch"][0]["ssh"] == ["ssh_diagnose_cpu"]
    base = [skills.base_package()]
    assert skills.prefetch_plan(base, "alert", "cpu")["ssh"] == [
        "ssh_diagnose_cpu",
        "ssh_diagnose_processes",
    ]
    # The base Skill's alert rules never reach SSH for Q&A or Web questions.
    for scope in ("qa", "web"):
        assert skills.prefetch_plan(base, scope, "cpu") == {
            "ssh": [],
            "zabbix_items": [],
            "schemas": [],
        }


def test_alert_prefetch_resolves_target_and_collects_before_the_first_round(rig):
    session, _ = rig
    session.tools.append(
        remote_tool("ssh_resolve_host", {"zabbix_hostid": {"type": "string"}})
    )
    original = session.call_tool

    async def call_tool(name, args):
        if name == "ssh_resolve_host":
            session.calls.append((name, args))
            return SimpleNamespace(
                structuredContent={
                    "status": "success",
                    "host_id": 7,
                    "address": "198.51.100.21",
                    "revision": 3,
                    "name": "linux-live",
                    "zabbix_hostid": "10913",
                },
                content=[],
                isError=False,
            )
        return await original(name, args)

    session.call_tool = call_tool
    client_for().post(P, json=upload(PREFETCH, enabled=True, providers=["ssh_mcp"]))
    event = {
        "event_id": "770100",
        "event_value": "1",
        "event_name": "Linux: Load average is too high",
        "severity": "4",
        "host_id": "10913",
    }
    create = AsyncMock(return_value=response(text='{"cause": "负载偏高"}'))
    _, usage = asyncio.run(
        mcp_runtime.run(
            "JSON",
            json.dumps({"alert": event}, ensure_ascii=False),
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            event=event,
            return_usage=True,
        )
    )
    assert [name for name, _ in session.calls] == [
        "ssh_resolve_host",
        "ssh_diagnose_cpu",
    ]
    assert session.calls[1][1] == {"host_id": 7, "expected_revision": 3}
    sent = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert sent["verified_ssh_target"]["host_id"] == 7
    assert sent["verified_ssh_target"]["revision"] == 3
    assert sent["prefetched"][0]["tool"] == "ssh_diagnose_cpu"
    assert sent["prefetched"][0]["result"]["data"]["action"] == "cpu"
    assert sent["preloaded_tool_schemas"][0]["name"] == "ssh_diagnose_cpu"
    task = tasks.get(usage["task_id"])
    # One model round answered directly; both MCP calls are evidence.
    assert create.call_count == 1 and task["status"] == "success"
    assert task["tools"] == 2 and task["report"]["budget"]["used"]["calls"] == 2


def test_prefetch_notes_unresolved_ssh_target_without_marking_a_gap(rig):
    session, _ = rig
    session.tools.append(
        remote_tool("ssh_resolve_host", {"zabbix_hostid": {"type": "string"}})
    )

    async def call_tool(name, args):
        session.calls.append((name, args))
        return SimpleNamespace(
            structuredContent={
                "status": "failed",
                "error": "映射不存在或存在重复关联，请由管理员修正",
                "error_code": "mapping_unresolved",
            },
            content=[],
            isError=False,
        )

    session.call_tool = call_tool
    client_for().post(P, json=upload(PREFETCH, enabled=True, providers=["ssh_mcp"]))
    event = {"event_id": "770101", "event_name": "CPU load high", "host_id": "20001"}
    create = AsyncMock(return_value=response(text='{"cause": "无 SSH 证据"}'))
    _, usage = asyncio.run(
        mcp_runtime.run(
            "JSON",
            json.dumps({"alert": event}, ensure_ascii=False),
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            event=event,
            return_usage=True,
        )
    )
    assert [name for name, _ in session.calls] == ["ssh_resolve_host"]
    sent = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert sent["ssh_target"]["error_code"] == "mapping_unresolved"
    assert "prefetched" not in sent
    # Windows/network/unregistered hosts have no SSH asset: a note, not a gap.
    assert tasks.get(usage["task_id"])["status"] == "success"


def test_prefetched_evidence_is_numbered_and_alert_citations_are_checked(rig):
    session, _ = rig
    session.tools.append(
        remote_tool("ssh_resolve_host", {"zabbix_hostid": {"type": "string"}})
    )
    original = session.call_tool

    async def call_tool(name, args):
        if name == "ssh_resolve_host":
            session.calls.append((name, args))
            return SimpleNamespace(
                structuredContent={
                    "status": "success",
                    "host_id": 7,
                    "address": "198.51.100.21",
                    "revision": 3,
                    "name": "linux-live",
                    "zabbix_hostid": "10913",
                },
                content=[],
                isError=False,
            )
        return await original(name, args)

    session.call_tool = call_tool
    client_for().post(P, json=upload(PREFETCH, enabled=True, providers=["ssh_mcp"]))
    event = {"event_id": "770102", "event_name": "Load high", "host_id": "10913"}
    answer = {
        "cause": "负载偏高（E2）",
        "action": ["核对告警时段的批处理任务", "补查短时进程增量"],
        "evidence": [
            {"id": "E2", "quote": "load 0.5"},
            {"id": "E2", "quote": "load 9.5"},
            {"id": "E7", "quote": "不存在"},
        ],
    }
    create = AsyncMock(return_value=response(text=json.dumps(answer)))
    _, usage = asyncio.run(
        mcp_runtime.run(
            "JSON",
            json.dumps({"alert": event}, ensure_ascii=False),
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            event=event,
            return_usage=True,
        )
    )
    sent = json.loads(create.call_args_list[0].kwargs["input"][0]["content"])
    assert sent["verified_ssh_target"]["evidence_id"] == "E1"
    assert sent["prefetched"][0]["result"]["evidence_id"] == "E2"
    report = tasks.get(usage["task_id"])["report"]
    citations = report["citations"]
    assert [item["quote"] for item in citations["valid"]] == ["load 0.5"]
    assert [item["id"] for item in citations["invalid"]] == ["E2", "E7"]
    assert citations["confidence"] == "中"
    # Structured output: the platform numbers the suggestions and renders the
    # scope, so the model's final round does not restate target, time or sources.
    text = report["answer"]
    assert "处理建议\n1. 核对告警时段的批处理任务\n2. 补查短时进程增量" in text
    assert "诊断范围（平台生成）\n- 目标：linux-live（Zabbix Host ID 10913" in text
    assert "SSH 资产 7，地址 198.51.100.21）" in text
    assert "- 采集时间（北京时间）：" in text and "历史查询窗口" not in text
    assert "- 证据来源：SSH MCP 2 条（E1–E2，详见证据与工具执行记录）" in text
    assert text.index("诊断范围") < text.index("证据核对\n依据可信度：中")
    # Evidence ids map to the stored evidence rows shown on the task page.
    rows = {
        str(row["id"]): row["tool"] for row in tasks.evidence_page(usage["task_id"])
    }
    assert {rows[row]: ident for row, ident in report["evidence_ids"].items()} == {
        "ssh_resolve_host": "E1",
        "ssh_diagnose_cpu": "E2",
    }


def test_model_calls_get_evidence_ids_and_cache_hits_keep_theirs(rig):
    install(providers=["ssh_mcp"])
    cpu = Call(
        "call_mcp_tool",
        {
            "provider": "ssh_mcp",
            "name": "ssh_diagnose_cpu",
            "arguments": {"host_id": 7},
        },
    )
    create = AsyncMock(
        side_effect=[
            response(Call("list_mcp_tools", {"provider": "ssh_mcp"})),
            response(
                Call(
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_resolve_target",
                        "arguments": {"address": "198.51.100.21"},
                    },
                )
            ),
            response(cpu, cpu),
            response(text="CPU 负载 0.5（E2），目标见 E1，另见 E9。"),
        ]
    )
    _, usage = asyncio.run(
        mcp_runtime.run(
            "中文报告",
            "查询 198.51.100.21 现在 CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    conversation = create.call_args_list[-1].kwargs["input"]
    ids = [
        json.loads(item["output"]).get("evidence_id")
        for item in conversation
        if item.get("type") == "function_call_output"
    ]
    # Catalogs are not evidence; the repeated call reuses E2.
    assert ids == [None, "E1", "E2", "E2"]
    report = tasks.get(usage["task_id"])["report"]
    assert report["citations"]["method"] == "reference"
    assert [item["id"] for item in report["citations"]["valid"]] == ["E2", "E1"]
    assert report["citations"]["invalid"][0]["id"] == "E9"
    assert "- E2 SSH MCP / ssh_diagnose_cpu" in report["answer"]


def test_zabbix_schemas_are_compact_but_validation_is_unchanged():
    schema = zabbix.input_schema("item_get")
    assert len(json.dumps(schema, ensure_ascii=False)) < 2000
    assert "key_" in schema["properties"]["search"]["propertyNames"]["enum"]
    with pytest.raises(ValueError, match="search"):
        zabbix.validate_args("item_get", {"search": {"password": "x"}})
    assert zabbix.validate_args(
        "item_get", {"search": {"key_": ["system.cpu.load"]}, "hostids": ["10"]}
    )["search"] == {"key_": ["system.cpu.load"]}


def test_long_answer_is_kept_whole_in_web_and_feishu(rig):
    from app.worker import analysis_summary

    install(providers=["ssh_mcp"])
    long_answer = "完整依据🙂\n" * 9000 + "最后一段不能丢失"
    create = AsyncMock(return_value=response(text=long_answer))
    answer, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "CPU",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    report = tasks.get(usage["task_id"])["report"]
    assert answer == long_answer and report["answer"] == long_answer
    assert long_answer in analysis_summary({"_report_answer": report["answer"]})
