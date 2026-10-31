"""The log analysis platform's MCP as the third evidence source (fake sessions)."""

import asyncio
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
import json
import socket
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from zoneinfo import ZoneInfo

import httpx
import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool, ToolAnnotations
from starlette.responses import PlainTextResponse

from app import main, mcp_runtime, skill_store as skills, worker
from app.integrations import log_mcp, ssh_mcp, zabbix
from app.orchestrator import tasks
from app.skill_context import model_view
from app.skill_mcp import EPOCH_SETTING, SkillMCP, clear_catalog_cache
from test_platform import client_for

TOKEN = "logmcp_fixture-token-0123456789"
CONFIG = {
    "openai_model": "fixture",
    "log_mcp_url": "http://logs.invalid/mcp",
    "log_mcp_token": TOKEN,
}
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False)
# Common window parameters of the log tools (logmcp/mcp_tools.py).
WINDOW = {
    "target": {"type": "string", "default": ""},
    "start": {"type": "string", "default": ""},
    "end": {"type": "string", "default": ""},
    "around": {"type": "string", "default": ""},
    "minutes": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None},
}
CLOCK = int(
    datetime(2026, 10, 31, 10, 0, 0, tzinfo=ZoneInfo("Asia/Shanghai")).timestamp()
)


def tool(name, props=None, required=(), annotations=READ_ONLY):
    return Tool(
        name=name,
        inputSchema={
            "type": "object",
            "properties": props or {},
            "required": list(required),
        },
        annotations=annotations,
    )


# Tools as the log platform lists them, plus ones the platform must never
# offer the model: not read-only, taking SQL or a URL, or not a log_ tool.
SERVER_TOOLS = [
    tool("log_list_tool_catalog"),
    tool(
        "log_list_sources", {"query": {"type": "string"}, "limit": {"type": "integer"}}
    ),
    tool(
        "log_resolve_target", {"ip": {"type": "string"}, "hostname": {"type": "string"}}
    ),
    tool("log_overview", {**WINDOW, "service": {"type": "string"}}),
    tool("log_compare", {**WINDOW, "query": {"type": "string"}, "baseline": {}}),
    tool("log_nginx_summary", {**WINDOW, "path_prefix": {"type": "string"}}),
    tool("log_java_exceptions", {**WINDOW, "service": {"type": "string"}}),
    tool("log_network_events", {**WINDOW, "timeline": {"type": "integer"}}),
    tool("log_search", {**WINDOW, "query": {"type": "string"}, "limit": {}}),
    tool("log_trace", {"trace_id": {"type": "string"}}, ["trace_id"]),
    tool(
        "log_purge",
        {"target": {"type": "string"}},
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
    ),
    tool("log_raw_query", {"SQL": {"type": "string"}}),
    tool("log_fetch", {"url": {"type": "string"}}),
    tool("shell_exec", {"cmd": {"type": "string"}}),
]
ALLOWED = {
    "log_list_tool_catalog",
    "log_list_sources",
    "log_resolve_target",
    "log_overview",
    "log_compare",
    "log_nginx_summary",
    "log_java_exceptions",
    "log_network_events",
    "log_search",
    "log_trace",
}
OVERVIEW = {
    "window": {"start": "2026-10-31 09:30:00", "end": "2026-10-31 10:30:00"},
    "total": 5210,
    "errors": 42,
    "previous_window_errors": 3,
    "top_errors": [
        {
            "template": "upstream timed out while reading response header from upstream",
            "count": 37,
            "hosts": 1,
            "new": True,
            "first": "2026-10-31 09:58:12",
            "last": "2026-10-31 10:21:40",
            "sample": "2026-10-31 10:21:40.120 [ERROR] web-01 nginx: upstream timed out",
        }
    ],
    "last_log": "2026-10-31 10:29:59",
    "topics": ["Nginx：请求 5100，5xx 37，4xx 12，P95 2.31 秒"],
    "status": "success",
}


def text_reply(data):
    """FastMCP's answer for a tool returning a dict: one JSON text block."""
    return SimpleNamespace(
        structuredContent=None,
        content=[
            SimpleNamespace(type="text", text=json.dumps(data, ensure_ascii=False))
        ],
        isError=False,
    )


class LogSession:
    def __init__(self, *, found=True, types=("os", "nginx_access"), granted=None):
        self.calls = []
        self.found, self.types, self.granted = found, list(types), granted

    async def list_tools(self, cursor=None):
        return SimpleNamespace(tools=SERVER_TOOLS, nextCursor=None)

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        if name == "log_list_tool_catalog":
            if isinstance(self.granted, Exception):
                raise self.granted
            if self.granted == "failed":
                return text_reply(
                    {"status": "failed", "error_code": "query_failed", "error": "x"}
                )
            names = (
                [t.name for t in SERVER_TOOLS]
                if self.granted is None
                else [
                    *log_mcp.META,
                    *self.granted,
                ]
            )
            return text_reply(
                {
                    "tools": [{"name": n, "kind": "统计摘要"} for n in names],
                    "status": "success",
                }
            )
        if name == "log_resolve_target":
            if not self.found:
                return text_reply(
                    {
                        "found": False,
                        "target": args.get("ip"),
                        "similar": [],
                        "hint": "最近 7 天没有来自该目标的日志：设备可能未配置 syslog、Agent 未部署",
                        "status": "success",
                    }
                )
            return text_reply(
                {
                    "found": True,
                    "target": args["ip"],
                    "matches": [
                        {
                            "host": "web-01",
                            "ip": args["ip"],
                            "types": self.types,
                            "count_7d": 120000,
                        }
                    ],
                    "status": "success",
                }
            )
        if name == "log_overview":
            return text_reply(OVERVIEW)
        return text_reply(
            {"window": OVERVIEW["window"], "tool": name, "status": "success"}
        )


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


@pytest.fixture
def logs(monkeypatch):
    session = LogSession()
    config = dict(CONFIG)
    connects, ssh = [], []
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))

    @asynccontextmanager
    async def connect(read_setting, **kwargs):
        connects.append(read_setting("log_mcp_token"))
        yield session

    @asynccontextmanager
    async def no_ssh(*args, **kwargs):
        ssh.append(args)
        raise ssh_mcp.IntegrationError("SSH MCP 未启用")
        yield

    monkeypatch.setattr(log_mcp, "connect", connect)
    monkeypatch.setattr(ssh_mcp, "configured", no_ssh)
    return SimpleNamespace(session=session, config=config, connects=connects, ssh=ssh)


class Call:
    type = "function_call"

    def __init__(self, name, args):
        self.name, self.arguments, self.call_id = name, json.dumps(args), "fixture"

    def model_dump(self, **kwargs):
        return {
            "type": self.type,
            "name": self.name,
            "arguments": self.arguments,
            "call_id": self.call_id,
        }


def response(*calls, text=""):
    return SimpleNamespace(
        output=list(calls),
        output_text=text,
        usage=SimpleNamespace(input_tokens=20, output_tokens=10, total_tokens=30),
    )


def analyze(event, *replies):
    """Run an alert analysis; the model gives `replies`, then a short conclusion
    (repeated: an uncited conclusion is sent back once for evidence)."""
    final = response(text='{"cause": "上游超时导致 502（E2）"}')
    create = AsyncMock(side_effect=[*replies, *[final] * 4])
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
    return tasks.get(usage["task_id"]), sent, create


def nginx_alert(event_id="880100"):
    return {
        "event_id": event_id,
        "event_name": "Nginx: 502 错误率过高",
        "host_ip": "198.51.100.40",
        "event_date": "2026.10.31",
        "event_time": "10:00:00",
    }


def test_only_read_only_log_tools_without_code_or_address_parameters_are_kept():
    assert {t.name for t in SERVER_TOOLS if log_mcp.allowed(t)} == ALLOWED
    assert log_mcp.authorized_tools(
        {"tools": [{"name": "log_overview"}, "bad", {"name": 3}], "status": "success"}
    ) == {"log_overview"}
    for unclear in ({"status": "failed", "tools": []}, [], {"tools": "x"}, None):
        assert log_mcp.authorized_tools(unclear) is None


def catalog(monkeypatch, session):
    # Each call stands for a different server state: no per-process cache.
    clear_catalog_cache()

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield session

    monkeypatch.setattr(log_mcp, "connect", connect)

    async def run():
        async with SkillMCP(
            lambda key: CONFIG.get(key, ""), ["logs"], deadline=time.monotonic() + 20
        ) as bridge:
            return set(await bridge.catalog("logs")), bridge.unauthorized_log_tools()

    return asyncio.run(run())


def test_catalog_shows_the_model_only_tools_the_token_was_granted(monkeypatch):
    tools, hidden = catalog(monkeypatch, LogSession(granted=["log_overview"]))
    assert tools == set(log_mcp.META) | {"log_overview"}
    # Hidden tools are reported; tools the platform never allows are not listed.
    assert "log_compare" in hidden and "log_purge" not in hidden
    # A token granted nothing beyond the base tools gets only those.
    tools, hidden = catalog(monkeypatch, LogSession(granted=[]))
    assert tools == set(log_mcp.META)
    # A catalog the platform cannot read keeps the full list: the log
    # platform still refuses tools the token was not granted.
    for granted in (RuntimeError("down"), "failed"):
        tools, hidden = catalog(monkeypatch, LogSession(granted=granted))
        assert tools == ALLOWED and hidden == []


def test_log_catalog_is_reused_until_the_console_bumps_the_epoch(monkeypatch):
    settings = dict(CONFIG)
    session = LogSession(granted=["log_overview"])

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield session

    monkeypatch.setattr(log_mcp, "connect", connect)

    async def tools():
        async with SkillMCP(
            settings.get, ["logs"], deadline=time.monotonic() + 20
        ) as bridge:
            return set(await bridge.catalog("logs")), bridge.unauthorized_log_tools()

    first = asyncio.run(tools())
    assert "log_overview" in first[0]
    # A new grant is not seen by the next task of this process yet ...
    session.granted = ["log_compare"]
    assert asyncio.run(tools()) == first
    # ... until 刷新目录 / 验证连接 bumps the epoch every worker keys on.
    settings[EPOCH_SETTING] = "2"
    refreshed, hidden = asyncio.run(tools())
    assert "log_compare" in refreshed and "log_overview" not in refreshed
    assert "log_overview" in hidden


def test_bridge_parses_single_json_text_blocks_and_keeps_failures_as_data(monkeypatch):
    session = LogSession()

    async def call_tool(name, args):
        session.calls.append((name, args))
        if args.get("target") == "203.0.113.9":
            return text_reply(
                {
                    "status": "failed",
                    "error_code": "forbidden",
                    "error": "当前令牌无权访问该来源",
                }
            )
        return text_reply({**OVERVIEW, "target": args["target"]})

    session.call_tool = call_tool

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield session

    monkeypatch.setattr(log_mcp, "connect", connect)

    async def run():
        async with SkillMCP(
            lambda key: CONFIG.get(key, ""), ["logs"], deadline=time.monotonic() + 20
        ) as bridge:
            ok = await bridge.call(
                "logs", "log_overview", {"target": "198.51.100.40", "minutes": 30}
            )
            refused = await bridge.call(
                "logs", "log_overview", {"target": "203.0.113.9"}
            )
            with pytest.raises(ValueError, match="Schema"):
                await bridge.call("logs", "log_overview", {"command": "id"})
            with pytest.raises(ValueError, match="授权的只读目录"):
                await bridge.call("logs", "log_purge", {"target": "x"})
            with pytest.raises(Exception, match="minutes"):
                await bridge.call("logs", "log_overview", {"minutes": "thirty"})
            return ok, refused

    ok, refused = asyncio.run(run())
    assert ok == {
        "is_error": False,
        "data": {**OVERVIEW, "target": "198.51.100.40"},
        "status": "success",
    }
    assert refused["is_error"] and refused["status"] == "failed"
    assert refused["error"] == "当前令牌无权访问该来源"
    # Rejected arguments never reached the log platform.
    assert [args for name, args in session.calls if name == "log_overview"] == [
        {"target": "198.51.100.40", "minutes": 30},
        {"target": "203.0.113.9"},
    ]


def test_alert_prefetch_finds_the_log_source_then_reads_the_alert_window(logs):
    task, sent, create = analyze(nginx_alert())
    calls = logs.session.calls
    assert calls[:2] == [
        ("log_list_tool_catalog", {}),
        ("log_resolve_target", {"ip": "198.51.100.40"}),
    ]
    window = {"target": "198.51.100.40", "around": str(CLOCK), "minutes": 30}
    assert sorted(calls[2:], key=lambda c: c[0]) == [
        ("log_compare", window),
        ("log_nginx_summary", window),
        ("log_overview", window),
    ]
    assert logs.connects == [TOKEN]
    evidence = sent["evidence"]
    assert evidence["log_target"] == {
        "evidence_id": "E1",
        "target": "198.51.100.40",
        "source_types": ["nginx_access", "os"],
    }
    prefetched = {p["tool"]: p["result"] for p in evidence["prefetched"]}
    assert set(prefetched) == {"log_overview", "log_nginx_summary", "log_compare"}
    # The JSON text block arrives as structured data with an evidence id.
    assert prefetched["log_overview"]["data"]["errors"] == 42
    assert all(result["evidence_id"] for result in prefetched.values())
    surge = [s for s in evidence["signals"] if s["metric"] == "error_surge"]
    assert surge and surge[0]["source"] == "logs"
    assert surge[0]["value"] == {"errors": 42, "previous_window_errors": 3}
    assert any(s["metric"] == "new_error_templates" for s in evidence["signals"])
    assert "platform-logs" in sent["applied_skills"]
    tools = create.call_args_list[0].kwargs["tools"]
    assert "logs" in tools[1]["parameters"]["properties"]["provider"]["enum"]
    report = task["report"]
    assert task["status"] == "success" and report["limitations"] == []
    assert report["capabilities"]["logs"] == {
        "status": "used",
        "target": "198.51.100.40",
    }
    assert report["capabilities"]["diagnostic_path"] == "logs-only"
    assert set(report["coverage"]["collected"]) == set(prefetched)
    assert "日志 MCP 4 条" in report["answer"] and "仅日志数据" in report["answer"]
    # Log evidence, statistics included, is shown in full only with logs.read.
    assert all(
        row["payload"]["restricted"] for row in tasks.evidence_page(task["task_id"])
    )
    assert all(
        row["payload"]["_meta"]["sensitive"] is True
        for row in tasks.evidence_page(task["task_id"], include_logs=True)
    )


def test_network_device_alert_adds_device_events_from_the_interface_ip(
    logs, monkeypatch
):
    logs.session.types = ["network"]
    logs.config["mcp_url"] = "http://zabbix.invalid/mcp"
    device = {
        "hostid": "10500",
        "host": "core-switch-01",
        "name": "核心交换机",
        "parentTemplates": [{"templateid": "1", "name": "Huawei VRP by SNMP"}],
        "interfaces": [{"type": "2", "ip": "198.51.100.50", "main": "1"}],
    }

    class ZabbixSession:
        async def list_tools(self):
            schema = {"output": {"type": "string"}, "extra_params": {"type": "object"}}
            return SimpleNamespace(
                tools=[tool(n, schema) for n in ("host_get", "item_get", "event_get")],
                nextCursor=None,
            )

        async def call_tool(self, name, args):
            rows = [device] if name == "host_get" else []
            return SimpleNamespace(
                structuredContent={"result": rows}, content=[], isError=False
            )

    @asynccontextmanager
    async def connect(*args):
        yield ZabbixSession()

    monkeypatch.setattr(zabbix, "connect", connect)
    event = {
        "event_id": "880200",
        "event_name": "Interface GE0/0/1: Link down",
        "host_id": "10500",
        "trigger_id": "90001",
        "event_date": "2026.10.31",
        "event_time": "10:00:00",
    }
    task, sent, _ = analyze(event)
    window = {"target": "198.51.100.50", "around": str(CLOCK), "minutes": 30}
    assert sorted(logs.session.calls[1:], key=lambda c: c[0]) == [
        ("log_network_events", window),
        ("log_overview", window),
        ("log_resolve_target", {"ip": "198.51.100.50"}),
    ]
    # Network devices get log evidence but never an SSH connection.
    assert logs.ssh == []
    assert sent["capabilities"]["device_type"] == "network"
    assert {"platform-network", "platform-logs"} <= set(sent["applied_skills"])
    assert task["report"]["capabilities"]["diagnostic_path"] == "zabbix+logs"


def test_topics_for_log_types_the_source_never_sent_are_skipped(logs):
    logs.session.types = ["os"]
    event = {**nginx_alert("880300"), "event_name": "Java: 频繁 Full GC"}
    task, _, _ = analyze(event)
    assert sorted(name for name, _ in logs.session.calls[2:]) == [
        "log_compare",
        "log_overview",
    ]
    assert {
        "tool": "log_java_exceptions",
        "reason": "该日志来源近 7 天没有Java日志",
    } in task["report"]["coverage"]["skipped"]
    assert task["status"] == "success"


def test_target_not_sending_logs_is_a_capability_note_not_a_gap(logs):
    logs.session.found = False
    task, sent, create = analyze(
        nginx_alert("880400"),
        response(
            Call(
                "call_mcp_tool",
                {"provider": "logs", "name": "log_search", "arguments": {}},
            )
        ),
        response(text='{"cause": "上游超时导致 502"}'),
    )
    assert [name for name, _ in logs.session.calls] == [
        "log_list_tool_catalog",
        "log_resolve_target",
    ]
    state = sent["capabilities"]["logs"]
    assert state["status"] == "not_onboarded"
    assert state["reason"].startswith("198.51.100.40 最近 7 天没有来自该目标的日志")
    # No log tools and no log Skill for the model.
    assert "platform-logs" not in sent["applied_skills"]
    tools = create.call_args_list[0].kwargs["tools"]
    assert "logs" not in tools[1]["parameters"]["properties"]["provider"]["enum"]
    report = task["report"]
    assert task["status"] == "success" and report["limitations"] == []
    assert {
        "tool": "log_search",
        "reason": "本任务的日志证据不可用，未调用",
    } in report["coverage"]["skipped"]
    assert "日志 MCP目标未接入：198.51.100.40 最近 7 天没有" in report["answer"]
    assert "日志 MCP目标未接入" in report["chat_scope"]


def test_failed_source_lookup_is_noted_and_closes_the_log_tools(logs):
    original = logs.session.call_tool

    async def call_tool(name, args):
        if name != "log_resolve_target":
            return await original(name, args)
        logs.session.calls.append((name, args))
        return text_reply(
            {
                "status": "failed",
                "error_code": "query_failed",
                "error": "日志库查询失败",
            }
        )

    logs.session.call_tool = call_tool
    task, sent, _ = analyze(nginx_alert("880450"))
    assert sent["capabilities"]["logs"] == {
        "status": "unavailable",
        "reason": "日志来源定位失败：日志库查询失败",
        "error_code": "query_failed",
    }
    assert [name for name, _ in logs.session.calls] == [
        "log_list_tool_catalog",
        "log_resolve_target",
    ]
    assert "platform-logs" not in sent["applied_skills"]
    assert task["status"] == "success" and task["report"]["limitations"] == []


def test_unconfigured_log_mcp_is_never_contacted_and_only_noted(logs):
    del logs.config["log_mcp_url"], logs.config["log_mcp_token"]
    task, sent, _ = analyze(nginx_alert("880500"))
    assert logs.connects == [] and logs.session.calls == []
    assert sent["capabilities"]["logs"] == {
        "status": "disabled",
        "reason": "未配置日志 MCP 地址和令牌",
    }
    assert "platform-logs" not in sent["applied_skills"]
    assert task["status"] == "success" and task["report"]["limitations"] == []
    assert "日志 MCP未启用：未配置日志 MCP 地址和令牌" in task["report"]["answer"]


def rejected(*args, **kwargs):
    """What the MCP client raises for HTTP 401: an anyio-wrapped status error."""
    request = httpx.Request("POST", "http://logs.invalid/mcp")
    error = httpx.HTTPStatusError(
        "401", request=request, response=httpx.Response(401, request=request)
    )
    raise BaseExceptionGroup("unhandled errors in a TaskGroup", [error])


def test_rejected_token_is_a_capability_note_with_the_reason(logs, monkeypatch):
    @asynccontextmanager
    async def connect(*args, **kwargs):
        rejected()
        yield

    monkeypatch.setattr(log_mcp, "connect", connect)
    task, sent, _ = analyze(nginx_alert("880600"))
    state = sent["capabilities"]["logs"]
    assert state["status"] == "unreachable"
    assert state["reason"].startswith(
        "日志 MCP 拒绝令牌（HTTP 401）：令牌无效、已过期或已撤销"
    )
    assert TOKEN not in json.dumps(task["report"], ensure_ascii=False)
    assert task["status"] == "success" and task["report"]["limitations"] == []
    assert "日志 MCP连接失败：日志 MCP 拒绝令牌（HTTP 401）" in task["report"]["answer"]


@contextmanager
def log_server():
    """The log platform's tool shapes over the real Streamable HTTP SDK."""
    mcp = FastMCP("logs", stateless_http=True, json_response=True)

    @mcp.tool(annotations=READ_ONLY)
    def log_list_tool_catalog() -> dict:
        return {"tools": [{"name": "log_overview"}], "status": "success"}

    @mcp.tool(annotations=READ_ONLY)
    def log_resolve_target(ip: str = "", hostname: str = "") -> dict:
        return {"found": True, "target": ip, "matches": [], "status": "success"}

    @mcp.tool(annotations=READ_ONLY)
    def log_overview(
        target: str = "", around: str = "", minutes: int | None = None
    ) -> dict:
        return {
            "total": 10,
            "errors": 2,
            "window": {"around": around},
            "status": "success",
        }

    @mcp.tool(annotations=READ_ONLY)
    def log_search(target: str = "", query: str = "") -> dict:
        return {"lines": [], "status": "success"}

    inner = mcp.streamable_http_app()

    async def app(scope, receive, send):
        if scope["type"] == "http":
            header = dict(scope["headers"]).get(b"authorization", b"").decode()
            if header != "Bearer " + TOKEN:
                await PlainTextResponse(
                    "MCP 令牌无效、已过期或已撤销", status_code=401
                )(scope, receive, send)
                return
        await inner(scope, receive, send)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    service = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
    thread = threading.Thread(
        target=service.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    try:
        for _ in range(1200):
            if service.started:
                break
            time.sleep(0.025)
        else:
            raise RuntimeError("fixture log MCP failed to start")
        yield f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"
    finally:
        service.should_exit = True
        thread.join(timeout=5)
        sock.close()


def test_real_transport_catalog_text_results_and_rejected_token():
    with log_server() as url:
        settings = {"log_mcp_url": url, "log_mcp_token": TOKEN}

        async def run(read):
            async with SkillMCP(
                read, ["logs"], deadline=time.monotonic() + 20
            ) as bridge:
                tools = set(await bridge.catalog("logs"))
                result = await bridge.call(
                    "logs", "log_overview", {"target": "198.51.100.40", "minutes": 30}
                )
                return tools, bridge.unauthorized_log_tools(), result

        tools, hidden, result = asyncio.run(run(settings.get))
        # log_search exists but this token's catalog does not grant it.
        assert tools == {"log_list_tool_catalog", "log_resolve_target", "log_overview"}
        assert hidden == ["log_search"]
        assert result["status"] == "success" and result["data"]["errors"] == 2
        wrong = {**settings, "log_mcp_token": "logmcp_revoked"}
        with pytest.raises(ssh_mcp.IntegrationError, match=r"拒绝令牌（HTTP 401）"):
            asyncio.run(run(wrong.get))


def test_verify_connection_lists_granted_tools_and_records_health(monkeypatch):
    session = LogSession(granted=["log_overview", "log_compare"])

    @asynccontextmanager
    async def connect(read, **kwargs):
        assert read("log_mcp_token") == TOKEN
        yield session

    monkeypatch.setattr(log_mcp, "connect", connect)
    client = client_for()
    values = {"log_mcp_url": "http://198.51.100.60:7077/mcp", "log_mcp_token": TOKEN}
    path = "/api/v1/platform/tools/discover?provider=logs"
    draft = client.post(path, json={"values": values}).json()
    assert draft["ok"] and draft["authorized_tools"] == sorted(
        {"log_overview", "log_compare"} | (log_mcp.META & ALLOWED)
    )
    # An unsaved draft never marks the saved configuration healthy.
    with main.connection() as db:
        assert not db.execute(
            "SELECT 1 FROM integration_health WHERE provider='logs'"
        ).fetchone()
    assert client.put("/api/v1/settings", json={"values": values}).status_code == 200
    assert client.post(path).json()["ok"]
    with main.connection() as db:
        assert db.execute(
            "SELECT status FROM integration_health WHERE provider='logs'"
        ).fetchone() == ("success",)
    overview = client.get("/api/v1/platform/overview").json()
    assert overview["readiness"]["logs"] and overview["log_mcp_configured"]

    @asynccontextmanager
    async def refused(*args, **kwargs):
        rejected()
        yield

    monkeypatch.setattr(log_mcp, "connect", refused)
    failed = client.post(path).json()
    assert not failed["ok"] and failed["detail"].startswith(
        "日志 MCP 拒绝令牌（HTTP 401）"
    )


def test_log_mcp_settings_are_validated_and_the_token_encrypted():
    client = client_for()
    values = {"log_mcp_url": "http://198.51.100.60:7077/mcp", "log_mcp_token": TOKEN}
    assert client.post("/api/v1/settings/validate", json={"values": values}).json()[
        "ok"
    ]
    assert client.put("/api/v1/settings", json={"values": values}).status_code == 200
    assert client.get("/api/v1/settings").json()["log_mcp_token"] == "********"
    with main.connection() as db:
        raw = db.execute(
            "SELECT value,secret FROM settings WHERE key='log_mcp_token'"
        ).fetchone()
    assert raw[1] == 1 and TOKEN not in raw[0]
    assert main.read_setting("log_mcp_token") == TOKEN
    for bad in (
        {"log_mcp_url": "http://198.51.100.60:7077/api"},
        {"log_mcp_url": "http://user:pass@198.51.100.60:7077/mcp"},
        {"log_mcp_token": "ssh-client-token"},
        {"log_mcp_token": "logmcp_with space"},
        {"log_mcp_url": "http://198.51.100.60:7077/mcp", "log_mcp_token": ""},
    ):
        assert (
            client.post("/api/v1/settings/validate", json={"values": bad}).status_code
            == 422
        ), bad
    # The masked token keeps the saved one; clearing both turns logs off.
    assert client.post(
        "/api/v1/settings/validate",
        json={"values": {**values, "log_mcp_token": "********"}},
    ).json()["ok"]
    empty = {"log_mcp_url": "", "log_mcp_token": ""}
    assert client.put("/api/v1/settings", json={"values": empty}).status_code == 200
    assert not log_mcp.configured(main.read_setting)


def skill_with(rule):
    return (
        "---\nname: log-rules\ndescription: 日志预采集\nprefetch:\n"
        + rule
        + "\n---\n按日志证据分析。"
    )


def test_prefetch_rules_take_log_tools_and_device_limits():
    parsed = skills.parse_document(
        skill_with(
            "- scopes: [alert]\n  types: ['*']\n  devices: [network]\n"
            "  logs: [log_overview, log_network_events]\n  schemas: [log_search]"
        )
    )
    assert parsed["prefetch"][0]["logs"] == ["log_overview", "log_network_events"]
    rows = [parsed]
    assert skills.prefetch_plan(rows, "alert", "network", "network")["logs"] == [
        "log_overview",
        "log_network_events",
    ]
    assert skills.prefetch_plan(rows, "alert", "network", "linux")["logs"] == []
    for rule in (
        "- scopes: [alert]\n  types: ['*']\n  logs: [log_trace]",
        "- scopes: [alert]\n  types: ['*']\n  logs: [log_resolve_target]",
        "- scopes: [alert]\n  types: ['*']\n  logs: [ssh_diagnose_cpu]",
        "- scopes: [alert]\n  types: ['*']\n  devices: [mainframe]",
    ):
        with pytest.raises(ValueError):
            skills.parse_document(skill_with(rule))


def test_platform_logs_skill_opens_only_the_log_mcp_and_plans_the_topics():
    package = skills.managed_package("platform-logs")
    rows = [package]
    assert skills.prefetch_plan(rows, "alert", "cpu", "linux")["logs"] == [
        "log_overview"
    ]
    assert skills.prefetch_plan(rows, "alert", "cpu", "network")["logs"] == [
        "log_overview",
        "log_network_events",
    ]
    assert skills.prefetch_plan(rows, "web", "nginx", "linux")["logs"] == [
        "log_overview",
        "log_nginx_summary",
        "log_compare",
    ]
    assert skills.prefetch_plan(rows, "qa", "nginx", "linux")["logs"] == []
    installed = {row["name"]: row for row in skills.rows()}
    assert installed["platform-logs"]["providers"] == ["logs"]
    assert "logs" not in installed["platform-base"]["providers"]


def test_log_view_keeps_whole_entries_within_the_model_limit():
    lines = [
        f"2026-10-31 10:{n % 60:02d}:00 [ERROR] web-01 app: " + "x" * 480
        for n in range(200)
    ]
    trend = [{"t": f"10:{n:02d}", "requests": n} for n in range(60)]
    outcome = {
        "is_error": False,
        "status": "success",
        "data": {"total": 200, "lines": lines, "trend": trend},
    }
    view = model_view("logs", "log_search", outcome, max_chars=4000)
    assert len(json.dumps(view, ensure_ascii=False)) <= 4000
    data = view["data"]
    assert data["total"] == 200 and data["lines_omitted"] == 200 - len(data["lines"])
    # A time series keeps its first and last points.
    assert data["trend"][0]["t"] == "10:00" and data["trend"][-1]["t"] == "10:59"
    assert "截短" in view["view_note"]
    # The note counts against the limit at every size (v1.3.2 lesson).
    for limit in range(500, 4001, 250):
        shown = model_view("logs", "log_search", outcome, max_chars=limit)
        assert len(json.dumps(shown, ensure_ascii=False)) <= limit, limit
    small = {"is_error": False, "status": "success", "data": {"total": 1}}
    assert model_view("logs", "log_overview", small, max_chars=4000) == small


def test_feishu_card_names_the_log_source_without_evidence_ids():
    info = {
        "_evidence": [
            {
                "id": "E3",
                "quote": "错误日志 42 条（E3）",
                "provider": "logs",
                "tool": "log_overview",
            }
        ],
        "_capabilities": {"diagnostic_path": "zabbix+logs", "device_type": "network"},
    }
    assert worker.evidence_lines(info) == ["· 日志 日志概览：错误日志 42 条"]
    assert worker.source_line(info) == "Zabbix 历史 + 日志（网络设备）"
