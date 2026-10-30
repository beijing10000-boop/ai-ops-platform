"""Live SSH MCP tool registry, catalog-based discovery and the diagnostic test."""

from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import pytest
from mcp.types import Tool, ToolAnnotations

from app import main, platform_api
from app.integrations import ssh_mcp
from app.orchestrator import tasks
from tests.test_platform import client_for

HOST = {"type": "integer"}
REVISION = {"anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]}
DETAIL = {"enum": ["summary", "full"], "type": "string", "default": "summary"}
SERVICE = {"type": "string", "pattern": "^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$"}
MINUTES = {"type": "integer", "minimum": 1, "maximum": 1440, "default": 30}


def remote(name, props=None, required=("host_id",), read_only=True):
    props = (
        {"host_id": HOST, "expected_revision": REVISION, "detail": DETAIL, **props}
        if props is not None
        else {}
    )
    return Tool(
        name=name,
        description="远端描述：" + name,
        inputSchema={
            "type": "object",
            "properties": props,
            "required": list(required) if props else [],
        },
        annotations=ToolAnnotations(
            readOnlyHint=read_only, destructiveHint=not read_only
        ),
    )


TOOLS = [
    Tool(
        name="ssh_resolve_host",
        description="按 Zabbix Host ID 解析",
        inputSchema={
            "type": "object",
            "properties": {"zabbix_hostid": {"type": "string"}},
            "required": ["zabbix_hostid"],
        },
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    ),
    remote("ssh_list_tool_catalog"),
    remote("ssh_test_connection", {}),
    remote("ssh_diagnose_cpu", {}),
    remote("ssh_diagnose_nginx", {"minutes": MINUTES}),
    remote("ssh_diagnose_oom", {"minutes": MINUTES}),
    remote(
        "ssh_diagnose_service_detail",
        {"service": SERVICE, "minutes": MINUTES},
        ("host_id", "service"),
    ),
    # Listed by the server but not granted to this client token.
    remote(
        "ssh_diagnose_logs",
        {"service": SERVICE, "minutes": MINUTES},
        ("host_id", "service"),
    ),
    # Job control is not read-only: never listed, never probed.
    remote("ssh_submit_diagnostics", {"host_ids": {"type": "array"}}, read_only=False),
]
CATALOG = [
    {
        "id": "connection",
        "tool": "ssh_test_connection",
        "name": "SSH 连接测试",
        "question": "是否能严格校验主机身份、登录并执行 Linux 命令？",
        "category": "连接与概览",
        "params": [],
        "risk": "low",
        "sensitive": False,
        "extension": False,
        "standard_only": False,
        "notes": [],
        "estimated_seconds": 20,
    },
    {"id": "cpu", "tool": "ssh_diagnose_cpu", "category": "性能与进程", "risk": "low"},
    {
        "id": "nginx",
        "tool": "ssh_diagnose_nginx",
        "name": "Nginx 诊断",
        "category": "Web 服务",
        "params": [
            {
                "name": "minutes",
                "type": "integer",
                "required": False,
                "default": 30,
                "minimum": 1,
                "maximum": 1440,
                "description": "回溯窗口（分钟）",
            }
        ],
        "risk": "medium",
        "sensitive": True,
        "extension": True,
        "standard_only": True,
        "notes": ["只读取文件尾部有限字节"],
        "estimated_seconds": 15,
    },
    {
        "id": "service_detail",
        "tool": "ssh_diagnose_service_detail",
        "category": "服务与日志",
        "params": [{"name": "service", "type": "string", "required": True}],
        "risk": "low",
        "sensitive": True,
        "extension": True,
    },
    # Servers before v0.5.0 return only the action id.
    {"id": "oom", "category": "服务与日志", "risk": "low", "sensitive": True},
    # Granted, but this server version does not expose the tool.
    {"id": "jvm", "tool": "ssh_diagnose_jvm", "risk": "high"},
]


class Session:
    def __init__(self, tools=TOOLS, catalog=CATALOG):
        self.tools, self.catalog, self.calls, self.listings = tools, catalog, [], 0

    async def list_tools(self, cursor=None):
        self.listings += 1
        return SimpleNamespace(tools=self.tools, nextCursor=None)

    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        if name == "ssh_list_tool_catalog":
            data = {"result": self.catalog}
        elif name == "ssh_resolve_host":
            data = (
                {
                    "status": "success",
                    "host_id": 92,
                    "revision": 3,
                    "zabbix_hostid": "10",
                    "name": "linux-live",
                    "address": "198.51.100.21",
                }
                if args["zabbix_hostid"] == "10"
                else {
                    "status": "failed",
                    "error": "映射不存在或存在重复关联，请由管理员修正",
                    "error_code": "mapping_unresolved",
                }
            )
        else:
            data = {
                "host_id": args["host_id"],
                "action": name.removeprefix("ssh_"),
                "status": "success",
                "summary": {"assessment": "已采集；未触发已实现规则不代表健康"},
                "findings": [{"level": "info", "metric": "login", "value": "ok"}],
                "duration_ms": 321,
            }
        return SimpleNamespace(structuredContent=data, content=[], isError=False)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    monkeypatch.setattr(platform_api, "SSH_REGISTRY_CACHE", {})
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)")


def enable_ssh():
    with main.connection() as db:
        for key, value in (
            ("ssh_mcp_enabled", "true"),
            ("ssh_mcp_url", "http://ssh.invalid/mcp"),
            ("ssh_mcp_token", "never-expose-token"),
        ):
            db.execute("INSERT INTO settings VALUES (?,?,0)", (key, value))


@pytest.fixture
def session(monkeypatch):
    session = Session()

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield SimpleNamespace(session=session)

    monkeypatch.setattr(ssh_mcp, "configured", connect)
    enable_ssh()
    return session


def ssh_rows(data):
    return {t["name"]: t for t in data["tools"] if t["provider"] == "ssh_mcp"}


def test_registry_lists_live_ssh_tools_with_catalog_metadata(session):
    client = client_for("auditor")
    data = client.get("/api/v1/platform/tools").json()
    rows = ssh_rows(data)
    assert data["ssh_mcp_error"] is None and data["ssh_catalog"] is True
    assert "diagnose_linux_host" not in {t["name"] for t in data["tools"]}
    assert "ssh_submit_diagnostics" not in rows
    # Zabbix keeps its curated, locally enforced schema.
    host_get = next(t for t in data["tools"] if t["name"] == "host_get")
    assert (
        host_get["provider"] == "zabbix_mcp" and host_get["input_schema"]["properties"]
    )
    nginx = rows["ssh_diagnose_nginx"]
    assert nginx["risk"] == "medium" and nginx["sensitive"] is True
    assert nginx["extension"] is True and nginx["standard_only"] is True
    assert [p["name"] for p in nginx["params"]] == ["minutes"]
    assert nginx["authorized"] is True and nginx["category"] == "Web 服务"
    assert nginx["description"] == "远端描述：ssh_diagnose_nginx"
    assert nginx["input_schema"]["properties"]["minutes"]["maximum"] == 1440
    assert nginx["device_types"] == ["linux"] and nginx["notes"]
    # Older catalog entries (id only) still authorize ssh_diagnose_<id>.
    assert rows["ssh_diagnose_oom"]["authorized"] is True
    assert rows["ssh_diagnose_service_detail"]["params"][0]["required"] is True
    # Listed by the server but outside the token's catalog.
    logs = rows["ssh_diagnose_logs"]
    assert logs["authorized"] is False and logs["enabled"] is False
    assert {p["name"]: p["required"] for p in logs["params"]} == {
        "service": True,
        "minutes": False,
    }
    assert logs["sensitive"] is True and logs["risk"] is None
    resolve = rows["ssh_resolve_host"]
    assert resolve["category"] == "资产解析" and resolve["authorized"] is True
    assert list(rows)[:2] == ["ssh_list_tool_catalog", "ssh_resolve_host"]
    # The granted-but-unlisted jvm action is not invented as a usable tool.
    assert "ssh_diagnose_jvm" not in rows
    assert "never-expose-token" not in json.dumps(data)


def test_registry_is_cached_and_refreshable(session):
    client = client_for("operator")
    first = client.get("/api/v1/platform/tools").json()
    listings = session.listings
    again = client.get("/api/v1/platform/tools").json()
    assert first["ssh_cached"] is False and again["ssh_cached"] is True
    assert session.listings == listings and ssh_rows(again) == ssh_rows(first)
    fresh = client.get("/api/v1/platform/tools?refresh=true").json()
    assert fresh["ssh_cached"] is False and session.listings > listings


def test_registry_without_ssh_mcp_reports_the_reason(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("disabled SSH MCP must not be contacted")

    monkeypatch.setattr(ssh_mcp, "configured", forbidden)
    data = client_for("auditor").get("/api/v1/platform/tools").json()
    assert not ssh_rows(data) and "未启用" in data["ssh_mcp_error"]
    assert any(t["provider"] == "zabbix_mcp" for t in data["tools"])
    assert data["playbooks"]["cpu"]["label"]


@pytest.mark.parametrize(
    "error,expected",
    [
        # anyio wraps errors raised while the Streamable HTTP session closes.
        (
            ExceptionGroup(
                "unhandled errors in a TaskGroup",
                [
                    ExceptionGroup(
                        "nested", [ssh_mcp.IntegrationError("SSH MCP 未启用")]
                    )
                ],
            ),
            "SSH MCP 未启用",
        ),
        (OSError("connection refused"), "SSH MCP 连接失败：OSError"),
    ],
)
def test_unreachable_ssh_mcp_returns_empty_list_not_500(monkeypatch, error, expected):
    @asynccontextmanager
    async def broken(*args, **kwargs):
        raise error
        yield

    monkeypatch.setattr(ssh_mcp, "configured", broken)
    enable_ssh()
    response = client_for("auditor").get("/api/v1/platform/tools")
    assert response.status_code == 200
    assert not ssh_rows(response.json())
    assert response.json()["ssh_mcp_error"] == expected


def test_discover_returns_catalog_authorized_tool_names(session):
    data = client_for().post("/api/v1/platform/tools/discover?provider=ssh_mcp").json()
    assert data["ok"] is True
    # From the catalog itself, not intersected with a fixed platform table.
    assert data["authorized_tools"] == [
        "ssh_diagnose_cpu",
        "ssh_diagnose_jvm",
        "ssh_diagnose_nginx",
        "ssh_diagnose_oom",
        "ssh_diagnose_service_detail",
        "ssh_test_connection",
    ]


def test_discover_falls_back_to_read_only_ssh_tools_without_catalog(session):
    session.tools = [t for t in TOOLS if t.name != "ssh_list_tool_catalog"]
    data = client_for().post("/api/v1/platform/tools/discover?provider=ssh_mcp").json()
    assert data["ok"] is True
    assert "ssh_resolve_host" in data["authorized_tools"]
    assert "ssh_diagnose_logs" in data["authorized_tools"]
    assert "ssh_submit_diagnostics" not in data["authorized_tools"]
    assert not any(name == "ssh_list_tool_catalog" for name, _ in session.calls)


@pytest.mark.parametrize(
    "body,status,text",
    [
        ({"tool": "ssh_submit_diagnostics", "zabbix_hostid": "10"}, 422, "仅支持"),
        ({"tool": "ssh_triage", "zabbix_hostid": "10"}, 422, "仅支持"),
        ({"tool": "ssh_resolve_host", "zabbix_hostid": "10"}, 422, "仅支持"),
        (
            {"tool": "ssh_diagnose_service_detail", "zabbix_hostid": "10"},
            422,
            "service",
        ),
        ({"tool": "ssh_diagnose_logs", "zabbix_hostid": "10"}, 422, "授权"),
        ({"tool": "ssh_diagnose_cpu", "zabbix_hostid": "10;id"}, 422, ""),
        (
            {
                "tool": "ssh_diagnose_cpu",
                "zabbix_hostid": "10",
                "arguments": {"service": "nginx.service"},
            },
            422,
            "",
        ),
        (
            {"provider": "zabbix_mcp", "tool": "host_get", "zabbix_hostid": "10"},
            422,
            "",
        ),
    ],
)
def test_probe_rejects_tools_needing_more_than_the_host(session, body, status, text):
    response = client_for().post("/api/v1/platform/tools/probe", json=body)
    assert response.status_code == status
    assert text in json.dumps(response.json(), ensure_ascii=False)
    # Nothing ran on the target host.
    assert not [c for c in session.calls if c[0] not in {"ssh_list_tool_catalog"}]
    assert tasks.page()["total"] == 0


def test_probe_requires_settings_permission(session):
    body = {"tool": "ssh_test_connection", "zabbix_hostid": "10"}
    for role in ("operator", "auditor"):
        assert (
            client_for(role).post("/api/v1/platform/tools/probe", json=body).status_code
            == 403
        )
    assert session.calls == []


def test_probe_resolves_host_and_runs_one_read_only_call(session):
    response = client_for("ops_admin").post(
        "/api/v1/platform/tools/probe",
        json={
            "provider": "ssh_mcp",
            "tool": "ssh_test_connection",
            "zabbix_hostid": "10",
        },
    )
    data = response.json()
    assert response.status_code == 200 and data["ok"] is True
    assert data["status"] == "success" and data["duration_ms"] == 321
    assert data["findings"][0]["metric"] == "login" and data["error_code"] is None
    assert data["ssh_host_id"] == 92 and data["host_revision"] == 3
    remote_calls = [c for c in session.calls if c[0] != "ssh_list_tool_catalog"]
    assert remote_calls == [
        ("ssh_resolve_host", {"zabbix_hostid": "10"}),
        ("ssh_test_connection", {"host_id": 92, "expected_revision": 3}),
    ]
    assert tasks.page()["total"] == 0
    with main.connection() as db:
        audit = db.execute("SELECT key FROM audit WHERE action='tool_probe'").fetchall()
    assert audit == [("ssh_test_connection host=10 result=success",)]


def test_probe_reports_unmapped_host_without_running_the_tool(session):
    data = (
        client_for()
        .post(
            "/api/v1/platform/tools/probe",
            json={"tool": "ssh_diagnose_nginx", "zabbix_hostid": "11"},
        )
        .json()
    )
    assert data["ok"] is False and data["status"] == "failed"
    assert data["error_code"] == "mapping_unresolved" and "映射" in data["error"]
    assert "ssh_diagnose_nginx" not in [name for name, _ in session.calls]


def test_evidence_page_hides_sensitive_meta_and_log_like_tool_names():
    task, _ = tasks.create({"question": "日志"})
    rows = [
        # The recorded catalog flag wins even for an innocuous name.
        (
            "ssh_mcp",
            "ssh_diagnose_cpu",
            {
                "output": "flagged-raw",
                "_meta": {
                    "kind": "model",
                    "arguments": {"host_id": 92},
                    "sensitive": True,
                    "evidence_id": "E1",
                },
            },
        ),
        ("ssh_mcp", "ssh_diagnose_nginx_access", {"output": "GET /private-path"}),
        ("ssh_mcp", "ssh_diagnose_syslog", {"output": "sshd failed password"}),
        ("ssh_mcp", "ssh_collect", {"output": "collected-steps"}),
        ("linux_ssh", "logs", {"output": "legacy-log-line"}),
        ("ssh_mcp", "ssh_diagnose_cpu", {"output": "visible-cpu"}),
        (
            "zabbix_mcp",
            "history_get",
            {
                "data": "visible-history",
                "_meta": {"kind": "prefetch", "sensitive": False},
            },
        ),
    ]
    for provider, tool, payload in rows:
        tasks.evidence(task["task_id"], provider, tool, payload)
    hidden = tasks.evidence_page(task["task_id"])
    assert [bool(r["payload"].get("restricted")) for r in hidden] == [
        True,
        True,
        True,
        True,
        True,
        False,
        False,
    ]
    text = json.dumps(hidden, ensure_ascii=False)
    for secret in (
        "flagged-raw",
        "/private-path",
        "failed password",
        "legacy-log-line",
    ):
        assert secret not in text
    # Call metadata stays visible: it identifies the evidence, not its content.
    assert hidden[0]["payload"]["_meta"]["evidence_id"] == "E1"
    assert hidden[0]["payload"]["_meta"]["arguments"] == {"host_id": 92}
    shown = tasks.evidence_page(task["task_id"], include_logs=True)
    assert shown[1]["payload"]["output"] == "GET /private-path"


def test_report_budget_fallback_keeps_limits_hit():
    task, _ = tasks.create({"question": "预算"})
    client = client_for("auditor")
    data = client.get("/api/v1/platform/tasks/" + task["task_id"]).json()
    assert data["budget"]["limits_hit"] == [] and data["budget"]["limits"]["calls"]
    tasks.finish(
        task["task_id"],
        {
            "answer": "完成",
            "budget": {
                "limits": {"calls": 12},
                "used": {"calls": 3, "model_ms": 1200},
                "reasons": [],
                "limits_hit": ["采集次数达到上限"],
            },
            "capabilities": {"device_type": "linux", "diagnostic_path": "zabbix+ssh"},
            "coverage": {"planned": ["history_get"], "collected": ["history_get"]},
            "facts": {"confirmed": 2, "demoted": 1, "probable": 0, "hypotheses": 1},
        },
    )
    data = client.get("/api/v1/platform/tasks/" + task["task_id"]).json()
    assert data["budget"]["limits_hit"] == ["采集次数达到上限"]
    assert data["report"]["capabilities"]["diagnostic_path"] == "zabbix+ssh"
    assert data["report"]["facts"]["confirmed"] == 2
