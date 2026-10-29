"""No local host catalog: query and validate the exact Zabbix Host ID on demand."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from app import main
from app.integrations import zabbix
from app.orchestrator import tasks
from tests.test_platform import client_for


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)")


@pytest.fixture
def remote(monkeypatch):
    async def hosts(read, query="", host_id=None):
        if host_id and host_id not in {"10", "11"}:
            raise ValueError("主机不存在或不在读取范围内")
        return [
            {
                "zabbix_hostid": host_id or "10",
                "name": "监控主机",
                "device_type": "linux" if host_id != "11" else "network",
                "monitored": True,
            }
        ]

    mock = AsyncMock(side_effect=hosts)
    monkeypatch.setattr(zabbix, "monitoring_hosts", mock)
    return mock


def test_no_asset_crud_groups_import_or_sync_endpoints():
    client = client_for()
    for path in ("assets", "groups", "assets-import", "assets-sync", "validate"):
        assert client.get("/api/v1/platform/" + path).status_code == 404
        assert client.post("/api/v1/platform/" + path, json={}).status_code == 404
    for method in (client.put, client.delete):
        assert method("/api/v1/platform/assets/1").status_code == 404
    assert client.post("/api/v1/platform/assets/1/validate").status_code == 404


def test_host_lookup_requires_auth_and_diagnostic_role(remote):
    assert TestClient(main.app).get("/api/v1/platform/hosts").status_code == 401
    assert client_for("auditor").get("/api/v1/platform/hosts").status_code == 403
    assert (
        client_for("operator")
        .get("/api/v1/platform/hosts?q=node")
        .json()["items"][0]["zabbix_hostid"]
        == "10"
    )
    assert remote.await_args.args[1] == "node"


def test_manual_diagnosis_binds_remote_host_without_writing_assets(remote, monkeypatch):
    monkeypatch.setattr(tasks, "enqueue", lambda _: None)
    response = client_for().post(
        "/api/v1/platform/tasks",
        json={"zabbix_hostid": "10", "question": "CPU usage high", "profile": "quick"},
    )
    assert response.status_code == 202
    task = tasks.get(response.json()["task_id"], private=True)
    assert task["asset_id"] is None and task["request"]["event"]["host_id"] == "10"
    with main.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


def test_malformed_host_ids_and_old_asset_fields_are_rejected(remote):
    # Which sources to query is the Skill's job; submission only validates input.
    client = client_for()
    for bad in (
        {"asset_id": 1},
        {"zabbix_hostid": "10;id"},
        {"zabbix_hostid": "198.51.100.1"},
        {"address": "10.0.0.1"},
        {"device_type": "linux"},
    ):
        assert client.post("/api/v1/platform/tasks", json=bad).status_code == 422
    assert tasks.page()["total"] == 0


def test_selected_host_must_match_stored_alert(remote, monkeypatch):
    monkeypatch.setattr(tasks, "enqueue", lambda _: None)
    event = {
        "event_id": "500",
        "event_value": "1",
        "host_id": "10",
        "event_name": "CPU high",
    }
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_json) VALUES ('500','1',?)",
            (json.dumps(event),),
        )
    client = client_for()
    assert (
        client.post(
            "/api/v1/platform/tasks", json={"event_id": "500", "zabbix_hostid": "11"}
        ).status_code
        == 422
    )
    response = client.post("/api/v1/platform/tasks", json={"event_id": "500"})
    assert response.status_code == 202
    assert (
        tasks.get(response.json()["task_id"], private=True)["request"]["event"][
            "host_id"
        ]
        == "10"
    )


def test_network_and_quick_preflight_do_not_open_ssh(remote, monkeypatch):
    from app.integrations import ssh_mcp

    mock = AsyncMock(side_effect=AssertionError("must not open SSH"))
    monkeypatch.setattr(ssh_mcp, "configured", mock)
    client = client_for()
    assert client.post(
        "/api/v1/platform/tasks/validate", json={"zabbix_hostid": "11"}
    ).json()["ok"]
    assert client.post(
        "/api/v1/platform/tasks/validate",
        json={"zabbix_hostid": "10", "profile": "quick"},
    ).json()["ok"]
    mock.assert_not_called()
    assert tasks.page()["total"] == 0


def test_direct_mcp_host_query_is_bounded_scoped_and_does_not_return_extra_fields(
    monkeypatch,
):
    calls = []

    class Context:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(zabbix, "connect", lambda read: Context())
    # Discovery is required by production to honor the actual MCP tool schema.
    monkeypatch.setattr(
        zabbix,
        "discover",
        AsyncMock(
            return_value=[
                SimpleNamespace(
                    name="host_get",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                )
            ]
        ),
    )

    async def call(session, name, args, **kwargs):
        calls.append((name, args))
        return SimpleNamespace(
            isError=False,
            content=[
                SimpleNamespace(
                    text=json.dumps(
                        [
                            {
                                "hostid": "10",
                                "name": "node",
                                "password": "never-show",
                                "inventory": {"os": "Linux"},
                            }
                        ]
                    )
                )
            ],
        )

    monkeypatch.setattr(zabbix, "call", call)
    rows = asyncio.run(zabbix.monitoring_hosts(lambda _: "", host_id="10"))
    assert rows[0]["device_type"] == "linux" and "never-show" not in json.dumps(rows)
    assert calls[0][1]["hostids"] == ["10"] and calls[0][1]["limit"] == 100
    with pytest.raises(ValueError, match="不匹配"):
        asyncio.run(zabbix.monitoring_hosts(lambda _: "", host_id="11"))


@pytest.mark.parametrize(
    "host,expected",
    [
        (
            {
                "hostid": "11848",
                "inventory": {},
                "hostgroups": [
                    {"groupid": "1", "name": "Discovered hosts"},
                    {"groupid": "2", "name": "Linux servers"},
                ],
            },
            "linux",
        ),
        (
            {"hostid": "11848", "hostgroups": [{"name": "Windows servers"}]},
            "windows",
        ),
        (
            {"hostid": "11848", "groups": [{"name": "Linux servers"}]},
            "linux",
        ),
        (
            {
                "hostid": "11848",
                "tags": [{"tag": "aiops.device_type", "value": "unknown"}],
                "hostgroups": [{"name": "Linux"}],
            },
            "linux",
        ),
        (
            {"hostid": "11848", "hostgroups": [{"name": "Not Linux servers"}]},
            "unknown",
        ),
        (
            {
                "hostid": "11848",
                "hostgroups": [{"name": "Linux servers"}, {"name": "Windows servers"}],
            },
            "unknown",
        ),
        (
            {
                "hostid": "11848",
                "tags": [{"tag": "aiops.device_type", "value": "network"}],
                "inventory": {"os": "Linux Rocky"},
                "hostgroups": [{"name": "Linux servers"}],
            },
            "network",
        ),
        (
            {"hostid": "11848", "inventory": {"os": "Rocky Linux 9.7"}},
            "linux",
        ),
        (
            {"hostid": "11848", "hostgroups": [{"name": "Discovered hosts"}]},
            "unknown",
        ),
    ],
)
def test_device_type_detected_from_verified_zabbix_metadata(host, expected):
    assert zabbix.infer_device(host) == expected


def test_monitoring_host_query_requests_authoritative_groups(monkeypatch):
    calls = []

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(zabbix, "connect", lambda read: Session())
    monkeypatch.setattr(
        zabbix,
        "discover",
        AsyncMock(
            return_value=[
                SimpleNamespace(
                    name="host_get",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        ),
    )

    async def fake_call(session, name, args, **kwargs):
        calls.append(args)
        return SimpleNamespace(
            isError=False,
            content=[
                SimpleNamespace(
                    text=json.dumps(
                        [
                            {
                                "hostid": "11848",
                                "name": "192-0-2-10",
                                "inventory": {},
                                "hostgroups": [
                                    {"groupid": "2", "name": "Linux servers"}
                                ],
                            }
                        ]
                    )
                )
            ],
        )

    monkeypatch.setattr(zabbix, "call", fake_call)
    rows = asyncio.run(zabbix.monitoring_hosts(lambda _: "", host_id="11848"))
    assert rows[0]["device_type"] == "linux"
    assert calls[0]["hostids"] == ["11848"]
    assert calls[0]["selectHostGroups"] == ["groupid", "name"]


@pytest.mark.parametrize("count", [2, 150])
def test_monitoring_query_rejects_duplicates_for_exact_host_and_caps_lists(
    monkeypatch, count
):
    class Context:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(zabbix, "connect", lambda read: Context())
    # Discovery is required by production to honor the actual MCP tool schema.
    monkeypatch.setattr(
        zabbix,
        "discover",
        AsyncMock(
            return_value=[
                SimpleNamespace(
                    name="host_get",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                )
            ]
        ),
    )

    async def call(*args, **kwargs):
        rows = [
            {"hostid": "10" if count == 2 else str(10 + i), "name": "node"}
            for i in range(count)
        ]
        return SimpleNamespace(
            isError=False, content=[SimpleNamespace(text=json.dumps(rows))]
        )

    monkeypatch.setattr(zabbix, "call", call)
    if count == 2:
        with pytest.raises(ValueError, match="重复"):
            asyncio.run(zabbix.monitoring_hosts(lambda _: "", host_id="10"))
    else:
        assert len(asyncio.run(zabbix.monitoring_hosts(lambda _: ""))) == 100
