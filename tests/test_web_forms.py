"""Draft checks never mutate configuration, launch jobs, or expose secrets."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app import main
from app.integrations import ssh_mcp
from app.orchestrator import tasks
from tests.test_platform import client_for


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)")


def test_diagnostic_prompts_are_replaced_by_skill_and_legacy_values_preserved():
    client = client_for()
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('ai_alert_prompt','historical-alert-rule',0)"
        )
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('ai_qa_prompt','historical-qa-rule',0)"
        )
    settings = client.get("/api/v1/settings").json()
    options = client.get("/api/v1/settings/options").json()
    for key in ("ai_alert_prompt", "ai_qa_prompt"):
        assert key not in settings
        assert (
            client.put(
                "/api/v1/settings", json={"values": {key: "override"}}
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/v1/settings/validate", json={"values": {key: "override"}}
            ).status_code
            == 422
        )
    assert "prompts" not in options
    assert options["profiles"]["standard"]["calls"] == 12
    assert "host_get" in options["tools"]
    with main.connection() as db:
        assert (
            db.execute(
                "SELECT value FROM settings WHERE key='ai_alert_prompt'"
            ).fetchone()[0]
            == "historical-alert-rule"
        )
        assert (
            db.execute(
                "SELECT value FROM settings WHERE key='ai_qa_prompt'"
            ).fetchone()[0]
            == "historical-qa-rule"
        )


def test_draft_configuration_is_validated_without_save_and_secrets_stay_encrypted():
    client = client_for()
    values = {
        "ssh_mcp_enabled": "true",
        "ssh_mcp_url": "http://192.0.2.12:9099/mcp",
        "ssh_mcp_token": "dedicated-client-fixture-token",
        "ssh_mcp_timeout_seconds": "90",
    }
    assert client.post("/api/v1/settings/validate", json={"values": values}).json()[
        "ok"
    ]
    assert main.read_setting("ssh_mcp_url") == ""
    assert client.put("/api/v1/settings", json={"values": values}).status_code == 200
    assert client.get("/api/v1/settings").json()["ssh_mcp_token"] == "********"
    with main.connection() as db:
        raw = db.execute(
            "SELECT value,secret FROM settings WHERE key='ssh_mcp_token'"
        ).fetchone()
    assert raw[1] == 1 and values["ssh_mcp_token"] not in raw[0]
    assert (
        client.post(
            "/api/v1/settings/validate", json={"values": {"ssh_mcp_token": "********"}}
        ).status_code
        == 200
    )
    for bad in (
        {"ssh_mcp_url": "http://user:pass@host/mcp"},
        {"ssh_mcp_url": "http://host/mcp?token=abc"},
        {"ssh_mcp_timeout_seconds": "999"},
        {"web_public_host": "host:bad"},
        {"web_protocol": "file"},
    ):
        assert (
            client.post("/api/v1/settings/validate", json={"values": bad}).status_code
            == 422
        )


def test_retired_local_ssh_apis_and_input_fields_are_absent():
    client = client_for()
    for path in ("credentials", "proxies", "host-keys"):
        assert client.get("/api/v1/platform/" + path).status_code == 404
    assert client.post("/api/v1/platform/assets/1/test").status_code == 404
    assert (
        client.post(
            "/api/v1/platform/assets", json={"name": "x", "username": "root"}
        ).status_code
        == 404
    )
    with main.connection() as db:
        columns = {r[1] for r in db.execute("PRAGMA table_info(assets)")}
        tables = {
            r[0]
            for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert not {"host_key", "credential_id", "proxy_id", "username"} & columns
    assert not {"ssh_credentials", "ssh_proxies", "host_key_scans"} & tables


def test_editor_and_diagnostic_preflights_are_read_only():
    client = client_for()
    assert client.post(
        "/api/v1/platform/members/validate",
        json={"open_id": "ou_test", "role": "operator", "enabled": True},
    ).json()["ok"]
    assert client.get("/api/v1/platform/assets").status_code == 404
    assert client.post(
        "/api/v1/platform/tasks/validate", json={"profile": "quick"}
    ).json()["ok"]
    assert tasks.page()["total"] == 0
    assert (
        client.post(
            "/api/v1/alert-mutes/validate",
            json={"host_id": "10", "trigger_id": "20", "hours": 1},
        ).status_code
        == 200
    )
    assert client.get("/api/v1/alert-mutes").json() == []


def test_mute_management_lists_active_and_recent_expired_with_role_checks():
    import time

    now = int(time.time())
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_mutes(host_id,trigger_id,expires_at) VALUES (?,?,?)",
            ("11848", "21001", now + 3600),
        )
        db.execute(
            "INSERT INTO alert_mutes(host_id,trigger_id,expires_at) VALUES (?,?,?)",
            ("11848", "21002", now - 60),
        )
        db.execute(
            "INSERT INTO alert_mutes(host_id,trigger_id,expires_at) VALUES (?,?,?)",
            ("11848", "21003", now - 120),
        )
    client = client_for("ops_admin")
    active = client.get("/api/v1/alert-mutes")
    assert active.status_code == 200
    assert [(r["host_id"], r["trigger_id"]) for r in active.json()] == [
        ("11848", "21001")
    ]
    expired = client.get("/api/v1/alert-mutes?status=expired")
    assert expired.status_code == 200
    assert [r["trigger_id"] for r in expired.json()] == ["21002", "21003"]
    assert all(r["expires_at"] <= now for r in expired.json())
    assert client.get("/api/v1/alert-mutes?status=invalid").status_code == 422
    assert client_for("operator").get("/api/v1/alert-mutes").status_code == 403
    assert (
        client_for("auditor").get("/api/v1/alert-mutes?status=expired").status_code
        == 403
    )


def test_new_verification_endpoints_enforce_auth_csrf_and_roles():
    client = client_for("operator")
    assert client.post("/api/v1/test/feishu").status_code == 403
    assert (
        client.post("/api/v1/settings/validate", json={"values": {}}).status_code == 403
    )
    assert (
        client.post("/api/v1/platform/tools/discover?provider=ssh_mcp").status_code
        == 403
    )
    client = client_for()
    client.headers.pop("x-csrf-token")
    assert (
        client.post("/api/v1/settings/validate", json={"values": {}}).status_code == 403
    )


def test_binding_verification_only_resolves_host_and_does_not_create_tasks(monkeypatch):
    adapter = SimpleNamespace(
        resolve=AsyncMock(return_value=ssh_mcp.HostBinding("10", 92, 4))
    )

    class Context:
        async def __aenter__(self):
            return adapter

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(ssh_mcp, "configured", lambda *a, **k: Context())
    from app.integrations import zabbix

    monkeypatch.setattr(
        zabbix,
        "monitoring_hosts",
        AsyncMock(
            return_value=[
                {"zabbix_hostid": "10", "device_type": "linux", "name": "test"}
            ]
        ),
    )
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('ssh_mcp_enabled','true',0)")
    response = client_for().post(
        "/api/v1/platform/tasks/validate", json={"zabbix_hostid": "10"}
    )
    assert response.json()["ssh_host_id"] == 92
    adapter.resolve.assert_awaited_once_with("10")
    assert tasks.page()["total"] == 0


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {"status": "success", "zabbix_hostid": "11", "host_id": 92, "revision": 4},
        {"status": "success", "zabbix_hostid": "10", "host_id": True, "revision": 4},
    ],
)
def test_malformed_or_wrong_host_mapping_fails_closed(bad):
    session = SimpleNamespace(
        call_tool=AsyncMock(
            return_value=SimpleNamespace(
                isError=False, structuredContent=bad, content=[]
            )
        )
    )
    with pytest.raises(ssh_mcp.IntegrationError):
        asyncio.run(ssh_mcp.SSHMCPAdapter(session).resolve("10"))


def test_legacy_schema_upgrade_removes_credentials_and_preserves_reports():
    with main.connection() as db:
        aid = db.execute(
            "INSERT INTO assets(name,zabbix_hostid,device_type) VALUES ('kept','10','linux')"
        ).lastrowid
    task, _ = tasks.create({"question": "kept"}, asset_id=aid)
    tasks.finish(task["task_id"], {"answer": "original encrypted report"})
    with main.connection() as db:
        db.execute(
            "CREATE TABLE ssh_credentials(id INTEGER PRIMARY KEY,private_key TEXT)"
        )
        db.execute("INSERT INTO ssh_credentials VALUES (1,'old-encrypted-key')")
        db.execute(
            "CREATE TABLE ssh_proxies(id INTEGER PRIMARY KEY,credential_id INTEGER REFERENCES ssh_credentials(id))"
        )
        db.execute(
            "ALTER TABLE assets ADD COLUMN credential_id INTEGER REFERENCES ssh_credentials(id)"
        )
        db.execute(
            "ALTER TABLE assets ADD COLUMN proxy_id INTEGER REFERENCES ssh_proxies(id)"
        )
        db.execute("ALTER TABLE assets ADD COLUMN host_key TEXT DEFAULT ''")
        db.execute("UPDATE assets SET credential_id=1,host_key='old-key'")
        db.execute("DELETE FROM platform_migrations")
        db.executemany(
            "INSERT INTO platform_migrations(version) VALUES (?)", [(1,), (2,), (3,)]
        )
    from app.platform_db import archived_asset

    assert archived_asset(aid)["name"] == "kept"
    assert tasks.get(task["task_id"])["report"]["answer"] == "original encrypted report"
    with main.connection() as db:
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='ssh_credentials'"
            ).fetchone()
            is None
        )
        assert (
            db.execute("SELECT MAX(version) FROM platform_migrations").fetchone()[0]
            == 7
        )


def test_feishu_verification_uses_draft_credentials_and_never_sends_messages(
    monkeypatch,
):
    import httpx

    calls = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, **kwargs):
            calls.append(("POST", url, kwargs))
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"code": 0, "tenant_access_token": "tenant-fixture-secret"},
            )

        async def get(self, url, **kwargs):
            calls.append(("GET", url, kwargs))
            return httpx.Response(
                200, request=httpx.Request("GET", url), json={"code": 0}
            )

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: Client())
    values = {
        "lark_app_id": "cli_abcdefgh",
        "lark_app_secret": "draft-app-fixture-secret",
        "allowed_chat_ids": "oc_fixture",
    }
    response = client_for().post(
        "/api/v1/test/feishu?check_groups=true", json={"values": values}
    )
    assert (
        response.json()["ok"]
        and response.json()["groups"][0]["chat_id"] == "oc_fixture"
    )
    assert main.read_setting("lark_app_secret") == ""
    assert calls[0][2]["json"]["app_secret"] == values["lark_app_secret"]
    assert calls[1][0] == "GET" and "/im/v1/chats/" in calls[1][1]
    assert "tenant-fixture-secret" not in response.text
    assert "draft-app-fixture-secret" not in response.text
