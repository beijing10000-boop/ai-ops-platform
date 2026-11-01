"""Regressions for the 2026-11 settings and Web audit (OPS-WEB)."""

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import main
from app.configuration import validate_form
from app.orchestrator import tasks
from tests.test_platform import client_for


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)")


# OPS-WEB-01


def fake_model(monkeypatch):
    import openai

    contacted = []

    class Model:
        def __init__(self, api_key, base_url, **kwargs):
            contacted.append((base_url, api_key))
            self.responses = SimpleNamespace(create=self.create)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def create(self, **kwargs):
            return SimpleNamespace(output_text="AI连接成功")

    monkeypatch.setattr(openai, "AsyncOpenAI", Model)
    return contacted


@pytest.fixture
def saved_endpoints(monkeypatch):
    from app.integrations import zabbix

    reached = []

    @asynccontextmanager
    async def connect(read):
        reached.append((read("mcp_url"), read("mcp_token")))
        raise RuntimeError("fixture: no MCP server")
        yield

    monkeypatch.setattr(zabbix, "connect", connect)
    values = {
        "openai_base_url": "https://llm.example.com/v1",
        "openai_model": "fixture",
        "openai_api_key": "sk-saved-fixture",
        "mcp_url": "http://zabbix.example.com:8080/mcp",
        "mcp_token": "zbx-saved-fixture",
    }
    client = client_for()
    assert client.put("/api/v1/settings", json={"values": values}).status_code == 200
    return client, values, reached


def test_saved_secrets_never_go_to_a_draft_address(monkeypatch, saved_endpoints):
    client, saved, reached = saved_endpoints
    contacted = fake_model(monkeypatch)
    moved = {
        "openai_base_url": "https://collector.invalid/v1",
        "openai_model": "fixture",
        "openai_api_key": "********",
    }
    for draft in (moved, {k: v for k, v in moved.items() if k != "openai_api_key"}):
        response = client.post("/api/v1/test/ai", json={"values": draft})
        assert response.status_code == 422
        assert response.json()["detail"] == "修改地址后请重新填写密钥/令牌"
    path = "/api/v1/platform/tools/discover?provider=zabbix_mcp"
    draft = {"mcp_url": "http://collector.invalid/mcp", "mcp_token": "********"}
    assert client.post(path, json={"values": draft}).status_code == 422
    assert contacted == [] and reached == []
    # A secret typed again goes to the new address; the saved one to its own.
    typed = {**moved, "openai_api_key": "sk-typed-fixture"}
    assert client.post("/api/v1/test/ai", json={"values": typed}).json()["ok"]
    same = {
        **saved,
        "openai_api_key": "********",
        "openai_base_url": saved["openai_base_url"] + "/",
    }
    assert client.post("/api/v1/test/ai", json={"values": same}).json()["ok"]
    assert contacted == [
        ("https://collector.invalid/v1", "sk-typed-fixture"),
        ("https://llm.example.com/v1/", "sk-saved-fixture"),
    ]
    assert not client.post(path, json={"values": {**draft, "mcp_token": "t"}}).json()[
        "ok"
    ]
    assert reached == [("http://collector.invalid/mcp", "t")]


def test_connection_tests_are_audited_with_the_target_host(
    monkeypatch, saved_endpoints
):
    import httpx

    client, _, _ = saved_endpoints
    fake_model(monkeypatch)

    class Feishu:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, **kwargs):
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"code": 0, "tenant_access_token": "tenant-fixture"},
            )

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: Feishu())
    assert client.post("/api/v1/test/ai").json()["ok"]
    assert client.post(
        "/api/v1/test/feishu",
        json={"values": {"lark_app_id": "cli_abcdefgh", "lark_app_secret": "x" * 12}},
    ).json()["ok"]
    client.post("/api/v1/platform/tools/discover?provider=zabbix_mcp")
    with main.connection() as db:
        rows = db.execute(
            "SELECT action,key,actor FROM audit WHERE action IN "
            "('ai_model_test','feishu_connection_test','mcp_connection_test')"
        ).fetchall()
    assert sorted(rows) == [
        ("ai_model_test", "llm.example.com", "ou_super"),
        ("feishu_connection_test", "cli_abcdefgh", "ou_super"),
        ("mcp_connection_test", "zabbix_mcp zabbix.example.com:8080", "ou_super"),
    ]


def test_saving_a_new_address_with_the_masked_secret_still_works(saved_endpoints):
    # Saving is audited as settings_update and was kept compatible on purpose.
    client, _, _ = saved_endpoints
    values = {"mcp_url": "http://zabbix2.example.com/mcp", "mcp_token": "********"}
    assert client.put("/api/v1/settings", json={"values": values}).status_code == 200
    assert main.read_setting("mcp_token") == "zbx-saved-fixture"


# OPS-WEB-02


def test_web_question_is_audited_and_owned_by_the_asker(monkeypatch):
    from app import ai_agent

    task, _ = tasks.create({"question": "CPU"}, source="qa")

    async def ask(question, return_usage=False):
        return "CPU 正常", {"available": False, "task_id": task["task_id"]}

    monkeypatch.setattr(ai_agent, "ask", ask)
    response = client_for("operator").post("/api/v1/ask", json={"question": "CPU"})
    assert response.json() == {"ok": True, "answer": "CPU 正常"}
    assert tasks.get(task["task_id"])["actor"] == "ou_operator"
    with main.connection() as db:
        rows = db.execute(
            "SELECT actor FROM audit WHERE action='web_question'"
        ).fetchall()
    assert rows == [("ou_operator",)]


# OPS-WEB-04


def test_webhook_answers_401_for_non_ascii_secrets_or_headers():
    client = TestClient(main.app)
    body = {"event_id": "998001", "severity": "4"}

    def save(secret):
        with main.connection() as db:
            db.execute(
                "INSERT OR REPLACE INTO settings VALUES ('zabbix_webhook_secret',?,1)",
                (main.cipher().encrypt(secret.encode()).decode(),),
            )

    save("ascii-webhook-fixture")
    header = {"authorization": "Bearer é".encode("latin-1")}
    assert client.post("/zabbix", json=body, headers=header).status_code == 401
    save("中文-webhook-fixture")
    header = {"authorization": "Bearer ascii-webhook-fixture"}
    assert client.post("/zabbix", json=body, headers=header).status_code == 401
    # Such secrets are refused when saved.
    for key in ("zabbix_webhook_secret", "openai_api_key"):
        for bad in ("中文密钥-fixture", "with space-fixture"):
            with pytest.raises(HTTPException):
                validate_form({key: bad}, lambda name: "")
    assert (
        client_for()
        .put("/api/v1/settings", json={"values": {"zabbix_webhook_secret": "密钥"}})
        .status_code
        == 422
    )
    assert validate_form(
        {"zabbix_webhook_secret": "********", "openai_api_key": ""}, lambda name: ""
    )["ok"]


# OPS-WEB-05


def test_setup_repair_keeps_the_protocol_and_reports_the_saved_callback(
    monkeypatch,
):
    monkeypatch.setattr(main, "ADMIN_TOKEN", "test-admin")
    with main.connection() as db:
        for key, value in (
            ("lark_app_id", "cli_12345678"),
            ("web_public_host", "ops.example.com"),
            ("web_protocol", "https"),
        ):
            db.execute("INSERT INTO settings VALUES (?,?,0)", (key, value))
    client = TestClient(main.app)
    payload = {
        "bootstrap_token": "test-admin",
        "web_protocol": "http",
        "web_public_host": "203.0.113.9",
        "lark_app_id": "cli_87654321",
        "lark_app_secret": "restored-secret",
        "feishu_admin_open_ids": "ou_other",
    }
    callback = "https://ops.example.com/api/v1/auth/callback"
    assert (
        client.post("/api/v1/setup/validate", json=payload).json()["callback_url"]
        == callback
    )
    assert client.post("/api/v1/setup", json=payload).json()["callback_url"] == callback
    assert main.read_setting("web_protocol") == "https"
    from app.feishu_auth import _redirect_uri

    assert _redirect_uri() == callback


def test_fresh_setup_saves_the_submitted_protocol(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_TOKEN", "test-admin")
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('web_protocol','http',0)")
    payload = {
        "bootstrap_token": "test-admin",
        "web_protocol": "https",
        "web_public_host": "ops.example.com:8443/",
        "lark_app_id": "cli_12345678",
        "lark_app_secret": "first-secret",
        "feishu_admin_open_ids": "ou_super",
    }
    result = TestClient(main.app).post("/api/v1/setup", json=payload).json()
    assert result["callback_url"] == "https://ops.example.com:8443/api/v1/auth/callback"
    assert main.read_setting("web_protocol") == "https"
