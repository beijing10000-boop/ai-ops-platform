from fastapi.testclient import TestClient
from app.main import app, connection


def test_setup_requires_bootstrap_secret_and_closes_after_completion(monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "test-admin")
    from app import main

    monkeypatch.setattr(main, "ADMIN_TOKEN", "test-admin")
    client = TestClient(app)
    with connection() as db:
        db.execute(
            "DELETE FROM settings WHERE key IN ('feishu_admin_open_ids','lark_app_id','lark_app_secret','web_public_host','web_protocol')"
        )
    assert client.get("/api/v1/setup/status").json()["setup_required"] is True
    payload = {
        "bootstrap_token": "wrong",
        "web_protocol": "http",
        "web_public_host": "192.0.2.10:8088",
        "lark_app_id": "cli_12345678",
        "lark_app_secret": "testing-app-secret",
        "feishu_admin_open_ids": "ou_first_admin",
    }
    assert client.post("/api/v1/setup", json=payload).status_code == 403
    payload["bootstrap_token"] = "test-admin"
    assert client.post("/api/v1/setup", json=payload).status_code == 200
    assert client.get("/api/v1/setup/status").json()["setup_required"] is False
    assert client.post("/api/v1/setup", json=payload).status_code == 409
    from app.feishu_auth import _redirect_uri, _admins

    assert _redirect_uri() == "http://192.0.2.10:8088/api/v1/auth/callback"
    assert _admins() == {"ou_first_admin"}
    from app.main import read_setting

    assert read_setting("lark_app_secret") == "testing-app-secret"


def test_setup_never_overwrites_existing_admins(monkeypatch):
    from app import main

    monkeypatch.setattr(main, "ADMIN_TOKEN", "test-admin")
    client = TestClient(app)
    with connection() as db:
        db.execute(
            "DELETE FROM settings WHERE key IN ('web_public_host','feishu_admin_open_ids','lark_app_secret')"
        )
        db.execute(
            "INSERT INTO settings(key,value,secret) VALUES ('feishu_admin_open_ids','ou_first_admin',0)"
        )
        from app.main import cipher

        db.execute(
            "INSERT INTO settings(key,value,secret) VALUES ('lark_app_secret',?,1)",
            (cipher().encrypt(b"testing-app-secret").decode(),),
        )
    payload = {
        "bootstrap_token": "test-admin",
        "web_protocol": "http",
        "web_public_host": "192.0.2.10:8088",
        "lark_app_id": "cli_12345678",
        "lark_app_secret": "new-secret-value",
        "feishu_admin_open_ids": "ou_attacker",
    }
    assert client.post("/api/v1/setup", json=payload).status_code == 200
    from app.main import read_setting

    assert read_setting("feishu_admin_open_ids") == "ou_first_admin"
    assert read_setting("lark_app_secret") == "testing-app-secret"


def test_setup_restores_a_cleared_app_secret_and_keeps_valid_settings(
    monkeypatch, tmp_path
):
    from app import main
    from app.main import read_setting
    from test_platform import client_for

    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    monkeypatch.setattr(main, "ADMIN_TOKEN", "test-admin")
    with connection() as db:
        for key, value in (
            ("feishu_admin_open_ids", "ou_super"),
            ("lark_app_id", "cli_12345678"),
            ("web_public_host", "192.0.2.10:8088"),
        ):
            db.execute("INSERT OR REPLACE INTO settings VALUES (?,?,0)", (key, value))
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('lark_app_secret',?,1)",
            (main.cipher().encrypt(b"testing-app-secret").decode(),),
        )
    # An administrator clears the App Secret on the settings page: it is
    # stored as the ciphertext of "", and Feishu login stops working.
    response = client_for().put(
        "/api/v1/settings", json={"values": {"lark_app_secret": ""}}
    )
    assert response.status_code == 200
    client = TestClient(app)
    assert client.get("/api/v1/setup/status").json()["setup_required"] is True
    payload = {
        "bootstrap_token": "test-admin",
        "web_protocol": "http",
        "web_public_host": "203.0.113.9",
        "lark_app_id": "cli_87654321",
        "lark_app_secret": "restored-secret",
        "feishu_admin_open_ids": "ou_attacker",
    }
    assert client.post("/api/v1/setup", json=payload).status_code == 200
    assert read_setting("lark_app_secret") == "restored-secret"
    assert client.get("/api/v1/setup/status").json()["setup_required"] is False
    # Setup only fills what is missing; valid settings are never overwritten.
    assert read_setting("feishu_admin_open_ids") == "ou_super"
    assert read_setting("lark_app_id") == "cli_12345678"
    assert read_setting("web_public_host") == "192.0.2.10:8088"
    payload["lark_app_secret"] = "second-secret"
    assert client.post("/api/v1/setup", json=payload).status_code == 409
    assert read_setting("lark_app_secret") == "restored-secret"
