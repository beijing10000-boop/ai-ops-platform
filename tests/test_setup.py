from fastapi.testclient import TestClient
from app.main import app, connection
from cryptography.fernet import Fernet

def test_setup_requires_bootstrap_secret_and_closes_after_completion(monkeypatch):
    monkeypatch.setenv("ADMIN_API_TOKEN", "test-admin")
    from app import main
    monkeypatch.setattr(main, "ADMIN_TOKEN", "test-admin")
    client=TestClient(app)
    with connection() as db:
        db.execute("DELETE FROM settings WHERE key IN ('feishu_admin_open_ids','lark_app_id','lark_app_secret','web_public_host','web_protocol')")
    assert client.get("/api/v1/setup/status").json()["setup_required"] is True
    payload={"bootstrap_token":"wrong","web_protocol":"http","web_public_host":"172.20.200.93:8088",
             "lark_app_id":"cli_12345678","lark_app_secret":"testing-app-secret",
             "feishu_admin_open_ids":"ou_first_admin"}
    assert client.post("/api/v1/setup",json=payload).status_code==403
    payload["bootstrap_token"]="test-admin"
    assert client.post("/api/v1/setup",json=payload).status_code==200
    assert client.get("/api/v1/setup/status").json()["setup_required"] is False
    assert client.post("/api/v1/setup",json=payload).status_code==409
    from app.feishu_auth import _redirect_uri, _admins
    assert _redirect_uri()=="http://172.20.200.93:8088/api/v1/auth/callback"
    assert _admins()=={"ou_first_admin"}
    from app.main import read_setting
    assert read_setting("lark_app_secret")=="testing-app-secret"

def test_setup_never_overwrites_existing_admins(monkeypatch):
    from app import main
    monkeypatch.setattr(main,"ADMIN_TOKEN","test-admin")
    client=TestClient(app)
    with connection() as db:
        db.execute("DELETE FROM settings WHERE key IN ('web_public_host','feishu_admin_open_ids','lark_app_secret')")
        db.execute("INSERT INTO settings(key,value,secret) VALUES ('feishu_admin_open_ids','ou_first_admin',0)")
        from app.main import cipher
        db.execute("INSERT INTO settings(key,value,secret) VALUES ('lark_app_secret',?,1)",(cipher().encrypt(b"testing-app-secret").decode(),))
    payload={"bootstrap_token":"test-admin","web_protocol":"http",
             "web_public_host":"172.20.200.93:8088",
             "lark_app_id":"cli_12345678","lark_app_secret":"new-secret-value",
             "feishu_admin_open_ids":"ou_attacker"}
    assert client.post("/api/v1/setup",json=payload).status_code==200
    from app.main import read_setting
    assert read_setting("feishu_admin_open_ids")=="ou_first_admin"
    assert read_setting("lark_app_secret")=="testing-app-secret"
