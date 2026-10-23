"""Web-configured Feishu admin allowlist is shared across web login and card actions."""
from app import feishu_auth, alert_actions, alert_mute
from app.main import connection, read_setting

def test_admin_open_ids_read_database_only(monkeypatch):
    monkeypatch.setenv("FEISHU_ADMIN_OPEN_IDS", "ou_bootstrap")
    with connection() as db:
        db.execute("DELETE FROM settings WHERE key='feishu_admin_open_ids'")
    assert "ou_bootstrap" not in feishu_auth._admins()
    with connection() as db:
        db.execute("INSERT INTO settings(key,value,secret) VALUES ('feishu_admin_open_ids','ou_webadmin',0)")
    assert feishu_auth._admins() == {"ou_webadmin"}
    assert alert_actions._authorized("ou_webadmin")
    assert not alert_actions._authorized("ou_bootstrap")
    assert not alert_mute.handle_mute_action({"op":"mute_alert"},"ou_bootstrap")[0]
    with connection() as db:
        db.execute("DELETE FROM settings WHERE key='feishu_admin_open_ids'")

def test_admin_open_ids_can_be_saved_through_web_api(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setenv("ALLOW_LEGACY_ADMIN_TOKEN", "true")
    monkeypatch.setenv("ADMIN_API_TOKEN", "test-admin")
    client=TestClient(app)
    h={"Authorization":"Bearer test-admin"}
    response=client.put("/api/v1/settings", headers=h, json={"values":{"feishu_admin_open_ids":"ou_example_123,ou_example_456"}})
    assert response.status_code == 200
    assert client.get("/api/v1/settings",headers=h).json()["feishu_admin_open_ids"]=="ou_example_123,ou_example_456"
    assert client.put("/api/v1/settings",headers=h,json={"values":{"feishu_admin_open_ids":"admin"}}).status_code==422
    with connection() as db:
        db.execute("DELETE FROM settings WHERE key='feishu_admin_open_ids'")
