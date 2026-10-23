import os
from app.alert_mute import action_signature, handle_mute_action

def test_signed_callback_admin_only(monkeypatch):
    monkeypatch.setenv("FEISHU_ADMIN_OPEN_IDS","ou_admin")
    monkeypatch.setenv("APP_ENCRYPTION_KEY","unit-test-secret")
    data={"op":"mute_alert","host_id":"123","trigger_id":"456","hours":4}
    data["sig"]=action_signature("123","456",4)
    assert handle_mute_action(data,"ou_other")[0] is False
    assert handle_mute_action({**data,"hours":168},"ou_admin")[0] is False
    ok,msg=handle_mute_action(data,"ou_admin")
    assert ok and "4 小时" in msg
    from app.main import connection
    with connection() as db:
        assert db.execute("SELECT expires_at FROM alert_mutes WHERE host_id='123' AND trigger_id='456'").fetchone() is not None

def test_unlisted_duration_rejected(monkeypatch):
    monkeypatch.setenv("FEISHU_ADMIN_OPEN_IDS","ou_admin")
    monkeypatch.setenv("APP_ENCRYPTION_KEY","unit-test-secret")
    data={"op":"mute_alert","host_id":"123","trigger_id":"456","hours":2}
    data["sig"]=action_signature("123","456",2)
    assert handle_mute_action(data,"ou_admin")[0] is False
