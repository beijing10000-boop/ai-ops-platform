from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)

def test_health():
    assert client.get("/healthz").json()["ok"] is True

def test_no_admin_access():
    assert client.get("/api/v1/settings").status_code == 401

def test_secret_masking():
    h={"Authorization":"Bearer test-admin"}
    assert client.put("/api/v1/settings",headers=h,json={"values":{"openai_api_key":"test-secret"}}).status_code == 200
    assert client.get("/api/v1/settings",headers=h).json()["openai_api_key"] == "********"

def test_webhook_unauthorized():
    payload={"event_id":"123"}
    assert client.post("/zabbix",json=payload).status_code == 401

def test_runtime_status_requires_admin():
    assert client.get("/api/v1/status").status_code == 401
    result = client.get("/api/v1/status", headers={"Authorization": "Bearer test-admin"})
    assert result.status_code == 200
    assert "queues" in result.json()

def test_mcp_test_requires_admin():
    assert client.post("/api/v1/test/mcp").status_code == 401

def test_ai_and_ask_require_admin():
    assert client.post("/api/v1/test/ai").status_code == 401
    assert client.post("/api/v1/ask", json={"question":"测试"}).status_code == 401

def test_ask_validation():
    h={"Authorization":"Bearer test-admin"}
    assert client.post("/api/v1/ask", headers=h, json={"question":""}).status_code == 422
    assert client.post("/api/v1/ask", headers=h, json={"question":"x"*3001}).status_code == 422

def test_web_ask_calls_read_only_agent(monkeypatch):
    from app import ai_agent
    async def fake_ask(question, return_usage=False):
        assert question == "查询严重告警"
        return ("已从 MCP 查询", {"available":True,"input":8,"output":2,"total":10}) if return_usage else "已从 MCP 查询"
    monkeypatch.setattr(ai_agent, "ask", fake_ask)
    response=client.post("/api/v1/ask",
        headers={"Authorization":"Bearer test-admin"},
        json={"question":"查询严重告警"})
    assert response.status_code == 200
    assert response.json() == {"ok":True,"answer":"已从 MCP 查询"}

def test_ai_model_requires_configuration(monkeypatch):
    from app import main
    monkeypatch.setattr(main, "read_setting", lambda key: "")
    response=client.post("/api/v1/test/ai",
        headers={"Authorization":"Bearer test-admin"})
    assert response.status_code == 422

def test_write_endpoints_removed():
    h={"Authorization":"Bearer test-admin"}
    assert client.post("/api/v1/write/enable",headers=h).status_code == 404
    assert client.post("/api/v1/write/disable",headers=h).status_code == 404
    assert client.put("/api/v1/settings",headers=h,json={"values":{"write_mcp_token":"unused"}}).status_code == 422

def test_admin_timed_mute():
    h={"Authorization":"Bearer test-admin"}
    assert client.post("/api/v1/alert-mutes",json={"host_id":"101","trigger_id":"202","hours":1}).status_code == 401
    r=client.post("/api/v1/alert-mutes",headers=h,json={"host_id":"101","trigger_id":"202","hours":1})
    assert r.status_code == 200
    found=client.get("/api/v1/alert-mutes",headers=h)
    assert any(x["host_id"]=="101" and x["trigger_id"]=="202" for x in found.json())
    assert client.post("/api/v1/alert-mutes",headers=h,json={"host_id":"101","trigger_id":"202","hours":500}).status_code == 422
    assert client.delete("/api/v1/alert-mutes/101/202",headers=h).status_code == 200
    assert not any(x["host_id"]=="101" and x["trigger_id"]=="202" for x in client.get("/api/v1/alert-mutes",headers=h).json())

def test_beijing_time_handles_sqlite_utc():
    from app.main import beijing_time
    assert beijing_time("2026-10-19 10:42:16") == "2026-10-19 18:42:16"
    assert beijing_time("2026-10-19T10:42:16Z") == "2026-10-19 18:42:16"
    assert beijing_time(None) is None

def test_ai_question_metrics_separate_from_alerts():
    from app.main import record_ai_question
    rid = "test-question-metric-001"
    record_ai_question("feishu", rid, "查询 CPU 使用率", "running")
    record_ai_question("feishu", rid, "查询 CPU 使用率", "success")
    h = {"Authorization":"Bearer test-admin"}
    stats = client.get("/api/v1/qa-stats",headers=h)
    assert stats.status_code == 200
    assert stats.json()["success"] >= 1
    rows = client.get("/api/v1/qa-events",headers=h)
    assert rows.status_code == 200
    found = [x for x in rows.json() if x["request_id"] == rid]
    assert len(found) == 1 and found[0]["status"] == "success"
    assert found[0]["source"] == "feishu"
    assert client.get("/api/v1/qa-events").status_code == 401

def test_deprecated_settings_are_rejected_and_hidden():
    from app.main import ALLOWED, DEFAULTS
    assert "min_severity" not in ALLOWED
    assert "ai_prompt" not in ALLOWED
    assert "min_severity" not in DEFAULTS
    h={"Authorization":"Bearer test-admin"}
    assert client.put("/api/v1/settings",headers=h,json={
        "values":{"min_severity":"3"}}).status_code==422
    assert client.put("/api/v1/settings",headers=h,json={
        "values":{"ai_prompt":"old"}}).status_code==422
    result=client.get("/api/v1/settings",headers=h).json()
    assert "min_severity" not in result
    assert "ai_prompt" not in result
    assert "ai_min_severity" in result
    assert "ai_alert_prompt" in result and "ai_qa_prompt" in result

def test_mcp_tool_loading_setting_allowed_and_validated():
    from app.main import ALLOWED, DEFAULTS
    assert "ai_tool_loading" in ALLOWED
    assert DEFAULTS["ai_tool_loading"] == "dynamic"
    h = {"Authorization": "Bearer test-admin"}
    assert client.put("/api/v1/settings", headers=h, json={"values":{"ai_tool_loading":"full"}}).status_code == 200
    assert client.get("/api/v1/settings", headers=h).json()["ai_tool_loading"] == "full"
    assert client.put("/api/v1/settings", headers=h, json={"values":{"ai_tool_loading":"invalid"}}).status_code == 422
    assert client.put("/api/v1/settings", headers=h, json={"values":{"ai_tool_loading":"dynamic"}}).status_code == 200
