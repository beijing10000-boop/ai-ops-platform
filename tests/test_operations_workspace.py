"""Operations filtering, progress polling, and recoverable failure behavior."""

import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from app import main, diagnostic_worker
from app.orchestrator import tasks
from tests.test_platform import client_for


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)")


def seed_alerts():
    with main.connection() as db:
        for i in range(57):
            db.execute(
                "INSERT INTO alert_events(event_id,event_value,event_name,host_name,severity,event_json) VALUES (?,'1',?,?,?,?)",
                (
                    str(100 + i),
                    "CPU 90%_used" if i == 0 else "CPU high",
                    "node-" + str(i),
                    i % 6,
                    json.dumps({"private": "not for list"}),
                ),
            )
        for i in range(3):
            db.execute(
                "INSERT INTO alert_events(event_id,event_value) VALUES (?,'0')",
                (str(100 + i),),
            )


def test_alerts_recovery_filters_pagination_and_exact_search():
    seed_alerts()
    client = client_for("auditor")
    path = "/api/v1/platform/alerts"
    assert TestClient(main.app).get(path).status_code == 401
    assert client.get(path).json()["total"] == 57
    active = client.get(path + "?status=active").json()
    assert active["total"] == 54 and len(active["items"]) == 25
    recovered = client.get(path + "?status=recovered").json()
    assert recovered["total"] == 3 and all(
        row["recovered_at"] for row in recovered["items"]
    )
    assert client.get(path + "?status=recovered&severity=1").json()["total"] == 1
    literal = client.get(path, params={"q": "%_"}).json()
    assert literal["total"] == 1 and literal["items"][0]["event_id"] == "100"
    assert "event_json" not in literal["items"][0]
    assert client.get(path, params={"q": "' OR 1=1 --"}).json()["total"] == 0
    first = {row["event_id"] for row in active["items"]}
    second = client.get(path + "?status=active&page=2").json()["items"]
    assert not first & {row["event_id"] for row in second}
    for query in ("severity=6", "status=unknown", "page=0", "page_size=101"):
        assert client.get(path + "?" + query).status_code == 422


def test_latest_analysis_link_and_history_search():
    seed_alerts()
    old, _ = tasks.create({}, event_id="100")
    tasks.finish(old["task_id"], {}, status="failed")
    latest, _ = tasks.create({}, event_id="100")
    client = client_for()
    assert (
        client.get("/api/v1/platform/alerts?q=90").json()["items"][0]["task_id"]
        == latest["task_id"]
    )
    assert client.get("/api/v1/platform/tasks?q=100").json()["total"] == 2
    rows = client.get(
        "/api/v1/platform/tasks", params={"q": latest["trace_id"]}
    ).json()["items"]
    assert len(rows) == 1 and rows[0]["task_id"] == latest["task_id"]
    assert client.get("/api/v1/platform/tasks?q=%25").json()["total"] == 0
    assert client.get("/api/v1/platform/tasks?status=invalid").status_code == 422


def test_polling_is_bounded_without_report_log_disclosure_or_audit_spam():
    task, _ = tasks.create({"question": "private request"})
    tasks.start(task["task_id"])
    tasks.evidence(task["task_id"], "ssh_mcp", "logs", {"output": "private log"})
    client = client_for("auditor")
    path = f"/api/v1/platform/tasks/{task['task_id']}/status"
    for _ in range(4):
        response = client.get(path)
        assert response.json()["status"] == "running"
        assert not {"evidence", "report", "request"} & response.json().keys()
    with main.connection() as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='report_read'"
            ).fetchone()[0]
            == 0
        )
        db.execute(
            "UPDATE diagnostic_tasks SET started_at=datetime('now','-11 minutes')"
        )
    assert client.get(path).json()["error_type"] == "WorkerLost"
    assert tasks.get(task["task_id"])["status"] == "failed"
    assert TestClient(main.app).get(path).status_code == 401


def test_queue_failure_returns_saved_task_and_can_be_retried(monkeypatch):
    import redis

    def unavailable(*args, **kwargs):
        raise ConnectionError("secret connection detail")

    monkeypatch.setattr(redis.Redis, "from_url", unavailable)
    client = client_for()
    response = client.post("/api/v1/platform/tasks", json={"profile": "quick"})
    assert response.status_code == 503 and "secret" not in response.text
    task_id = response.json()["detail"]["task_id"]
    assert tasks.get(task_id)["error_type"] == "QueueUnavailable"
    monkeypatch.setattr(tasks, "enqueue", lambda task_id: None)
    retry = client.post(f"/api/v1/platform/tasks/{task_id}/retry")
    assert retry.status_code == 202 and retry.json()["task_id"] != task_id


def test_configured_profile_is_used_without_exposing_settings(monkeypatch):
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('ai_analysis_profile','quick',0)")
    client = client_for("operator")
    assert client.get("/api/v1/settings").status_code == 403
    assert client.get("/api/v1/platform/diagnostic-options").json() == {
        "default_profile": "quick"
    }
    monkeypatch.setattr(tasks, "enqueue", lambda task_id: None)
    result = client.post("/api/v1/platform/tasks", json={}).json()
    assert tasks.get(result["task_id"])["profile"] == "quick"


@pytest.mark.parametrize(
    "event_id,prompt", [("100", "alert-custom"), (None, "qa-custom")]
)
def test_web_alert_diagnosis_uses_alert_prompt(monkeypatch, event_id, prompt):
    from app import mcp_runtime

    with main.connection() as db:
        db.executemany(
            "INSERT INTO settings VALUES (?,?,0)",
            [("ai_alert_prompt", "alert-custom"), ("ai_qa_prompt", "qa-custom")],
        )
    task, _ = tasks.create({"question": "CPU", "event": {}}, event_id=event_id)
    run = AsyncMock(return_value="answer")
    monkeypatch.setattr(mcp_runtime, "run", run)
    diagnostic_worker.process(task["task_id"])
    assert run.await_args.args[0] == prompt


def test_saving_unchanged_settings_keeps_last_connection_check():
    client = client_for()
    values = {"mcp_url": "http://fixture/mcp", "mcp_token": "fixture-secret"}
    client.put("/api/v1/settings", json={"values": values})
    with main.connection() as db:
        db.execute(
            "INSERT INTO integration_health(provider,status,detail) VALUES ('zabbix_mcp','success','ok')"
        )
    values["mcp_token"] = "********"
    assert (
        client.put("/api/v1/settings", json={"values": values}).json()["changed"] == []
    )
    assert (
        client.get("/api/v1/platform/overview").json()["health"][0]["status"]
        == "success"
    )
    values["mcp_url"] = "http://fixture-new/mcp"
    client.put("/api/v1/settings", json={"values": values})
    assert client.get("/api/v1/platform/overview").json()["health"] == []
    assert client.get("/api/v1/settings").json()["mcp_token"] == "********"
