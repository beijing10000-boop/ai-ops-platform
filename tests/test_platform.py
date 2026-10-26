"""Authorization, encryption and durable task behavior using real SQLite."""

import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from app import main, feishu_auth, diagnostic_worker
from app.orchestrator import tasks


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def client_for(role="super_admin"):
    open_id = "ou_super" if role == "super_admin" else "ou_" + role
    raw = secrets.token_hex(24)
    csrf = secrets.token_hex(24)
    with main.connection() as db:
        feishu_auth._tables(db)
        if role != "super_admin":
            db.execute("INSERT OR REPLACE INTO members VALUES (?,?,1)", (open_id, role))
        db.execute(
            "INSERT INTO admin_sessions VALUES (?,?,?,?,?)",
            (feishu_auth._hash(raw), open_id, role, csrf, int(time.time()) + 3600),
        )
    return TestClient(
        main.app, headers={"x-csrf-token": csrf}, cookies={feishu_auth.COOKIE: raw}
    )


def test_roles_are_checked_on_direct_api_access():
    operator = client_for("operator")
    auditor = client_for("auditor")
    assert operator.get("/api/v1/settings").status_code == 403
    assert operator.get("/api/v1/platform/credentials").status_code == 404
    assert operator.get("/api/v1/platform/assets").status_code == 404
    assert auditor.post("/api/v1/platform/tasks", json={}).status_code == 403
    assert auditor.get("/api/v1/platform/audit").status_code == 200
    assert TestClient(main.app).get("/api/v1/platform/tasks").status_code == 401


def test_ops_admin_cannot_promote_itself_or_change_tool_authority():
    client = client_for("ops_admin")
    assert (
        client.put(
            "/api/v1/settings",
            json={"values": {"feishu_admin_open_ids": "ou_ops_admin"}},
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/v1/settings", json={"values": {"disabled_tools": "[]"}}
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/v1/platform/members", json={"open_id": "ou_self", "role": "ops_admin"}
        ).status_code
        == 403
    )


def test_csrf_is_enforced_on_new_apis():
    client = client_for()
    client.headers.pop("x-csrf-token")
    assert (
        client.post(
            "/api/v1/platform/tasks/validate", json={"profile": "quick"}
        ).status_code
        == 403
    )


def test_event_dedup_is_atomic_across_threads():
    def create(_):
        return tasks.create({"question": "CPU"}, event_id="777", diagnostic_type="cpu")

    with ThreadPoolExecutor(max_workers=5) as pool:
        result = list(pool.map(create, range(10)))
    assert sum(created for task, created in result) == 1
    assert len({task["task_id"] for task, created in result}) == 1


def test_raw_logs_require_separate_permission_and_are_encrypted():
    task, _ = tasks.create({"question": "logs"})
    tasks.evidence(
        task["task_id"],
        "linux_ssh",
        "logs",
        {"output": "bounded log content", "status": "success"},
    )
    client = client_for("auditor")
    detail = client.get("/api/v1/platform/tasks/" + task["task_id"]).json()
    assert detail["evidence"][0]["payload"]["restricted"] is True
    assert "request" not in detail
    assert (
        client.get(
            "/api/v1/platform/tasks/" + task["task_id"] + "?include_logs=true"
        ).status_code
        == 403
    )
    assert (
        client_for("ops_admin")
        .get("/api/v1/platform/tasks/" + task["task_id"] + "?include_logs=true")
        .json()["evidence"][0]["payload"]["output"]
        == "bounded log content"
    )
    with main.connection() as db:
        assert (
            "bounded log content"
            not in db.execute("SELECT payload FROM diagnostic_evidence").fetchone()[0]
        )


def test_hidden_kernel_error_retains_budget_reason_without_exposing_raw_logs():
    task, _ = tasks.create({"question": "内核"})
    tasks.evidence(
        task["task_id"],
        "ssh_mcp",
        "kernel",
        {
            "status": "failed",
            "error": "SSH MCP 诊断预算不足，停止补查",
            "output": "sensitive-kernel-content",
        },
    )
    data = client_for("auditor").get("/api/v1/platform/tasks/" + task["task_id"]).json()
    payload = data["evidence"][0]["payload"]
    assert payload["restricted"] and "采集预算不足" in payload["failure_reason"]
    assert "不代表工具调用被拒绝" in payload["message"]
    assert "sensitive-kernel-content" not in json.dumps(data)
    assert data["budget"]["limits"]["calls"] == 12


def test_qa_report_exposes_verified_host_and_original_budget_snapshot():
    task, _ = tasks.create({"question": "查看172.20.2.101的目录"}, source="qa")
    tasks.finish(
        task["task_id"],
        {
            "answer": "已采集",
            "device_type": "linux",
            "target": {"host_id": "11600", "host_name": "172.20.2.101"},
        },
    )
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES ('ai_profile_budgets',?,0)",
            ('{"standard":{"calls":24}}',),
        )
    data = client_for("auditor").get("/api/v1/platform/tasks/" + task["task_id"]).json()
    assert (
        data["alert"]["host_id"] == "11600"
        and data["alert"]["host_name"] == "172.20.2.101"
    )
    assert data["budget"]["limits"]["calls"] == 12


def test_cancellation_and_retry_create_independent_trace(monkeypatch):
    monkeypatch.setattr(tasks, "enqueue", lambda _: None)
    task, _ = tasks.create({"question": "query"})
    client = client_for("operator")
    assert (
        client.post("/api/v1/platform/tasks/" + task["task_id"] + "/cancel").status_code
        == 200
    )
    assert tasks.get(task["task_id"])["status"] == "cancelled"
    new = client.post("/api/v1/platform/tasks/" + task["task_id"] + "/retry").json()
    assert new["task_id"] != task["task_id"]
    assert tasks.get(new["task_id"])["trace_id"] != task["trace_id"]


def test_missing_model_is_recorded_as_failure_not_stuck_queued():
    task, _ = tasks.create({"question": "query"})
    with pytest.raises(RuntimeError):
        diagnostic_worker.process(task["task_id"])
    assert tasks.get(task["task_id"])["status"] == "failed"


def test_budget_validation_is_server_side():
    client = client_for()
    for raw in [
        '{"standard":{"calls":true}}',
        '{"standard":{"calls":1000}}',
        '{"unknown":{}}',
    ]:
        assert (
            client.put(
                "/api/v1/settings", json={"values": {"ai_profile_budgets": raw}}
            ).status_code
            == 422
        )
    assert (
        client.put(
            "/api/v1/settings",
            json={
                "values": {
                    "ai_profile_budgets": '{"standard":{"calls":7,"tokens":10000}}'
                }
            },
        ).status_code
        == 200
    )


def test_missing_master_key_cannot_replace_existing_ciphertext(monkeypatch):
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES ('openai_api_key',?,1)",
            (main.cipher().encrypt(b"provider-secret").decode(),),
        )
    monkeypatch.setattr(main, "MASTER_KEY", "")
    with pytest.raises(RuntimeError, match="原始主密钥"):
        main.cipher()
    assert not (main.DATA_DIR / "master.key").exists()


def test_trusted_feishu_event_lookup_requires_exact_message_and_chat():
    from app.integrations.feishu_links import remember, event_for_message

    event = {"event_id": "771", "event_value": "1", "host_id": "42"}
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_name,host_name,severity,event_json) VALUES ('771','1','cpu','server',4,?)",
            (json.dumps(event),),
        )
    remember(event, "oc_one", "om_source", "problem")
    assert event_for_message("om_source", "oc_one") == event
    assert event_for_message("om_source", "oc_two") is None
    assert event_for_message("om_other", "oc_one") is None


def test_queued_question_rechecks_revoked_permissions(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock
    from app import qa_worker

    reply = AsyncMock()
    ask = AsyncMock()
    monkeypatch.setattr(qa_worker, "reply_card", reply)
    monkeypatch.setattr(qa_worker, "ask", ask)
    monkeypatch.setattr(qa_worker, "record_ai_question", lambda *a, **k: None)
    asyncio.run(
        qa_worker.execute("oc_one", "diagnose", "om_q", sender_open_id="ou_revoked")
    )
    assert "无诊断权限" in reply.await_args.args
    ask.assert_not_awaited()


def test_imported_history_cannot_be_retried():
    old, _ = tasks.create({"legacy_id": 1}, kind="legacy")
    tasks.finish(old["task_id"], {}, status="failed")
    response = client_for().post(f"/api/v1/platform/tasks/{old['task_id']}/retry")
    assert response.status_code == 409
    assert tasks.page()["total"] == 1
