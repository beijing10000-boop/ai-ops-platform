"""Authorization, inventory, encryption and durable task behavior using real SQLite."""

import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import paramiko
import pytest
from fastapi.testclient import TestClient
from app import main, feishu_auth, inventory, diagnostic_worker
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
    assert operator.get("/api/v1/platform/credentials").status_code == 403
    assert operator.get("/api/v1/platform/assets").status_code == 200
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
            "/api/v1/platform/assets", json={"name": "linux", "device_type": "linux"}
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "body",
    [
        {"name": "bad", "address": "127.0.0.1"},
        {"name": "bad", "address": "8.8.8.8"},
        {"name": "bad", "address": "example.org"},
        {"name": "bad", "device_type": "linux", "username": "root"},
        {
            "name": "bad",
            "device_type": "linux",
            "username": "root",
            "diagnostic_mode": "privileged",
        },
        {"name": "bad", "device_type": "windows", "host_key": "invalid"},
        {"name": "bad", "device_type": "network", "proxy_id": 1},
        {"name": "bad", "device_type": "windows", "diagnostic_paths": ["/data"]},
        {"name": "bad", "device_type": "linux", "address": "172.20.1.1;id"},
    ],
)
def test_unsafe_asset_configuration_rejected(body):
    assert client_for().post("/api/v1/platform/assets", json=body).status_code == 422


def test_batch_is_atomic_and_pagination_handles_1000_assets():
    client = client_for()
    body = {
        "assets": [
            {
                "name": "node-" + str(i),
                "zabbix_hostid": str(10000 + i),
                "device_type": "linux",
                "address": "172.20.1.10",
            }
            for i in range(1000)
        ]
    }
    response = client.post("/api/v1/platform/assets-import", json=body)
    assert response.status_code == 200 and response.json()["count"] == 1000
    page = client.get("/api/v1/platform/assets?page=10&page_size=100").json()
    assert page["total"] == 1000 and len(page["items"]) == 100
    assert len({r["zabbix_hostid"] for r in page["items"]}) == 100
    assert (
        client.post(
            "/api/v1/platform/assets-import",
            json={"assets": [{"name": "would roll back"}, body["assets"][0]]},
        ).status_code
        == 409
    )
    assert client.get("/api/v1/platform/assets").json()["total"] == 1000
    assert client.get("/api/v1/platform/assets?page_size=1001").status_code == 422


def test_credentials_are_encrypted_and_rotation_invalidates_verification():
    import io

    key = paramiko.RSAKey.generate(2048)
    text = io.StringIO()
    key.write_private_key(text)
    client = client_for()
    data = client.post(
        "/api/v1/platform/credentials",
        json={"name": "dedicated", "private_key": text.getvalue(), "passphrase": ""},
    ).json()
    cid = data["id"]
    with main.connection() as db:
        row = db.execute(
            "SELECT private_key FROM ssh_credentials WHERE id=?", (cid,)
        ).fetchone()
        assert row[0] != text.getvalue()
        assert main.cipher().decrypt(row[0].encode()).decode() == text.getvalue()
    assets = client.post(
        "/api/v1/platform/assets",
        json={"name": "registered", "device_type": "linux", "credential_id": cid},
    ).json()
    with main.connection() as db:
        db.execute(
            "UPDATE assets SET last_test_status='success' WHERE id=?", (assets["id"],)
        )
    response = client.put(
        "/api/v1/platform/credentials/" + str(cid),
        json={"name": "dedicated", "private_key": text.getvalue(), "passphrase": ""},
    )
    assert response.status_code == 200
    assert inventory.get_asset(assets["id"])["last_test_status"] is None
    assert inventory.get_asset(assets["id"])["revision"] == 2
    public = client.get("/api/v1/platform/credentials").json()[0]
    assert (
        "private_key" not in public
        and "passphrase" not in public
        and public["revision"] == 2
    )


def test_exact_host_id_binding_and_non_linux_guard(monkeypatch):
    client = client_for()
    monkeypatch.setattr(tasks, "enqueue", lambda _: None)
    linux = client.post(
        "/api/v1/platform/assets",
        json={"name": "same-name", "device_type": "linux", "zabbix_hostid": "100"},
    ).json()
    windows = client.post(
        "/api/v1/platform/assets",
        json={"name": "same-name", "device_type": "windows", "zabbix_hostid": "101"},
    ).json()
    event = {
        "event_id": "500",
        "event_value": "1",
        "host_id": "100",
        "event_name": "CPU high",
    }
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_json) VALUES ('500','1',?)",
            (json.dumps(event),),
        )
    assert (
        client.post(
            "/api/v1/platform/tasks",
            json={"asset_id": windows["id"], "event_id": "500"},
        ).status_code
        == 422
    )
    accepted = client.post("/api/v1/platform/tasks", json={"event_id": "500"}).json()
    task = tasks.get(accepted["task_id"])
    assert task["asset_id"] == linux["id"] and task["diagnostic_type"] == "cpu"
    assert (
        client.post(
            "/api/v1/platform/assets/" + str(windows["id"]) + "/test"
        ).status_code
        == 422
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


def test_group_crud_preserves_synced_groups():
    client = client_for()
    gid = client.post("/api/v1/platform/groups", json={"name": "Local"}).json()["id"]
    assert (
        client.put(
            f"/api/v1/platform/groups/{gid}", json={"name": "Renamed"}
        ).status_code
        == 200
    )
    with main.connection() as db:
        sync_id = db.execute(
            "INSERT INTO asset_groups(name,zabbix_groupid) VALUES ('Synced','77')"
        ).lastrowid
    assert (
        client.put(
            f"/api/v1/platform/groups/{sync_id}", json={"name": "Changed"}
        ).status_code
        == 409
    )
    assert client.delete(f"/api/v1/platform/groups/{sync_id}").status_code == 409
    assert client.delete(f"/api/v1/platform/groups/{gid}").status_code == 200


def test_connection_retry_after_asset_change_uses_current_revision(monkeypatch):
    from app.diagnostics import ssh

    monkeypatch.setattr(tasks, "enqueue", lambda _: None)
    monkeypatch.setattr(
        ssh, "execute", lambda *a, **k: {"status": "success", "duration_ms": 1}
    )
    client = client_for()
    body = {"name": "retry-target", "device_type": "linux"}
    asset = client.post("/api/v1/platform/assets", json=body).json()
    old = client.post(f"/api/v1/platform/assets/{asset['id']}/test").json()
    tasks.finish(old["task_id"], {"message": "old failure"}, status="failed")
    body["username"] = "new-diagnostic"
    assert (
        client.put(f"/api/v1/platform/assets/{asset['id']}", json=body).status_code
        == 200
    )
    retry = client.post(f"/api/v1/platform/tasks/{old['task_id']}/retry")
    assert retry.status_code == 202
    new = tasks.get(retry.json()["task_id"], private=True)
    assert (
        new["request"]["asset_revision"] == inventory.get_asset(asset["id"])["revision"]
    )
    assert (
        new["request"]["asset_revision"]
        != tasks.get(old["task_id"], private=True)["request"]["asset_revision"]
    )
    diagnostic_worker.process(new["task_id"])
    assert tasks.get(new["task_id"])["status"] == "success"
    assert inventory.get_asset(asset["id"])["last_test_status"] == "success"


@pytest.mark.parametrize("change", [{"enabled": False}, {"device_type": "windows"}])
def test_connection_retry_rejects_unavailable_target(monkeypatch, change):
    monkeypatch.setattr(tasks, "enqueue", lambda _: None)
    client = client_for()
    body = {"name": "retry-target", "device_type": "linux"}
    asset = client.post("/api/v1/platform/assets", json=body).json()
    old = client.post(f"/api/v1/platform/assets/{asset['id']}/test").json()
    tasks.finish(old["task_id"], {}, status="failed")
    assert (
        client.put(
            f"/api/v1/platform/assets/{asset['id']}", json={**body, **change}
        ).status_code
        == 200
    )
    response = client.post(f"/api/v1/platform/tasks/{old['task_id']}/retry")
    assert response.status_code == 422
    assert tasks.page()["total"] == 1


def test_imported_history_cannot_be_retried():
    old, _ = tasks.create({"legacy_id": 1}, kind="legacy")
    tasks.finish(old["task_id"], {}, status="failed")
    response = client_for().post(f"/api/v1/platform/tasks/{old['task_id']}/retry")
    assert response.status_code == 409
    assert tasks.page()["total"] == 1
