"""Real disposable Redis/RQ; no production addresses or flushdb calls."""

import os
import shutil
import subprocess
import socket
import tempfile
import time
from pathlib import Path
import pytest
from redis import Redis
from rq import Queue, SimpleWorker
from fastapi.testclient import TestClient
from app import main, inventory, conversation_context as ctx
from app.orchestrator import tasks


@pytest.fixture
def real_redis(monkeypatch, tmp_path):
    binary = os.getenv("AIOPS_REDIS_SERVER") or shutil.which("redis-server")
    if not binary or not Path(binary).is_file():
        pytest.skip("Set AIOPS_REDIS_SERVER to run disposable Redis/RQ integration")
    with tempfile.TemporaryDirectory(prefix="aiops-redis-test-") as data:
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
        process = subprocess.Popen(
            [
                binary,
                "--port",
                str(port),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                data,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        redis = Redis(host="127.0.0.1", port=port)
        try:
            for _ in range(100):
                try:
                    if redis.ping():
                        break
                except Exception:
                    time.sleep(0.03)
            else:
                raise RuntimeError("disposable Redis did not start")
            url = "redis://127.0.0.1:" + str(port) + "/0"
            monkeypatch.setattr(main, "DATA_DIR", tmp_path)
            monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
            monkeypatch.setattr(main, "REDIS_URL", url)
            monkeypatch.setattr(ctx, "REDIS_URL", url)
            yield redis
        finally:
            process.terminate()
            process.wait(timeout=5)


def test_real_webhook_dedup_and_rq_alert_delivery_without_feishu(real_redis):
    secret = "disposable-test-webhook"
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES (?,?,1)",
            ("zabbix_webhook_secret", main.cipher().encrypt(secret.encode()).decode()),
        )
    client = TestClient(main.app)
    header = {"authorization": "Bearer " + secret}
    body = {"event_id": "900001", "severity": "0", "event_name": "test event"}
    first = client.post("/zabbix", headers=header, json=body)
    assert first.status_code == 202
    assert (
        client.post("/zabbix", headers=header, json=body).json()["status"]
        == "duplicate"
    )
    queue = Queue("ai-alerts", connection=real_redis)
    assert len(queue) == 1
    worker = SimpleWorker([queue], connection=real_redis)
    worker.work(burst=True, with_scheduler=False, logging_level="WARNING")
    assert queue.fetch_job(first.json()["job_id"]).is_finished
    with main.connection() as db:
        assert (
            db.execute("SELECT notify_status FROM alert_events").fetchone()[0]
            == "disabled"
        )


def test_real_diagnostic_queue_records_connection_failure(real_redis):
    asset = inventory.save_asset(
        inventory.AssetInput(name="no-credentials", device_type="linux"), "test"
    )
    task, _ = tasks.create(
        {"asset_revision": asset["revision"]},
        kind="connection",
        asset_id=asset["id"],
        diagnostic_type="connection",
    )
    tasks.enqueue(task["task_id"])
    queue = Queue("ai-diagnostics", connection=real_redis)
    assert queue.fetch_job(task["task_id"]).func_name == "app.diagnostic_worker.process"
    SimpleWorker([queue], connection=real_redis).work(
        burst=True, with_scheduler=False, logging_level="WARNING"
    )
    assert tasks.get(task["task_id"])["status"] == "failed"
    assert tasks.get(task["task_id"])["error_type"] == "ValueError"


def test_real_context_keeps_exact_reply_branch_and_chat_isolation(real_redis):
    root = {
        "origin": "alert",
        "turns": [],
        "event": {"event_id": "123", "host_id": "42"},
    }
    ctx.remember("oc_one", "om_q1", "om_a1", "question1", "answer1", root)
    first = ctx.recall("oc_one", "om_a1")
    ctx.remember("oc_one", "om_q2", "om_a2", "question2", "answer2", first)
    assert len(ctx.recall("oc_one", "om_a2")["turns"]) == 2
    assert len(ctx.recall("oc_one", "om_a1")["turns"]) == 1
    assert ctx.recall("oc_two", "om_a2") is None
    assert ctx.recall("oc_one", "om_a2")["event"]["host_id"] == "42"
    ctx.mark_pending("oc_one", "om_working")
    assert ctx.is_pending("oc_one", "om_working")
    assert not ctx.is_pending("oc_two", "om_working")
    ctx.clear_pending("oc_one", "om_working")
    assert not ctx.is_pending("oc_one", "om_working")
