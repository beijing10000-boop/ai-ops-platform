"""Per-task Responses API exchange history is encrypted and permission-gated."""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app import main
from app.model_interactions import traced_response
from app.orchestrator import tasks
from tests.test_platform import client_for


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def _response():
    return SimpleNamespace(
        status="completed",
        output_text="现有内存 90.15%，Token: hidden-token",
        output=[
            SimpleNamespace(
                type="function_call",
                name="call_mcp_tool",
                arguments='{"provider":"zabbix_mcp","api_key":"secret-xyz"}',
            )
        ],
        usage=SimpleNamespace(input_tokens=120, output_tokens=30, total_tokens=150),
    )


def test_model_exchange_saved_encrypted_with_secret_redaction():
    task, _ = tasks.create({"question": "CPU"}, source="qa")
    client = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(return_value=_response())))
    asyncio.run(
        traced_response(
            client,
            task_id=task["task_id"],
            round_number=1,
            secret_values=["secret-xyz"],
            deadline=time.monotonic() + 90,
            timeout_seconds=60,
            model="test-deployment",
            instructions="Read only; Authorization: Bearer secret-xyz",
            input=[{"role": "user", "content": "请检查 API_KEY=secret-xyz"}],
            tools=[{"name": "call_mcp_tool"}],
            max_output_tokens=3000,
        )
    )
    with main.connection() as db:
        stored = db.execute(
            "SELECT payload FROM model_interactions WHERE task_id=?", (task["task_id"],)
        ).fetchone()[0]
    assert "secret-xyz" not in stored
    assert "Read only" not in stored  # Fernet-encrypted at rest
    rows = tasks.model_interaction_page(task["task_id"])
    assert len(rows) == 1
    assert "payload" not in rows[0]
    assert rows[0]["token_total"] == 150
    row = tasks.model_interaction_page(task["task_id"], include_content=True)[0]
    assert row["payload"]["request"]["tools"] == ["call_mcp_tool"]
    assert "[REDACTED]" in row["payload"]["request"]["instructions"]["text"]
    assert "secret-xyz" not in str(row["payload"])
    assert row["payload"]["response"]["items"][0]["name"] == "call_mcp_tool"


def test_model_history_roles_and_no_context_reveal():
    task, _ = tasks.create({"question": "Secret question"}, source="qa")
    url = f"/api/v1/platform/tasks/{task['task_id']}/model-interactions"
    assert client_for("operator").get(url).status_code == 200
    assert client_for("operator").get(url + "?include_content=true").status_code == 403
    assert client_for("auditor").get(url + "?include_content=true").status_code == 403
    assert client_for("ops_admin").get(url + "?include_content=true").status_code == 200
    assert client_for().get(url + "?include_content=true").status_code == 200
    assert client_for().get("/api/v1/platform/tasks/no-such-task/model-interactions").status_code == 404


def test_large_preview_is_explicitly_truncated():
    from app.model_interactions import _preview

    value = "start:" + "x" * 25000 + ":end"
    data = _preview(value)
    assert data["truncated"] is True
    assert data["original_chars"] > 25000
    assert data["text"].startswith("start:")
    assert data["text"].endswith(":end")
    assert len(data["text"]) < 17000


def test_failed_model_request_keeps_safe_error_category():
    from openai import APIStatusError
    import httpx

    task, _ = tasks.create({"question": "Check"}, source="qa")
    req = httpx.Request("POST", "https://example.invalid")
    error = APIStatusError("sensitive service error", response=httpx.Response(400, request=req), body={})
    client = SimpleNamespace(responses=SimpleNamespace(create=AsyncMock(side_effect=error)))
    with pytest.raises(APIStatusError):
        asyncio.run(
            traced_response(
                client,
                task_id=task["task_id"],
                round_number=1,
                deadline=time.monotonic() + 60,
                timeout_seconds=25,
                model="test",
                instructions="private text",
                input=[],
            )
        )
    row = tasks.model_interaction_page(task["task_id"], include_content=True)[0]
    assert row["status"] == "failed"
    assert "sensitive service error" not in str(row)
    assert row["payload"]["error"] == "ModelRequestError"
