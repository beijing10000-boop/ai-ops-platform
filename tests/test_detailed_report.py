"""Detailed diagnostic export includes every saved record, under logs.read authorization."""

import pytest
from app import main
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


def test_export_has_all_sections_and_source_evidence_without_ui_toggle():
    task, _ = tasks.create(
        {
            "question": "诊断198.51.100.35内存",
            "event": {
                "event_id": "6590304",
                "host_id": "10825",
                "event_name": "High memory",
            },
        },
        source="alert",
        event_id="6590304",
    )
    tasks.evidence(
        task["task_id"],
        "ssh_mcp",
        "ssh_diagnose_memory_processes",
        {"records": [{"pid": 31272, "application": "billing.jar", "rss": "2232168"}]},
        43,
    )
    tasks.evidence(
        task["task_id"],
        "ssh_mcp",
        "ssh_diagnose_logs",
        {"output": "RAW-LOG-DETAIL-ONLY", "status": "success"},
        40,
    )
    tasks.finish(
        task["task_id"],
        {
            "answer": "Java 进程当前占用较高",
            "limitations": ["JVM 内部堆数据缺失"],
            "target": {"host_id": "10825", "ip": "198.51.100.35"},
            "budget": {"limits": {"rounds": 4}, "used": {"rounds": 2}},
        },
        {"available": True, "input": 500, "output": 100, "total": 600},
        duration_ms=57100,
    )
    with main.connection() as db:
        db.execute(
            "INSERT INTO model_interactions(task_id,round_number,model,status,"
            "duration_ms,token_input,token_output,token_total,payload) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                task["task_id"],
                1,
                "gpt-test",
                "completed",
                1230,
                500,
                100,
                600,
                tasks.encode(
                    {
                        "request": {
                            "instructions": {"text": "已应用只读 Skill"},
                            "input": {"text": "查询内存"},
                        },
                        "response": {"text": {"text": "诊断建议"}},
                    }
                ),
            ),
        )
    response = client_for("ops_admin").get(
        f"/api/v1/platform/tasks/{task['task_id']}/detailed-report"
    )
    assert response.status_code == 200
    assert "attachment;" in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["content-type"].startswith("text/markdown")
    text = response.text
    for key in (
        "AI 运维详细诊断报告",
        "任务总览",
        "告警、主机与诊断目标",
        "诊断不足和预算",
        "本次加载的 Skill",
        "原始任务元数据和请求快照",
        "诊断时间线",
        "逐轮与大模型交互记录",
        "MCP 工具执行记录和完整已保存证据",
        "gpt-test",
        "billing.jar",
        "RAW-LOG-DETAIL-ONLY",
        "已应用只读 Skill",
        "JVM 内部堆数据缺失",
        "57.10 秒",
        "6590304",
    ):
        assert key in text
    with main.connection() as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='detailed_report_export'"
            ).fetchone()[0]
            == 1
        )


def test_detailed_export_permissions_and_missing_task():
    task, _ = tasks.create({"question": "check"}, source="qa")
    url = f"/api/v1/platform/tasks/{task['task_id']}/detailed-report"
    from fastapi.testclient import TestClient

    assert TestClient(main.app).get(url).status_code == 401
    assert client_for("operator").get(url).status_code == 403
    assert client_for("auditor").get(url).status_code == 403
    assert client_for("ops_admin").get(url).status_code == 200
    assert client_for().get(url).status_code == 200
    assert (
        client_for()
        .get("/api/v1/platform/tasks/non-existent/detailed-report")
        .status_code
        == 404
    )
    with main.connection() as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='detailed_report_export'"
            ).fetchone()[0]
            == 2
        )


def test_detailed_export_reads_beyond_paginated_200_evidence_and_100_model_rounds():
    task, _ = tasks.create({"question": "大量历史"})
    with main.connection() as db:
        db.executemany(
            "INSERT INTO diagnostic_evidence(task_id,trace_id,provider,tool,"
            "status,duration_ms,payload) VALUES (?,?,?,?,?,?,?)",
            [
                (
                    task["task_id"],
                    task["trace_id"],
                    "zabbix_mcp",
                    "history_get",
                    "success",
                    2,
                    tasks.encode({"sequence": i}),
                )
                for i in range(205)
            ],
        )
        db.executemany(
            "INSERT INTO model_interactions(task_id,round_number,model,status,"
            "duration_ms,token_input,token_output,token_total,payload) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (
                    task["task_id"],
                    i,
                    "test-model",
                    "completed",
                    10,
                    1,
                    1,
                    2,
                    tasks.encode(
                        {
                            "request": {"text": f"request-{i}"},
                            "response": {"text": f"reply-{i}"},
                        }
                    ),
                )
                for i in range(1, 105)
            ],
        )
    text = (
        client_for()
        .get(f"/api/v1/platform/tasks/{task['task_id']}/detailed-report")
        .text
    )
    assert "已保存证据记录：205" in text
    assert "已保存模型交互记录：104" in text
    assert text.count("### zabbix_mcp / history_get") == 205
    assert text.count("### 第 ") == 104
    assert '"sequence": 204' in text
    assert "reply-104" in text


def test_export_never_reveals_known_tokens_or_password_fields():
    task, _ = tasks.create({"question": "检查secret-in-query ABCDEFG12345"})
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings(key,value,secret) VALUES(?,?,1)",
            ("openai_api_key", main.cipher().encrypt(b"ABCDEFG12345").decode()),
        )
    tasks.evidence(
        task["task_id"],
        "ssh_mcp",
        "ssh_diagnose_logs",
        {"output": "raw output with ABCDEFG12345", "api_key": "inner-secret"},
    )
    response = client_for().get(
        f"/api/v1/platform/tasks/{task['task_id']}/detailed-report"
    )
    assert response.status_code == 200
    assert "ABCDEFG12345" not in response.text
    assert "inner-secret" not in response.text
    assert "[REDACTED]" in response.text
