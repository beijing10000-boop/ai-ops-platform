"""Repeated task content is stored once; old details are purged only when configured."""

import asyncio
import base64
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app import main
from app.configuration import validate_form
from app.detailed_report import build_detailed_report
from app.model_interactions import traced_response
from app.orchestrator import tasks
from tests.test_platform import client_for

SKILL = (
    "---\nname: retention-check\ndescription: 实时主机查询\n---\n"
    "只在本测试出现的 Skill 正文段落。"
)
INSTRUCTIONS = "只在本测试出现的系统指令，各轮相同。"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def install_skill():
    response = client_for().post(
        "/api/v1/platform/skills",
        json={
            "filename": "SKILL.md",
            "data": base64.b64encode(SKILL.encode()).decode(),
            "enabled": True,
            "providers": ["ssh_mcp"],
        },
    )
    assert response.status_code == 201, response.text


def record_round(task_id, number):
    response = SimpleNamespace(
        status="completed",
        output_text="",
        output=[],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5, total_tokens=15),
    )
    asyncio.run(
        traced_response(
            SimpleNamespace(
                responses=SimpleNamespace(create=AsyncMock(return_value=response))
            ),
            task_id=task_id,
            round_number=number,
            deadline=time.monotonic() + 60,
            timeout_seconds=30,
            model="fixture",
            instructions=INSTRUCTIONS,
            input=[{"role": "user", "content": "round " + str(number)}],
        )
    )


def blob_count(kind):
    with main.connection() as db:
        return db.execute(
            "SELECT COUNT(*) FROM shared_blobs WHERE kind=?", (kind,)
        ).fetchone()[0]


def test_skill_snapshot_is_stored_once_per_content_and_hydrated():
    install_skill()
    first, _ = tasks.create({"question": "CPU"}, source="qa")
    second, _ = tasks.create({"question": "内存"}, source="qa")
    assert blob_count("skill") == 1
    with main.connection() as db:
        raw = db.execute(
            "SELECT request FROM diagnostic_tasks WHERE task_id=?",
            (second["task_id"],),
        ).fetchone()[0]
    assert set(tasks.decode(raw)["skills"][0]) == {"blob"}
    skill = tasks.get(second["task_id"], private=True)["request"]["skills"][0]
    assert skill["name"] == "retention-check"
    assert "只在本测试出现的 Skill 正文段落" in skill["files"]["SKILL.md"]
    assert tasks.get(first["task_id"], private=True)["request"]["skills"] == [skill]


def test_requests_saved_before_shared_blobs_still_read_inline():
    task, _ = tasks.create({"question": "CPU"}, source="qa")
    inline = {"name": "legacy", "files": {"SKILL.md": "旧任务内联保存"}}
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET request=? WHERE task_id=?",
            (tasks.encode({"question": "CPU", "skills": [inline]}), task["task_id"]),
        )
    assert tasks.get(task["task_id"], private=True)["request"]["skills"] == [inline]


def test_round_instructions_are_stored_once_and_shown_once_in_export():
    install_skill()
    task, _ = tasks.create({"question": "CPU"}, source="qa")
    for number in (1, 2, 3):
        record_round(task["task_id"], number)
    assert blob_count("instructions") == 1
    with main.connection() as db:
        payloads = [
            tasks.decode(row[0])
            for row in db.execute(
                "SELECT payload FROM model_interactions WHERE task_id=?",
                (task["task_id"],),
            )
        ]
    assert all("text" not in p["request"]["instructions"] for p in payloads)
    rows = tasks.model_interaction_page(task["task_id"], include_content=True)
    assert [r["payload"]["request"]["instructions"]["text"] for r in rows] == [
        INSTRUCTIONS
    ] * 3
    report = build_detailed_report(task["task_id"])
    assert report.count(INSTRUCTIONS) == 1
    assert report.count("只在本测试出现的 Skill 正文段落") == 1
    assert "完整内容见第 5 节" in report


def finished_task(question, days_ago):
    task, _ = tasks.create({"question": question}, source="qa")
    tasks.evidence(task["task_id"], "ssh_mcp", "ssh_diagnose_cpu", {"status": "ok"})
    record_round(task["task_id"], 1)
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET status='success',report=?,"
            "completed_at=datetime('now', ?) WHERE task_id=?",
            (
                tasks.encode({"answer": question + " 的结论"}),
                "-" + str(days_ago) + " days",
                task["task_id"],
            ),
        )
    return task["task_id"]


def details(task_id):
    with main.connection() as db:
        return tuple(
            db.execute(
                "SELECT COUNT(*) FROM " + table + " WHERE task_id=?", (task_id,)
            ).fetchone()[0]
            for table in ("diagnostic_evidence", "model_interactions")
        )


def test_retention_is_off_by_default_and_purges_old_details_once_a_day():
    old = finished_task("旧任务", 200)
    recent = finished_task("新任务", 10)
    assert tasks.purge_expired() is None  # default 0 keeps everything
    assert details(old) == (1, 1)
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('data_retention_days','180',0)")
    assert tasks.purge_expired() == {"evidence": 1, "interactions": 1}
    assert details(old) == (0, 0) and details(recent) == (1, 1)
    kept = tasks.get(old)
    assert kept["status"] == "success" and kept["report"]["answer"] == "旧任务 的结论"
    assert "证据明细已按保留天数清理" in build_detailed_report(old)
    # Claimed for today: a second worker finishing a task does not purge again.
    assert tasks.purge_expired() is None
    with main.connection() as db:
        assert db.execute(
            "SELECT key FROM audit WHERE action='data_retention_purge'"
        ).fetchall() == [("days=180 evidence=1 interactions=1",)]


@pytest.mark.parametrize("value", ["-1", "abc", "0180", "3651", "1.5"])
def test_retention_setting_rejects_invalid_values(value):
    with pytest.raises(HTTPException):
        validate_form({"data_retention_days": value}, lambda key: "")


def test_retention_setting_accepts_zero_and_days():
    for value in ("0", "180", "3650"):
        assert validate_form({"data_retention_days": value}, lambda key: "")["ok"]
