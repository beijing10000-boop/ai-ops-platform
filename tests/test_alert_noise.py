"""Flapping triggers, low-priority alerts and a daily budget keep automatic analysis cheap."""

import asyncio
import json

import pytest
from fastapi import HTTPException

from app import main, worker
from app.configuration import validate_form
from app.orchestrator import tasks


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")


def settings(monkeypatch, **values):
    merged = {
        "ai_min_severity": "4",
        "web_protocol": "http",
        "web_public_host": "ops.example.com:8088",
        **values,
    }
    monkeypatch.setattr(worker, "cfg", lambda key: merged.get(key, ""))


def alert(event_id, severity="4", trigger="66713", **extra):
    return {
        "event_id": event_id,
        "event_value": "1",
        "severity": severity,
        "host_id": "10913",
        "trigger_id": trigger,
        "host_name": "db-test-01",
        "event_name": "Linux: Load average is too high",
        "host_groups": "Linux servers",
        **extra,
    }


def store_alert(event, minutes_ago=0):
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_name,host_name,severity,"
            "event_json,received_at) VALUES (?,'1',?,?,?,?,datetime('now', ?))",
            (
                event["event_id"],
                event["event_name"],
                event["host_name"],
                int(event["severity"]),
                json.dumps(event),
                f"-{minutes_ago} minutes",
            ),
        )


def finished(event, *, minutes_ago, tokens=None, actor="system", days_ago=0):
    task, _ = tasks.create(
        {"event": event}, source="alert", event_id=event["event_id"], actor=actor
    )
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET status='success',token_total=?,"
            "completed_at=datetime('now', ?),created_at=datetime('now', ?) WHERE task_id=?",
            (
                tokens,
                f"-{minutes_ago} minutes",
                f"-{days_ago} days",
                task["task_id"],
            ),
        )
    return task["task_id"]


def capture(monkeypatch):
    cards, queued = [], []

    async def notify(card, event=None, **kwargs):
        cards.append(json.dumps(card, ensure_ascii=False))

    def enqueue(queue_name, func, event, *args, **kwargs):
        queued.append(kwargs)
        return {"task_id": "new-task"}, True

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(worker, "enqueue_analysis", enqueue)
    return cards, queued


def ai_status(event_id):
    with main.connection() as db:
        return db.execute(
            "SELECT ai_status FROM alert_events WHERE event_id=?", (event_id,)
        ).fetchone()[0]


def test_flapping_trigger_reuses_the_recent_analysis_on_the_original_card(
    monkeypatch,
):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards, queued = capture(monkeypatch)
    earlier = alert("880001")
    store_alert(alert("880000"), minutes_ago=300)
    store_alert(earlier, minutes_ago=40)
    reused = finished(earlier, minutes_ago=30)
    new = alert("880002")
    store_alert(new)
    result = asyncio.run(worker.handle_alert(new))
    assert result["ai_skipped"] and result["reused_task_id"] == reused
    assert queued == [] and ai_status("880002") == "reused"
    [card] = cards
    assert "本次不重复分析" in card and "近 24 小时共 3 次告警" in card
    # The report link is the plain report URL (opens in the default browser).
    assert "applink" not in card and "AI分析" in card
    assert "/#report/" + reused + ")" in card


def test_reuse_needs_same_trigger_within_the_window(monkeypatch):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    old = alert("880010")
    store_alert(old, minutes_ago=200)
    finished(old, minutes_ago=180)
    assert worker.recent_analysis(alert("880011")) is None  # older than 2 h
    other = alert("880012", trigger="99999")
    store_alert(other)
    finished(other, minutes_ago=5)
    assert worker.recent_analysis(alert("880013")) is None  # other trigger
    assert worker.recent_analysis(alert("880014", trigger="99999"))
    settings(monkeypatch, ai_alert_reuse_hours="0")
    assert worker.recent_analysis(alert("880015", trigger="99999")) is None


def test_daily_budget_counts_only_todays_automatic_analyses(monkeypatch):
    settings(monkeypatch, ai_daily_token_limit="10000", ai_alert_reuse_hours="0")
    for event_id, tokens, actor, days in (
        ("880020", 6000, "system", 0),
        ("880021", 9000, "ou_operator", 0),  # manual click
        ("880022", 50000, "system", 1),  # yesterday
    ):
        event = alert(event_id, trigger=event_id)
        store_alert(event)
        finished(event, minutes_ago=10, tokens=tokens, actor=actor, days_ago=days)
    assert worker.daily_budget() == (6000, 10000)
    cards, queued = capture(monkeypatch)
    asyncio.run(worker.handle_alert(alert("880023", trigger="1")))
    assert len(queued) == 1  # under the limit: analysed
    event = alert("880024", trigger="880024")
    store_alert(event)
    finished(event, minutes_ago=5, tokens=4000)
    blocked = alert("880025", trigger="2")
    store_alert(blocked)
    result = asyncio.run(worker.handle_alert(blocked))
    assert result["budget_exhausted"] and len(queued) == 1
    assert (
        "达到每日上限 10,000" in cards[-1] and ai_status("880025") == "skipped_budget"
    )
    settings(monkeypatch, ai_daily_token_limit="0")
    assert worker.daily_budget() is None


def test_low_severity_or_test_groups_use_the_quick_profile(monkeypatch):
    settings(
        monkeypatch,
        ai_min_severity="3",
        ai_analysis_profile="standard",
        ai_quick_severity_max="3",
        ai_quick_host_groups="测试环境, staging",
    )
    assert worker.alert_profile(alert("1", severity="3")) == "quick"
    assert worker.alert_profile(alert("2", severity="4")) == "standard"
    assert (
        worker.alert_profile(
            alert("3", severity="5", host_groups="Linux servers, 测试环境")
        )
        == "quick"
    )
    _, queued = capture(monkeypatch)
    asyncio.run(worker.handle_alert(alert("880030", severity="3", trigger="30")))
    asyncio.run(worker.handle_alert(alert("880031", severity="5", trigger="31")))
    assert [q["profile_name"] for q in queued] == ["quick", "standard"]


@pytest.mark.parametrize(
    "values",
    [
        {"ai_alert_reuse_hours": "73"},
        {"ai_daily_token_limit": "-1"},
        {"ai_quick_severity_max": "5"},
        {"ai_quick_host_groups": ",".join(["x"] * 21)},
        {"ai_quick_host_groups": "测试环境,,staging"},
    ],
)
def test_noise_settings_reject_invalid_values(values):
    with pytest.raises(HTTPException):
        validate_form(values, lambda key: "")


def test_noise_settings_accept_valid_values():
    assert validate_form(
        {
            "ai_alert_reuse_hours": "0",
            "ai_daily_token_limit": "200000",
            "ai_quick_severity_max": "3",
            "ai_quick_host_groups": "测试环境,staging",
        },
        lambda key: "",
    )["ok"]
