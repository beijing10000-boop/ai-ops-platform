"""Regressions for the remaining P2 findings of the 2026-11 audit
(OPS-PIPE-04/05/11/13, OPS-WEB-03/06)."""

import asyncio
import json
import re
from types import SimpleNamespace

import pytest

from app import conversation_context, feishu_client, main, qa_worker, worker
from app.orchestrator import tasks

TASK_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)")


def settings(monkeypatch, **values):
    merged = {
        "ai_min_severity": "4",
        "web_protocol": "http",
        "web_public_host": "ops.example.com:8088",
        **values,
    }
    monkeypatch.setattr(worker, "cfg", lambda key: merged.get(key, ""))


def alert(event_id, trigger="66713", **extra):
    return {
        "event_id": event_id,
        "event_value": "1",
        "severity": "4",
        "host_id": "10913",
        "trigger_id": trigger,
        "host_name": "db-test-01",
        "event_name": "Linux: High memory utilization",
        **extra,
    }


def store_alert(event, ai_status="pending"):
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_name,host_name,"
            "severity,ai_status,event_json) VALUES (?,?,?,?,4,?,?)",
            (
                event["event_id"],
                event["event_value"],
                event["event_name"],
                event["host_name"],
                ai_status,
                json.dumps(event),
            ),
        )


def recover(event):
    store_alert({**event, "event_value": "0"}, ai_status="not_required")


def queued_task(event, actor="system"):
    task, created = tasks.create(
        {"event": event}, source="alert", event_id=event["event_id"], actor=actor
    )
    assert created
    return task["task_id"]


def update_task(task_id, assignments):
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET " + assignments + " WHERE task_id=?",
            (task_id,),
        )


def ai_status(event_id):
    with main.connection() as db:
        return db.execute(
            "SELECT ai_status FROM alert_events WHERE event_id=? AND event_value='1'",
            (event_id,),
        ).fetchone()[0]


def capture(monkeypatch):
    cards, queued = [], []

    async def notify(card, event=None, **kwargs):
        cards.append(json.dumps(card, ensure_ascii=False))

    def enqueue(queue_name, func, event, *args, **kwargs):
        queued.append(event["event_id"])
        return {"task_id": "new-" + event["event_id"]}, True

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(worker, "enqueue_analysis", enqueue)
    return cards, queued


def analyses_run(monkeypatch):
    ran = []

    async def analyze(event, task_id=None):
        ran.append(task_id)
        return {"cause": "内存不足", "action": ["重启 dsp-api"], "analysis": ""}

    async def notify(card, event=None, **kwargs):
        pass

    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(worker, "notify", notify)
    return ran


# OPS-PIPE-04: a flapping trigger's alerts wait for the analysis in progress.


def test_alerts_of_a_trigger_wait_for_its_analysis_in_progress(monkeypatch):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards, queued = capture(monkeypatch)
    first = alert("770001")
    store_alert(first)
    task_id = queued_task(first)
    second = alert("770002")
    store_alert(second)
    result = asyncio.run(worker.handle_alert(second))
    assert result["reused_task_id"] == task_id and result["reused_in_progress"]
    assert result["ai_skipped"] and queued == []
    assert ai_status("770002") == "reused"
    assert "已有 AI 分析在排队" in cards[-1] and "近 24 小时共 2 次告警" in cards[-1]
    assert "本次不重复分析，结果将回复在该次告警的卡片下" in cards[-1]
    assert "/#report/" + task_id + ")" in cards[-1] and "AI分析" in cards[-1]
    # Running: the next alert waits for it too, and the card says it is under way.
    tasks.start(task_id)
    third = alert("770003")
    store_alert(third)
    assert asyncio.run(worker.handle_alert(third))["reused_task_id"] == task_id
    assert "的 AI 分析正在进行" in cards[-1] and queued == []
    # A finished analysis within the window still comes first, worded as before.
    tasks.finish(task_id, {"answer": "内存不足"})
    fourth = alert("770004")
    store_alert(fourth)
    result = asyncio.run(worker.handle_alert(fourth))
    assert result["reused_task_id"] == task_id and "reused_in_progress" not in result
    assert "已完成 AI 分析" in cards[-1]


def test_only_analyses_that_will_still_answer_are_waited_for(monkeypatch):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cases = {}
    for trigger in ("10", "11", "12", "13"):
        first = alert("7710" + trigger, trigger=trigger)
        store_alert(first)
        cases[trigger] = queued_task(first)
    # Its alert recovered: it will not run (outdated), so it is not waited for.
    recover(alert("771010", trigger="10"))
    # Queued longer than the reuse window: it will not run either.
    update_task(cases["11"], "created_at=datetime('now','-3 hours')")
    # Running past the longest analysis budget: its worker is gone.
    update_task(
        cases["12"], "status='running',started_at=datetime('now','-30 minutes')"
    )
    # Cancelled from the Web while running.
    update_task(
        cases["13"], "status='running',started_at=datetime('now'),cancel_requested=1"
    )
    for trigger in cases:
        assert worker.recent_analysis(alert("7711" + trigger, trigger=trigger)) is None
    # One that will answer is waited for; with reuse off, none is.
    live = alert("771020", trigger="20")
    store_alert(live)
    queued_task(live)
    assert worker.recent_analysis(alert("771021", trigger="20"))["in_progress"]
    settings(monkeypatch, ai_alert_reuse_hours="0")
    assert worker.recent_analysis(alert("771022", trigger="20")) is None


# OPS-PIPE-05: a queued automatic analysis checks its alert before it starts.


def test_queued_analysis_of_a_recovered_alert_is_not_run(monkeypatch):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    ran = analyses_run(monkeypatch)
    event = alert("772001")
    store_alert(event)
    task_id = queued_task(event)
    recover(event)
    result = worker.process_alert_analysis(event, task_id)
    assert result["skipped"] and result["reason"] == "AlertRecovered" and ran == []
    task = tasks.get(task_id)
    assert (task["status"], task["error_type"]) == ("cancelled", "AlertRecovered")
    assert "恢复" in task["report"]["message"] and "AI分析" in task["report"]["message"]
    assert ai_status("772001") == "cancelled"
    # A later alert of the trigger waiting for this analysis is still on: it runs.
    first = alert("772010", trigger="772010")
    store_alert(first)
    waited_for = queued_task(first)
    later = alert("772011", trigger="772010")
    store_alert(later)
    capture(monkeypatch)
    assert asyncio.run(worker.handle_alert(later))["reused_task_id"] == waited_for
    recover(first)
    ran = analyses_run(monkeypatch)
    assert worker.process_alert_analysis(first, waited_for)["diagnosed"]
    assert ran == [waited_for]
    # Both recovered: not run.
    again = alert("772020", trigger="772020")
    store_alert(again)
    skipped = queued_task(again)
    follower = alert("772021", trigger="772020")
    store_alert(follower, ai_status="reused")
    recover(again)
    recover(follower)
    assert worker.process_alert_analysis(again, skipped)["reason"] == "AlertRecovered"
    # A click on "🤖 AI分析" is a request: it runs, recovered or not.
    clicked = alert("772030", trigger="772030")
    store_alert(clicked)
    manual = queued_task(clicked, actor="ou_super")
    recover(clicked)
    update_task(manual, "created_at=datetime('now','-5 hours')")
    started = []

    async def on_demand(event, message_id, chat_id=None, task_id=None):
        started.append(task_id)
        return {"diagnosed": True}

    monkeypatch.setattr(worker, "analyze_on_demand", on_demand)
    worker.process_manual_analysis(clicked, "om_card", "oc_group", manual)
    assert started == [manual]


def test_queued_analysis_past_the_queue_limit_is_not_run(monkeypatch):
    # Reuse off: the limit is the reuse window's default, 2 hours.
    settings(monkeypatch, ai_alert_reuse_hours="0")
    ran = analyses_run(monkeypatch)
    event = alert("773001")
    store_alert(event)
    task_id = queued_task(event)
    update_task(task_id, "created_at=datetime('now','-150 minutes')")
    result = worker.process_alert_analysis(event, task_id)
    assert result["reason"] == "QueueExpired" and ran == []
    task = tasks.get(task_id)
    assert (task["status"], task["error_type"]) == ("cancelled", "QueueExpired")
    assert re.search(r"排队 15\d 分钟仍未开始", task["report"]["message"])
    assert "已超过排队上限 2 小时" in task["report"]["message"]
    assert ai_status("773001") == "cancelled"
    # Within a longer reuse window it still runs.
    settings(monkeypatch, ai_alert_reuse_hours="3")
    fresh = alert("773002", trigger="773002")
    store_alert(fresh)
    kept = queued_task(fresh)
    update_task(kept, "created_at=datetime('now','-150 minutes')")
    assert worker.process_alert_analysis(fresh, kept)["diagnosed"] and ran == [kept]


class ReceiverRedis:
    def __init__(self):
        self.keys = set()

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.keys:
            return None
        self.keys.add(key)
        return True

    def delete(self, key):
        self.keys.discard(key)


def chat_message(message_id, text):
    return SimpleNamespace(
        event=SimpleNamespace(
            message=SimpleNamespace(
                message_id=message_id,
                chat_id="oc_group",
                chat_type="group",
                message_type="text",
                content=json.dumps({"text": "@_user_1 " + text}, ensure_ascii=False),
                parent_id=None,
                root_id=None,
            ),
            sender=SimpleNamespace(
                sender_type="user", sender_id=SimpleNamespace(open_id="ou_super")
            ),
        )
    )


def test_a_question_that_waits_says_so_and_keeps_one_card(monkeypatch):
    from app import feishu_bot

    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('allowed_chat_ids','oc_group',0)")
    replies, updates, jobs = [], [], []

    async def reply(message_id, title, text, template="blue", link=None):
        replies.append((message_id, title, text))
        return "om_queued"

    async def update(message_id, title, text, template="green", link=None):
        updates.append((message_id, title, text, template))

    class Jobs:
        def enqueue(self, func, *args, **kwargs):
            jobs.append((args, kwargs))

    monkeypatch.setattr(feishu_client, "reply_card", reply)
    monkeypatch.setattr(feishu_client, "update_card", update)
    monkeypatch.setattr(feishu_bot, "queue", Jobs())
    monkeypatch.setattr(feishu_bot, "redis", ReceiverRedis())
    # Two questions ahead (one being answered, one waiting).
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (2, 1))
    feishu_bot.on_message(chat_message("om_question", "<at id=all></at> 内存高吗"))
    [(target, title, text)] = replies
    assert (target, title) == ("om_question", "AI 排队中")
    assert "前面还有 2 个问题，轮到后自动开始分析" in text and "<at" not in text
    [(args, kwargs)] = jobs
    assert args[2] == "om_question" and kwargs["queued_card"] == "om_queued"
    # Nothing ahead: it starts at once and the worker replies as before.
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (0, 1))
    feishu_bot.on_message(chat_message("om_next", "CPU 呢"))
    assert len(replies) == 1 and "queued_card" not in jobs[-1][1]
    # No qa-worker running: the question waits for one, and is told so.
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (0, 0))
    feishu_bot.on_message(chat_message("om_third", "磁盘呢"))
    assert "问答分析服务暂未运行" in replies[-1][2]
    # The worker turns the queued card into its progress card and then the answer.
    settings(monkeypatch)
    task, _ = tasks.create({"question": "CPU"}, source="qa")
    tasks.finish(task["task_id"], {"answer": "CPU 正常"})

    async def ask(question, context, return_usage=False, actor="system", **kwargs):
        return "CPU 正常", {"available": False, "task_id": task["task_id"]}

    async def no_reply(*args, **kwargs):
        raise AssertionError("the queued card is the question's only card")

    for name, value in {
        "ask": ask,
        "reply_card": no_reply,
        "update_card": update,
        "record_ai_question": lambda *args, **kwargs: None,
        "recall": lambda *args: None,
        "is_pending": lambda *args: False,
        "mark_pending": lambda *args: None,
        "clear_pending": lambda *args: None,
        "remember": lambda *args, **kwargs: None,
    }.items():
        monkeypatch.setattr(qa_worker, name, value)
    updates.clear()
    asyncio.run(
        qa_worker.execute("oc_group", "CPU", "om_question", queued_card="om_queued")
    )
    assert [(m, t) for m, t, _, _ in updates] == [
        ("om_queued", "AI 分析中"),
        ("om_queued", "AI 分析完成"),
    ]
    # A question turned away while it waited says so on the same card.
    monkeypatch.setattr(qa_worker, "is_pending", lambda *args: True)
    updates.clear()
    asyncio.run(
        qa_worker.execute(
            "oc_group", "再查", "om_again", parent_id="om_x", queued_card="om_q2"
        )
    )
    assert updates == [("om_q2", "AI 分析中", "正在分析中，请勿重复提交。", "orange")]


# OPS-PIPE-11: one body for the automatic and the clicked "AI 分析结果" card.


def clicked_card(monkeypatch, event, info):
    """The card a click on "🤖 AI分析" ends with, as Feishu receives it."""
    sent = []

    async def analyze(event, task_id=None):
        return dict(info)

    async def reply(message_id, title, text, template="blue", link=None):
        return "om_progress"

    async def update(message_id, title, text, template="green", link=None):
        sent.append(make_card(title, text, template, link))

    make_card = feishu_client.make_card
    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(feishu_client, "reply_card", reply)
    monkeypatch.setattr(feishu_client, "update_card", update)
    monkeypatch.setattr(conversation_context, "remember", lambda *a, **k: None)
    for name in ("mark_pending", "clear_pending"):
        monkeypatch.setattr(conversation_context, name, lambda *args: None)
    asyncio.run(worker.analyze_on_demand(event, "om_card", "oc_group", "task"))
    [card] = sent
    return card


def test_clicked_analysis_card_has_the_automatic_cards_body(monkeypatch):
    settings(monkeypatch)
    event = alert("774001")
    info = {
        "cause": "内存使用率 98%（E2），MemAvailable 1565240 kB，且未配置 Swap。",
        "action": ["重启 dsp-api（E3）", "建议配置 2 GB Swap 作为缓冲"],
        "_task_id": TASK_ID,
        "_diagnostic_status": "partial",
        "_token_usage": {"available": True, "input": 900, "output": 100, "total": 1000},
        "_duration_ms": 61200,
    }
    automatic = worker.make_card(event, info, analysis=True)
    clicked = clicked_card(monkeypatch, event, info)
    # Everything under the alert's own fields is the same, footer included,
    # and so is the colour: the alert's severity (the click used to be green
    # whatever the diagnosis said).
    assert clicked["elements"] == automatic["elements"][2:]
    assert clicked["header"]["template"] == automatic["header"]["template"] == "red"
    assert clicked["header"]["title"]["content"] == "AI 分析结果"
    body = clicked["elements"][0]["text"]["content"]
    assert body.startswith("**诊断状态**  部分完成\n\n**诊断结论**\n内存使用率 98%")
    assert "1.49 GiB" in body and "E2" not in body and "Swap" not in body
    assert body.endswith("**处理建议**\n1. 重启 dsp-api")
    assert clicked["elements"][1]["actions"][0]["url"].endswith("/#report/" + TASK_ID)
    note = clicked["elements"][-1]["elements"][0]["content"]
    assert note.startswith("◉ 本轮 Token 消耗：1,000") and "执行耗时：61.2 秒" in note
    # The footer is an element of its own, not found by its wording.
    monkeypatch.setattr(
        worker, "card_note", lambda info: "数据来源：仅 Zabbix 监控数据"
    )
    clicked = clicked_card(monkeypatch, event, info)
    assert clicked["elements"][-1]["elements"][0]["content"].endswith(
        "仅 Zabbix 监控数据"
    )
    assert "数据来源" not in clicked["elements"][0]["text"]["content"]
    # An unfinished analysis gets the same concrete next steps either way.
    unfinished = {
        "analysis": "AI 模型请求超时；模型未完成最终诊断。\n请在下方核验。",
        "_unstructured": True,
        "_diagnostic_status": "partial",
    }
    clicked = clicked_card(monkeypatch, {**event, "event_value": "0"}, unfinished)
    assert clicked["header"]["template"] == "green"  # a recovery event's card
    assert "1. " + worker.RETRY in clicked["elements"][0]["text"]["content"]
    assert (
        clicked["elements"][0]
        == worker.make_card(event, unfinished, analysis=True)["elements"][2]
    )


# OPS-PIPE-13 / OPS-WEB-03: the schema is set up once per version, reads take
# no write lock, and one connection authenticates a request.

WRITES = ("BEGIN", "CREATE", "ALTER", "INSERT", "UPDATE", "DELETE", "DROP")


def traced(monkeypatch, busy=None):
    """The statements each new connection runs, one list per connection;
    `busy` shortens the lock wait (20 s) so a wait fails fast."""
    import sqlite3

    real = sqlite3.connect
    runs = []

    def connect(*args, **kwargs):
        db = real(*args, **({**kwargs, "timeout": busy} if busy else kwargs))
        runs.append([])
        db.set_trace_callback(runs[-1].append)
        return db

    monkeypatch.setattr(sqlite3, "connect", connect)
    return runs


def test_reads_neither_set_the_schema_up_nor_take_the_write_lock(monkeypatch):
    import sqlite3

    real = sqlite3.connect
    runs = traced(monkeypatch, busy=0.5)
    assert main.read_setting("web_protocol") == "http"
    [run] = runs
    assert not [s for s in run if s.lstrip().upper().startswith(WRITES)], run
    holder = real(main.DB, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        # Readers no longer queue for a writer's lock (they did, up to 20 s) ...
        assert main.read_setting("web_protocol") == "http"
        with main.connection() as db:
            assert db.execute("SELECT COUNT(*) FROM settings").fetchone()[0] >= 1
        # ... writers still take it, one at a time, as before.
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with main.connection() as db:
                db.execute("INSERT INTO settings VALUES ('lock_probe','1',0)")
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert main.read_setting("lock_probe") == ""


def test_the_schema_is_set_up_once_per_version_across_processes(monkeypatch, tmp_path):
    import threading

    from app import platform_db

    def state():
        with main.connection() as db:
            return (
                db.execute("PRAGMA user_version").fetchone()[0],
                db.execute("SELECT MAX(version) FROM platform_migrations").fetchone()[
                    0
                ],
            )

    assert state() == (main.SCHEMA_VERSION, platform_db.LATEST)
    # A database v1.5.0 set up (no schema version), here one migration short.
    with main.connection() as db:
        db.execute("PRAGMA user_version=0")
        db.execute(
            "DELETE FROM platform_migrations WHERE version=?", (platform_db.LATEST,)
        )
    setups = []
    original = main.init_schema

    def counting(db):
        setups.append(threading.get_ident())
        original(db)

    monkeypatch.setattr(main, "init_schema", counting)
    # Web, workers and the receiver start together: each its own connection.
    barrier, errors = threading.Barrier(6), []

    def start():
        try:
            barrier.wait()
            with main.connection() as db:
                db.execute("SELECT COUNT(*) FROM settings").fetchone()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=start) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [] and len(setups) == 1
    assert state() == (main.SCHEMA_VERSION, platform_db.LATEST) and len(setups) == 1
    # A new database is set up by its first connection.
    monkeypatch.setattr(main, "DB", tmp_path / "fresh.sqlite3")
    with main.connection() as db:
        tables = {
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert {"settings", "alert_events", "diagnostic_tasks", "platform_skills"} <= tables
    assert len(setups) == 2


def test_schema_version_names_the_schema():
    """Fails when init_schema() or platform_db.migrate() changes the tables:
    bump main.SCHEMA_VERSION (only databases at another version are set up
    again) and record the new shape here."""
    import hashlib

    with main.connection() as db:
        tables = [
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite%' ORDER BY name"
            )
        ]
        shape = {
            table: [
                list(column[1:]) for column in db.execute(f"PRAGMA table_info({table})")
            ]
            for table in tables
        }
        shape["indexes"] = [
            list(row)
            for row in db.execute(
                "SELECT name,tbl_name FROM sqlite_master WHERE type='index' "
                "AND name NOT LIKE 'sqlite%' ORDER BY name"
            )
        ]
    digest = hashlib.sha256(json.dumps(shape, sort_keys=True).encode()).hexdigest()
    assert (main.SCHEMA_VERSION, digest[:16]) == (1, "591f9608ce793306")


def test_an_authenticated_request_reads_the_database_once(monkeypatch):
    import time

    from fastapi import HTTPException
    from fastapi.testclient import TestClient

    from app import feishu_auth
    from app.security import rbac

    raw, csrf = "session-operator", "csrf-operator"
    with main.connection() as db:
        feishu_auth._tables(db)
        db.execute("INSERT INTO members VALUES ('ou_operator','operator',1)")
        db.execute(
            "INSERT INTO admin_sessions VALUES (?,?,?,?,?)",
            (feishu_auth._hash(raw), "ou_operator", "Op", csrf, int(time.time()) + 60),
        )
    client = TestClient(
        main.app, headers={"x-csrf-token": csrf}, cookies={feishu_auth.COOKIE: raw}
    )
    runs = traced(monkeypatch)
    me = client.get("/api/v1/auth/me").json()
    assert (me["role"], len(runs)) == ("operator", 1)  # 5 before (7 with a check)
    assert "reports.read" in me["permissions"] and "*" not in me["permissions"]
    # Permission checks use the role read with the session.
    request = SimpleNamespace(
        cookies={feishu_auth.COOKIE: raw},
        headers={},
        method="GET",
        url=SimpleNamespace(path="/api/v1/qa-events"),
    )
    runs.clear()
    assert rbac.require("reports.read")(request)["open_id"] == "ou_operator"
    assert main.require_admin(request)["role"] == "operator"
    assert len(runs) == 2
    with pytest.raises(HTTPException) as denied:
        rbac.require("settings.manage")(request)
    assert denied.value.status_code == 403
    # Writes still need the CSRF token; a member disabled meanwhile is out.
    with pytest.raises(HTTPException) as forged:
        rbac.require("reports.read")(
            SimpleNamespace(**{**vars(request), "method": "POST"})
        )
    assert forged.value.status_code == 403
    with main.connection() as db:
        db.execute("UPDATE members SET enabled=0 WHERE open_id='ou_operator'")
    with pytest.raises(HTTPException) as gone:
        rbac.require("reports.read")(request)
    assert gone.value.status_code == 401
    # The super admin and the opt-in legacy token carry their role too.
    assert rbac.role_for("ou_super") == "super_admin"
    legacy = SimpleNamespace(
        cookies={}, headers={"authorization": "Bearer test-admin"}, method="GET"
    )
    assert feishu_auth.authenticate(legacy)["permissions"] == ["*"]
