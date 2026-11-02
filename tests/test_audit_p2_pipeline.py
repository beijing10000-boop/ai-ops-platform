"""Regressions for the remaining P2 findings of the 2026-11 audit
(OPS-PIPE-04/05/11/13, OPS-WEB-03/06) and for the review of their fixes."""

import asyncio
import json
import re
import threading
import time
from types import SimpleNamespace

import httpx
import pytest

from app import conversation_context, feishu_client, main, qa_worker, worker
from app.alert_mute import action_signature
from app.orchestrator import tasks

TASK_ID = "0123456789abcdef0123456789abcdef"
REPLY = feishu_client.ROOT + "/im/v1/messages/{}/reply"


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


def analyses_run(monkeypatch, notify=True):
    """The model stand-in: the task ids it analysed. `notify`: also stand in
    for the Feishu delivery (False keeps it, for a test faking Feishu)."""
    ran = []

    async def analyze(event, task_id=None):
        ran.append(task_id)
        return {"cause": "内存不足", "action": ["重启 dsp-api"], "analysis": ""}

    async def delivered(card, event=None, **kwargs):
        pass

    monkeypatch.setattr(worker, "analyze", analyze)
    if notify:
        monkeypatch.setattr(worker, "notify", delivered)
    return ran


def reused_task(event_id):
    with main.connection() as db:
        return db.execute(
            "SELECT reused_task_id FROM alert_events WHERE event_id=? AND event_value='1'",
            (event_id,),
        ).fetchone()[0]


def cards_sent(monkeypatch):
    """Alert cards as the alert-worker sends them; analyses queue for real
    (rq_jobs) so their tasks are created as in production."""
    cards = []

    async def notify(card, event=None, **kwargs):
        cards.append(json.dumps(card, ensure_ascii=False))

    monkeypatch.setattr(worker, "notify", notify)
    return cards


def rq_jobs(monkeypatch):
    """RQ stand-in: (queue, function, args) of every job enqueued."""
    jobs = []

    class Queue:
        def __init__(self, name, connection=None):
            self.name = name

        def enqueue(self, func, *args, **kwargs):
            jobs.append((self.name, func, args))

    monkeypatch.setattr(worker, "Queue", Queue)
    monkeypatch.setattr(
        worker, "Job", SimpleNamespace(exists=lambda job_id, connection=None: True)
    )
    return jobs


def feishu(monkeypatch):
    """Feishu API stand-in: (method, url, body) of every call; a card sent to
    a group gets the message id om_<group>."""
    sent = []

    async def token(_client):
        return "fixture-token"

    async def request(_client, method, url, auth=None, **kwargs):
        body = kwargs.get("json") or {}
        sent.append((method, url, body))
        return {"data": {"message_id": "om_" + str(body.get("receive_id") or "reply")}}

    monkeypatch.setattr(feishu_client, "get_token", token)
    monkeypatch.setattr(feishu_client, "request", request)
    monkeypatch.setattr(conversation_context, "remember", lambda *a, **k: None)
    return sent


def click(event_id, message_id, trigger="66713", event_value="1"):
    """A click on the "🤖 AI分析" button of the alert card `message_id`."""
    from app.alert_actions import handle_analyze_action

    return handle_analyze_action(
        {
            "op": "analyze_alert",
            "event_id": event_id,
            "trigger_id": trigger,
            "event_value": event_value,
            "sig": action_signature(event_id, trigger, 0),
        },
        "ou_super",
        message_id,
        "oc_group",
    )


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
    # Both recovered: not run, and the later alert no longer says it waits.
    again = alert("772020", trigger="772020")
    store_alert(again)
    skipped = queued_task(again)
    follower = alert("772021", trigger="772020")
    store_alert(follower)
    assert asyncio.run(worker.handle_alert(follower))["reused_task_id"] == skipped
    recover(again)
    recover(follower)
    assert worker.process_alert_analysis(again, skipped)["reason"] == "AlertRecovered"
    assert ai_status("772021") == "cancelled"
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
    """Redis stand-in for the receiver's duplicate check and the queued-card
    hand-off (SET NX, SET ... GET, EXISTS), one lock as Redis is one thread."""

    def __init__(self):
        self.items = {}
        self.lock = threading.Lock()

    def set(self, key, value, nx=False, ex=None, get=False):
        with self.lock:
            old = self.items.get(key)
            if nx and old is not None:
                return None
            self.items[key] = value
            return old if get else True

    def exists(self, key):
        with self.lock:
            return int(key in self.items)

    def delete(self, key):
        with self.lock:
            self.items.pop(key, None)


def queued_card_threads():
    for thread in threading.enumerate():
        if thread.name == "feishu-queued-card":
            thread.join(10)


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
    store = ReceiverRedis()

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
    monkeypatch.setattr(conversation_context, "_client", lambda: store)
    # Two questions ahead (one being answered, one waiting).
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (2, 1))
    feishu_bot.on_message(chat_message("om_question", "<at id=all></at> 内存高吗"))
    queued_card_threads()
    [(target, title, text)] = replies
    assert (target, title) == ("om_question", "AI 排队中")
    assert "前面还有 2 个问题，轮到后自动开始分析" in text and "<at" not in text
    # The job is the one v1.5.0 queued; the card goes to its worker via Redis.
    [(args, kwargs)] = jobs
    assert args[2] == "om_question" and kwargs == {"job_timeout": -1}
    assert store.items["feishu-ai:queued-card:om_question"] == "om_queued"
    # Nothing ahead: it starts at once and the worker replies as before.
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (0, 1))
    feishu_bot.on_message(chat_message("om_next", "CPU 呢"))
    queued_card_threads()
    assert len(replies) == 1 and len(jobs) == 2
    # No qa-worker running: the question waits for one, and is told so.
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (0, 0))
    feishu_bot.on_message(chat_message("om_third", "磁盘呢"))
    queued_card_threads()
    assert "问答分析服务暂未运行" in replies[-1][2]
    # The question's worker takes the card over: it turns into its progress
    # card and then the answer.
    started, real_execute = [], qa_worker.execute

    async def execute(*args):
        started.append(args)

    monkeypatch.setattr(qa_worker, "execute", execute)
    qa_worker.process_question("oc_group", "内存高吗", "om_question", "ou_super")
    assert started[-1][-1] == "om_queued"
    # Taken once: a job run again does not take it a second time.
    qa_worker.process_question("oc_group", "内存高吗", "om_question", "ou_super")
    assert started[-1][-1] is None
    monkeypatch.setattr(qa_worker, "execute", real_execute)
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
    # 2: alert_events.reused_task_id and its index.
    assert (main.SCHEMA_VERSION, digest[:16]) == (2, "242f8f81c0ddfe23")


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


# OPS-WEB-06: builds resolve the same major; zoneinfo's data is declared.


def test_dependencies_stay_within_one_major_and_declare_tzdata():
    """An image build takes the newest version a range allows, so a range over
    two majors (rq and openai allowed 1.x and 2.x) lets builds differ; the
    v1.5.0 image resolved rq 2.12.0 and openai 2.54.0. zoneinfo needs tzdata
    in the slim image, where it came only through rq -> croniter -> dateutil."""
    from pathlib import Path

    text = (Path(__file__).parent.parent / "requirements.txt").read_text("utf-8")
    ranges = {}
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if line:
            name, low, high = re.fullmatch(
                r"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?>=([\d.]+)(?:,<(\d+))?", line
            ).groups()
            ranges[name.lower()] = (int(low.split(".")[0]), high and int(high))
    # Calendar-versioned time-zone data: a newer release only updates rules.
    assert ranges.pop("tzdata") == (2024, None)
    assert ranges["rq"] == ranges["openai"] == (2, 3)
    assert {
        name: (low, high) for name, (low, high) in ranges.items() if high != low + 1
    } == {}


# Review of the fixes above. Each test follows production's order: the
# webhook stores the alert row, later the alert-worker (handle_alert) sends
# the card and queues the analysis, the analysis worker
# (process_alert_analysis) takes it when the backlog reaches it.


def test_a_click_on_a_queued_automatic_analysis_gets_its_reply(monkeypatch):
    """The click joins the automatic analysis (one per alert at a time), which
    then runs as a click does: the alert recovering and the day's automatic
    budget running out meanwhile no longer cancel it."""
    feishu_on = {"feishu_enabled": "true", "feishu_alert_chat_ids": "oc_group"}
    settings(monkeypatch, ai_alert_reuse_hours="2", **feishu_on)
    sent, jobs = feishu(monkeypatch), rq_jobs(monkeypatch)
    event = alert("883001")
    store_alert(event)
    queued = asyncio.run(worker.handle_alert(event))
    task_id = queued["task_id"]
    assert queued["analysis_queued"] and [job[1] for job in jobs] == [
        "app.worker.process_alert_analysis"
    ]
    # The card the alert-worker sent to the group is om_oc_group.
    ok, message = click("883001", "om_oc_group")
    assert ok and message == "该告警的 AI 分析已在排队，结果将回复原告警消息"
    assert len(jobs) == 1 and tasks.get(task_id)["actor"] == "ou_super"
    # A second click finds it the first click's.
    assert click("883001", "om_oc_group") == (True, "正在分析中，请勿重复提交。")
    recover(event)
    assert asyncio.run(worker.handle_alert({**event, "event_value": "0"}))["notified"]
    settings(
        monkeypatch, ai_alert_reuse_hours="2", ai_daily_token_limit="1", **feishu_on
    )
    ran = analyses_run(monkeypatch, notify=False)
    sent.clear()
    assert worker.process_alert_analysis(event, task_id)["diagnosed"]
    assert ran == [task_id] and ai_status("883001") == "success"
    [(method, url, body)] = sent
    assert url == REPLY.format("om_oc_group") and "AI 分析结果" in body["content"]


def test_a_click_after_the_queue_check_cancelled_the_analysis_runs_its_own(
    monkeypatch,
):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards_sent(monkeypatch)
    jobs = rq_jobs(monkeypatch)
    ran = analyses_run(monkeypatch)
    event = alert("883101")
    store_alert(event)
    task_id = asyncio.run(worker.handle_alert(event))["task_id"]
    with main.connection() as db:
        db.execute(
            "INSERT INTO feishu_event_messages VALUES ('om_card','883101','1','oc_group','problem')"
        )
    recover(event)
    claim = worker.claim_queued

    def backlog_first(task, actor):
        # The analysis worker reaches the task between the click finding it
        # and taking it over: the alert has recovered, so it is cancelled.
        assert worker.process_alert_analysis(event, task)["reason"] == "AlertRecovered"
        return claim(task, actor)

    monkeypatch.setattr(worker, "claim_queued", backlog_first)
    ok, message = click("883101", "om_card")
    assert ok and message == "已提交 AI 分析，结果将回复原告警消息"
    name, func, args = jobs[-1]
    assert (name, func) == ("ai-alert-manual", "app.worker.process_manual_analysis")
    assert args[1:3] == ("om_card", "oc_group") and args[3] != task_id
    assert ran == [] and tasks.get(args[3])["actor"] == "ou_super"


def test_a_later_alert_keeps_the_analysis_it_waits_for_whenever_its_row_came(
    monkeypatch,
):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards = cards_sent(monkeypatch)
    rq_jobs(monkeypatch)
    first, follower = alert("880001"), alert("880002")
    # One burst: the webhook stores both rows before the alert-worker gets to
    # the first and creates its analysis.
    store_alert(first)
    store_alert(follower)
    with main.connection() as db:
        db.execute("UPDATE alert_events SET received_at=datetime('now','-20 seconds')")
    task_id = asyncio.run(worker.handle_alert(first))["task_id"]
    result = asyncio.run(worker.handle_alert(follower))
    assert result["reused_task_id"] == task_id and result["reused_in_progress"]
    assert "结果将回复在该次告警的卡片下" in cards[-1]
    assert reused_task("880002") == task_id and ai_status("880002") == "reused"
    # The first recovers before the backlog reaches it; the later one has not.
    recover(first)
    ran = analyses_run(monkeypatch)
    assert worker.process_alert_analysis(first, task_id)["diagnosed"]
    assert ran == [task_id] and ai_status("880002") == "reused"


def test_an_alert_whose_analysis_ends_before_it_waits_gets_its_own(monkeypatch):
    """The analysis is cancelled between recent_analysis() picking it and the
    alert recording that it waits: the card must not promise its result."""
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards = cards_sent(monkeypatch)
    jobs = rq_jobs(monkeypatch)
    first = alert("880101")
    store_alert(first)
    task_id = asyncio.run(worker.handle_alert(first))["task_id"]
    pick = worker.recent_analysis

    def then_cancelled(event):
        found = pick(event)
        assert found["task_id"] == task_id and found["in_progress"]
        recover(first)
        assert worker.process_alert_analysis(first, task_id)["skipped"]
        return found

    monkeypatch.setattr(worker, "recent_analysis", then_cancelled)
    follower = alert("880102")
    store_alert(follower)
    result = asyncio.run(worker.handle_alert(follower))
    assert result["analysis_queued"] and "reused_task_id" not in result
    assert jobs[-1][2][0]["event_id"] == "880102" and len(cards) == 2
    assert "结果将回复" not in cards[-1] and reused_task("880102") is None
    assert tasks.get(task_id)["error_type"] == "AlertRecovered"


def test_the_queue_limit_counts_from_the_latest_alert_waiting(monkeypatch):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards_sent(monkeypatch)
    rq_jobs(monkeypatch)

    def queued_for(task_id, minutes):
        update_task(task_id, f"created_at=datetime('now','-{minutes} minutes')")

    def received(event_id, minutes):
        with main.connection() as db:
            db.execute(
                "UPDATE alert_events SET received_at=datetime('now',?) WHERE event_id=?",
                (f"-{minutes} minutes", event_id),
            )

    first = alert("881001")
    store_alert(first)
    waited_for = asyncio.run(worker.handle_alert(first))["task_id"]
    # The backlog grows; 90 minutes on, the trigger fires again and waits.
    queued_for(waited_for, 90)
    received("881001", 90)
    follower = alert("881002")
    store_alert(follower)
    assert asyncio.run(worker.handle_alert(follower))["reused_task_id"] == waited_for
    # 31 minutes later the backlog reaches it: over the 2 hours itself, but
    # the alert waiting for it came 31 minutes ago.
    queued_for(waited_for, 121)
    received("881002", 31)
    ran = analyses_run(monkeypatch)
    assert worker.process_alert_analysis(first, waited_for)["diagnosed"]
    assert ran == [waited_for]
    # The latest alert waiting is over the limit too: cancelled, and the alert
    # no longer shows "复用近期分析".
    first = alert("881010", trigger="881010")
    store_alert(first)
    task_id = asyncio.run(worker.handle_alert(first))["task_id"]
    follower = alert("881011", trigger="881010")
    store_alert(follower)
    assert asyncio.run(worker.handle_alert(follower))["reused_task_id"] == task_id
    queued_for(task_id, 200)
    received("881010", 200)
    received("881011", 130)
    result = worker.process_alert_analysis(first, task_id)
    assert result["reason"] == "QueueExpired" and ran == [waited_for]
    message = tasks.get(task_id)["report"]["message"]
    assert re.search(r"排队 20\d 分钟仍未开始", message)
    assert "后续告警最近一条也已超过" in message
    assert ai_status("881010") == ai_status("881011") == "cancelled"
    # A later alert that recovered does not hold it either.
    first = alert("881020", trigger="881020")
    store_alert(first)
    task_id = asyncio.run(worker.handle_alert(first))["task_id"]
    follower = alert("881021", trigger="881020")
    store_alert(follower)
    asyncio.run(worker.handle_alert(follower))
    recover(follower)
    update_task(task_id, "created_at=datetime('now','-130 minutes')")
    assert worker.process_alert_analysis(first, task_id)["reason"] == "QueueExpired"


def test_only_automatic_analyses_in_progress_are_waited_for(monkeypatch):
    """A Web diagnosis or a click's analysis of an earlier alert never replies
    under that alert's card for the later one; a finished one is still reused
    as in v1.5.0 (its card links the report, nothing is promised)."""
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards, jobs = cards_sent(monkeypatch), rq_jobs(monkeypatch)
    first = alert("882001")
    store_alert(first)
    web, created = tasks.create(
        {"event": first, "question": "看看磁盘"},
        source="web",
        actor="ou_operator",
        event_id="882001",
        diagnostic_type="disk",
        profile="quick",
    )
    assert created
    follower = alert("882002")
    store_alert(follower)
    result = asyncio.run(worker.handle_alert(follower))
    assert "reused_task_id" not in result and result["analysis_queued"]
    assert [job[2][0]["event_id"] for job in jobs] == ["882002"]
    assert "结果将回复在该次告警的卡片下" not in cards[-1]
    # A click on the earlier alert's card is told where that result is.
    with main.connection() as db:
        db.execute(
            "INSERT INTO feishu_event_messages VALUES ('om_card','882001','1','oc_group','problem')"
        )
    ok, message = click("882001", "om_card")
    assert not ok and "Web 诊断" in message and len(jobs) == 1
    assert tasks.get(web["task_id"])["actor"] == "ou_operator"
    # A click's analysis in progress is not waited for either.
    clicked = alert("882010", trigger="882010")
    store_alert(clicked)
    queued_task(clicked, actor="ou_super")
    assert worker.recent_analysis(alert("882011", trigger="882010")) is None
    # Finished, the Web diagnosis is reused.
    tasks.finish(web["task_id"], {"answer": "磁盘正常"})
    again = alert("882003")
    store_alert(again)
    result = asyncio.run(worker.handle_alert(again))
    assert result["reused_task_id"] == web["task_id"]
    assert "reused_in_progress" not in result and "已完成 AI 分析" in cards[-1]


def test_alerts_waiting_for_an_analysis_that_ended_without_a_result_say_so(
    monkeypatch,
):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards_sent(monkeypatch)
    rq_jobs(monkeypatch)
    pairs = {}
    for trigger in ("884010", "884020", "884030", "884040"):
        first, follower = (
            alert(trigger, trigger=trigger),
            alert(str(int(trigger) + 1), trigger=trigger),
        )
        store_alert(first)
        task_id = asyncio.run(worker.handle_alert(first))["task_id"]
        store_alert(follower)
        assert asyncio.run(worker.handle_alert(follower))["reused_task_id"] == task_id
        pairs[trigger] = (first, task_id, follower["event_id"])
    # The model failed.
    first, task_id, waiting = pairs["884010"]

    async def broken(event, task_id=None):
        raise RuntimeError("model offline")

    monkeypatch.setattr(worker, "analyze", broken)
    assert worker.process_alert_analysis(first, task_id)["ai_failed"]
    assert ai_status(waiting) == "failed"
    # Cancelled from the Web while queued: its job finds it cancelled.
    first, task_id, waiting = pairs["884020"]
    update_task(task_id, "status='cancelled'")
    assert worker.process_alert_analysis(first, task_id)["skipped"]
    assert ai_status(waiting) == "cancelled"
    # Over the daily budget when it starts (the day used 5,000 Token).
    update_task(pairs["884010"][1], "token_total=5000")
    first, task_id, waiting = pairs["884030"]
    settings(monkeypatch, ai_alert_reuse_hours="2", ai_daily_token_limit="5000")
    assert worker.process_alert_analysis(first, task_id)["reason"] == "DailyBudget"
    assert ai_status(waiting) == "skipped_budget"
    # Its job lost (reconcile: QueueLost): the periodic sync catches it.
    first, task_id, waiting = pairs["884040"]
    update_task(task_id, "status='failed',error_type='QueueLost'")
    worker.sync_ai_states()
    assert ai_status(waiting) == "failed"


def test_invalid_saved_budgets_do_not_stop_the_alert_card(monkeypatch):
    settings(monkeypatch, ai_alert_reuse_hours="2")
    cards, queued = capture(monkeypatch)
    first = alert("885001")
    store_alert(first)
    task_id = queued_task(first)
    with main.connection() as db:
        db.execute(
            "INSERT INTO settings VALUES ('ai_profile_budgets','{\"turbo\": {}}',0)"
        )
    with pytest.raises(Exception):
        tasks.stall_seconds()
    assert worker.stalled_after() == 600
    follower = alert("885002")
    store_alert(follower)
    assert asyncio.run(worker.handle_alert(follower))["reused_task_id"] == task_id
    assert len(cards) == 1


def test_the_receiver_never_waits_for_feishu(monkeypatch):
    """lark-oapi runs callbacks on its WebSocket event loop: while one waits,
    no other message or card button (3 s limit) is handled. The question is
    queued at once; the "AI 排队中" card follows from a thread."""
    from app import feishu_bot

    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('allowed_chat_ids','oc_group',0)")
    store, jobs, replies, updates = ReceiverRedis(), [], [], []
    inside, release = threading.Event(), threading.Event()

    async def reply(message_id, title, text, template="blue", link=None):
        # Whether the question was queued before its card was asked for.
        replies.append((message_id, title, message_id in jobs))
        inside.set()
        release.wait(30)  # Feishu answers when the test lets it
        return "om_card_" + message_id

    def sending():
        return any(
            thread.name == "feishu-queued-card" and thread.is_alive()
            for thread in threading.enumerate()
        )

    async def update(message_id, title, text, template="green", link=None):
        updates.append((message_id, title, template))

    class Jobs:
        def enqueue(self, func, *args, **kwargs):
            jobs.append(args[2])

    monkeypatch.setattr(feishu_client, "reply_card", reply)
    monkeypatch.setattr(feishu_client, "update_card", update)
    monkeypatch.setattr(feishu_bot, "queue", Jobs())
    monkeypatch.setattr(feishu_bot, "redis", ReceiverRedis())
    monkeypatch.setattr(conversation_context, "_client", lambda: store)
    monkeypatch.setattr(feishu_bot, "questions_ahead", lambda: (3, 1))
    try:
        feishu_bot.on_message(chat_message("om_q1", "内存高吗"))
        # The callback has returned while Feishu is still sending the card.
        assert jobs == ["om_q1"] and inside.wait(30) and sending()
        release.set()
        queued_card_threads()
        assert replies == [("om_q1", "AI 排队中", True)]
        assert conversation_context.take_queued_card("om_q1") == "om_card_om_q1"
        replies.clear()
        # Its worker began the question while the card was on its way: it
        # replied on its own, so the late card says so, not "排队中".
        inside.clear()
        release.clear()
        feishu_bot.on_message(chat_message("om_q2", "CPU 呢"))
        assert inside.wait(30)
        assert conversation_context.take_queued_card("om_q2") is None
        release.set()
        queued_card_threads()
        assert replies == [("om_q2", "AI 排队中", True)]
        assert updates == [("om_card_om_q2", "AI 分析已开始", "grey")]
        replies.clear()
        # It began before the card was sent: no card at all.
        jobs_enqueue = Jobs.enqueue

        def taken_at_once(self, func, *args, **kwargs):
            jobs_enqueue(self, func, *args, **kwargs)
            conversation_context.take_queued_card(args[2])

        monkeypatch.setattr(Jobs, "enqueue", taken_at_once)
        feishu_bot.on_message(chat_message("om_q3", "磁盘呢"))
        queued_card_threads()
        assert jobs[-1] == "om_q3" and replies == [] and len(updates) == 1
    finally:
        release.set()
        queued_card_threads()


def test_the_tenant_token_is_fetched_once_until_it_expires(monkeypatch):
    monkeypatch.setattr(feishu_client, "_token", {})
    with main.connection() as db:
        db.execute("INSERT INTO settings VALUES ('lark_app_id','cli_fixture',0)")
        db.execute("INSERT INTO settings VALUES ('lark_app_secret','secret-1',0)")
    fetched, answers = [], []

    class Client:
        async def request(self, method, url, headers=None, **kwargs):
            if url.endswith("/tenant_access_token/internal"):
                fetched.append(kwargs["json"]["app_secret"])
                body = {"code": 0, "tenant_access_token": f"t-{len(fetched)}"}
                body.update(answers.pop(0) if answers else {"expire": 7200})
                return httpx.Response(
                    200, json=body, request=httpx.Request(method, url)
                )
            # Feishu refuses the token.
            return httpx.Response(
                400,
                json={"code": 99991663, "msg": "Invalid access token"},
                request=httpx.Request(method, url),
            )

    def token():
        return asyncio.run(feishu_client.get_token(Client()))

    assert token() == token() == "t-1" and fetched == ["secret-1"]
    # Renewed before Feishu's expiry.
    feishu_client._token["until"] = time.monotonic() - 1
    assert token() == "t-2" and token() == "t-2" and len(fetched) == 2
    # New credentials, new token.
    with main.connection() as db:
        db.execute("UPDATE settings SET value='secret-2' WHERE key='lark_app_secret'")
    assert token() == "t-3" and fetched[-1] == "secret-2"
    # A token Feishu refuses is dropped.
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(
            feishu_client.request(Client(), "GET", feishu_client.ROOT + "/x", "t-3")
        )
    assert token() == "t-4"
    # Without an expiry it is not kept.
    feishu_client.forget_token()
    answers.extend([{}, {}])
    assert token() == "t-5" and token() == "t-6"


def test_a_newer_database_is_left_as_it_is(monkeypatch):
    """After a rollback the database is newer than the code: it is not set
    up (or its version rewritten) again, let alone on every connection."""
    from app import platform_db

    newer = main.SCHEMA_VERSION + 1
    with main.connection() as db:
        db.execute(f"PRAGMA user_version={newer}")
        db.execute(
            "INSERT INTO platform_migrations(version) VALUES (?)",
            (platform_db.LATEST + 1,),
        )
    setups = []
    monkeypatch.setattr(main, "init_schema", setups.append)
    runs = traced(monkeypatch)
    assert main.read_setting("web_protocol") == "http"
    with main.connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == newer
    statements = [s.upper().replace(" ", "") for run in runs for s in run]
    assert setups == [] and len(runs) == 2
    assert not [s for s in statements if s.startswith(WRITES) or "USER_VERSION=" in s]
    # An older one is set up, once, and only ever raised to this version.
    with main.connection() as db:
        db.execute("PRAGMA user_version=1")
    for _ in range(2):
        with main.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
    assert len(setups) == 1 and version == main.SCHEMA_VERSION == 2
