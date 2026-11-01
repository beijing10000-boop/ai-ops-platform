"""Regressions for the 2026-11 pipeline audit (OPS-PIPE)."""

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from rq.exceptions import NoSuchJobError

from app import conversation_context, feishu_client, main, qa_worker, worker
from app.orchestrator import tasks
from app.orchestrator.budgets import PROFILES

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


def alert(event_id, **extra):
    return {
        "event_id": event_id,
        "event_value": "1",
        "severity": "4",
        "host_id": "10913",
        "trigger_id": event_id,
        "host_name": "db-test-01",
        "event_name": "Linux: High memory utilization",
        **extra,
    }


def store_alert(event, notify_status="queued"):
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_name,severity,"
            "notify_status,ai_status,event_json) VALUES (?,?,?,4,?,'pending',?)",
            (
                event["event_id"],
                event["event_value"],
                event["event_name"],
                notify_status,
                json.dumps(event),
            ),
        )


def column(event_id, name, event_value="1"):
    with main.connection() as db:
        return db.execute(
            "SELECT " + name + " FROM alert_events WHERE event_id=? AND event_value=?",
            (event_id, event_value),
        ).fetchone()[0]


def feishu(monkeypatch, failing=()):
    """Feishu API stand-in; groups in `failing` reject every message."""
    sent = []

    async def token(_client):
        return "fixture-token"

    async def request(_client, method, url, auth=None, **kwargs):
        body = kwargs.get("json") or {}
        if body.get("receive_id") in failing:
            raise RuntimeError("bot removed from the group")
        sent.append((method, url, body))
        return {"data": {"message_id": "om_" + str(body.get("receive_id") or "reply")}}

    monkeypatch.setattr(feishu_client, "get_token", token)
    monkeypatch.setattr(feishu_client, "request", request)
    return sent


def queue_recorder(monkeypatch):
    queued = []

    def enqueue(queue_name, func, event, *args, **kwargs):
        queued.append(event["event_id"])
        return {"task_id": "task-" + event["event_id"]}, True

    monkeypatch.setattr(worker, "enqueue_analysis", enqueue)
    return queued


class FakeRedis:
    def __init__(self):
        self.items = {}

    def set(self, key, value, ex=None):
        self.items[key] = value

    def get(self, key):
        return self.items.get(key)

    def delete(self, key):
        return int(self.items.pop(key, None) is not None)

    def scan_iter(self, pattern):
        return [key for key in self.items if key.startswith(pattern.rstrip("*"))]


# OPS-PIPE-01


def test_one_failing_group_still_delivers_queues_analysis_and_pairs_recovery(
    monkeypatch,
):
    settings(
        monkeypatch, feishu_enabled="true", feishu_alert_chat_ids="oc_good,oc_gone"
    )
    sent = feishu(monkeypatch, failing={"oc_gone"})
    queued = queue_recorder(monkeypatch)
    event = alert("990001")
    store_alert(event)
    result = asyncio.run(worker.handle_alert(event))
    assert result["analysis_queued"] and queued == ["990001"]
    assert column("990001", "notify_status") == "sent"
    with main.connection() as db:
        links = db.execute(
            "SELECT chat_id FROM alert_message_links WHERE event_id='990001'"
        ).fetchall()
    assert links == [("oc_good",)]
    sent.clear()
    recovery = {**event, "event_value": "0"}
    store_alert(recovery)
    assert asyncio.run(worker.handle_alert(recovery))["notified"] is True
    # The recovery replies where the problem card is; the other group is skipped.
    assert [url for _, url, _ in sent] == [REPLY.format("om_oc_good")]


def test_delivery_fails_only_when_no_group_got_the_card(monkeypatch):
    settings(
        monkeypatch, feishu_enabled="true", feishu_alert_chat_ids="oc_gone,oc_lost"
    )
    feishu(monkeypatch, failing={"oc_gone", "oc_lost"})
    queued = queue_recorder(monkeypatch)
    event = alert("990002")
    store_alert(event)
    with pytest.raises(RuntimeError, match="全部群发送失败"):
        asyncio.run(worker.handle_alert(event))
    assert column("990002", "notify_status") == "failed" and queued == []


def test_recovery_follows_delivered_problem_cards_recorded_failed_before(
    monkeypatch,
):
    settings(
        monkeypatch, feishu_enabled="true", feishu_alert_chat_ids="oc_good,oc_gone"
    )
    sent = feishu(monkeypatch)
    # Before v1.4.6 one failing group marked the whole problem "failed".
    event = alert("990003")
    store_alert(event, notify_status="failed")
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_message_links VALUES ('990003','oc_good','om_legacy')"
        )
    recovery = {**event, "event_value": "0"}
    store_alert(recovery)
    assert asyncio.run(worker.handle_alert(recovery))["notified"] is True
    assert [url for _, url, _ in sent] == [REPLY.format("om_legacy")]
    # Never delivered anywhere: still suppressed.
    silent = alert("990004")
    store_alert(silent, notify_status="failed")
    assert asyncio.run(worker.handle_alert({**silent, "event_value": "0"}))[
        "recovery_suppressed"
    ]


# OPS-PIPE-02


def test_daily_budget_counts_analyses_still_queued_or_running(monkeypatch):
    settings(monkeypatch, ai_daily_token_limit="50000")
    budget = PROFILES["standard"]["tokens"]
    first, _ = tasks.create({"event": {}}, source="alert", event_id="991001")
    second, _ = tasks.create({"event": {}}, source="alert", event_id="991002")
    tasks.start(second["task_id"])
    # Manual clicks are not counted, queued or not.
    tasks.create({"event": {}}, source="alert", event_id="991003", actor="ou_op")
    assert worker.daily_budget() == (2 * budget, 50000)
    # The analysis about to start counts finished and running ones besides itself.
    assert worker.daily_budget(first["task_id"]) == (budget, 50000)
    cards = []

    async def notify(card, event=None, **kwargs):
        cards.append(json.dumps(card, ensure_ascii=False))

    monkeypatch.setattr(worker, "notify", notify)
    queued = queue_recorder(monkeypatch)
    blocked = alert("991004")
    store_alert(blocked)
    result = asyncio.run(worker.handle_alert(blocked))
    assert result["budget_exhausted"] and queued == []
    assert "含进行中分析的预算" in cards[-1] and "达到每日上限 50,000" in cards[-1]
    assert column("991004", "ai_status") == "skipped_budget"


def test_queued_analysis_rechecks_the_budget_and_is_skipped_explicitly(
    monkeypatch,
):
    settings(monkeypatch, ai_daily_token_limit="10000")
    done, _ = tasks.create({"event": {}}, source="alert", event_id="992001")
    tasks.finish(
        done["task_id"],
        {},
        {"available": True, "input": 9000, "output": 3000, "total": 12000},
    )
    event = alert("992002")
    store_alert(event)
    waiting, _ = tasks.create({"event": event}, source="alert", event_id="992002")

    async def analyze(event, task_id=None):
        raise AssertionError("over the daily budget: no model call")

    monkeypatch.setattr(worker, "analyze", analyze)
    assert worker.process_alert_analysis(event, waiting["task_id"])["skipped"]
    task = tasks.get(waiting["task_id"])
    assert (task["status"], task["error_type"]) == ("cancelled", "DailyBudget")
    assert "每日上限" in task["report"]["message"]
    assert column("992002", "ai_status") == "skipped_budget"


def test_analyses_queued_together_do_not_block_each_other(monkeypatch):
    settings(monkeypatch, ai_daily_token_limit="40000")
    first = alert("992010")
    store_alert(first)
    one, _ = tasks.create({"event": first}, source="alert", event_id="992010")
    tasks.create({"event": {}}, source="alert", event_id="992011")
    ran = []

    async def analyze(event, task_id=None):
        ran.append(task_id)
        return {"cause": "内存不足", "action": ["重启 dsp-api"], "analysis": ""}

    async def notify(card, event=None, **kwargs):
        pass

    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(worker, "notify", notify)
    assert worker.process_alert_analysis(first, one["task_id"])["diagnosed"]
    assert ran == [one["task_id"]]


# OPS-PIPE-03


def test_reconcile_closes_what_a_killed_worker_left_without_rerunning(monkeypatch):
    import rq

    monkeypatch.setattr(conversation_context, "_client", lambda: FakeRedis())
    enqueued = []
    monkeypatch.setattr(rq.Queue, "enqueue", lambda *a, **k: enqueued.append(a))
    event = alert("993001")
    store_alert(event)
    lost, _ = tasks.create({"event": event}, source="alert", event_id="993001")
    tasks.start(lost["task_id"])
    ended, _ = tasks.create({}, event_id="993002")  # its job ran, never started it
    waiting, _ = tasks.create({}, event_id="993003")  # still in the queue
    fresh, _ = tasks.create({}, event_id="993004")  # just created
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET started_at=datetime('now','-30 minutes') "
            "WHERE task_id=?",
            (lost["task_id"],),
        )
        db.execute(
            "UPDATE diagnostic_tasks SET created_at=datetime('now','-20 minutes') "
            "WHERE task_id IN (?,?)",
            (ended["task_id"], waiting["task_id"]),
        )
        db.execute("UPDATE alert_events SET ai_status='running'")
    main.record_ai_question("feishu", "om_old", "CPU?", "running")
    main.record_ai_question("web", "fresh-question", "CPU?", "running")
    with main.connection() as db:
        db.execute(
            "UPDATE ai_questions SET created_at=datetime('now','-2 hours') "
            "WHERE request_id='om_old'"
        )
    states = {ended["task_id"]: "finished", waiting["task_id"]: "queued"}

    class Job:
        @staticmethod
        def fetch(job_id, connection=None):
            if job_id not in states:
                raise NoSuchJobError(job_id)
            return SimpleNamespace(get_status=lambda: states[job_id])

    monkeypatch.setattr(worker, "Job", Job)
    worker.reconcile(redis=object())
    status = {
        task["task_id"]: (task["status"], task["error_type"])
        for task in tasks.page(page_size=10)["items"]
    }
    assert status[lost["task_id"]] == ("failed", "WorkerLost")
    assert status[ended["task_id"]] == ("failed", "QueueLost")
    assert status[waiting["task_id"]] == ("queued", None)
    assert status[fresh["task_id"]] == ("queued", None)
    with main.connection() as db:
        questions = dict(
            db.execute(
                "SELECT request_id,status||'/'||COALESCE(error_type,'') FROM ai_questions"
            )
        )
    assert questions == {"om_old": "failed/WorkerLost", "fresh-question": "running/"}
    # A live worker sets the alert status right after its card; a lost one
    # takes its task's end state once that ended ten minutes ago.
    assert column("993001", "ai_status") == "running"
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET completed_at=datetime('now','-11 minutes') "
            "WHERE task_id=?",
            (lost["task_id"],),
        )
    worker.reconcile(redis=object())
    assert column("993001", "ai_status") == "failed"
    assert enqueued == []


def test_reconcile_never_stops_the_worker(monkeypatch, caplog):
    steps = []

    def broken(job_state=None):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(tasks, "reconcile", broken)
    monkeypatch.setattr(worker, "sync_ai_states", lambda: steps.append("sync"))
    monkeypatch.setattr(
        worker, "close_abandoned_progress", lambda: steps.append("progress")
    )
    with caplog.at_level(logging.ERROR, logger="app.worker"):
        worker.reconcile()
    assert steps == ["sync", "progress"] and "RECONCILE_FAILED" in caplog.text


def test_worker_maintenance_runs_the_reconcile(monkeypatch):
    calls = []
    monkeypatch.setattr(
        worker.Worker, "run_maintenance_tasks", lambda self: calls.append("rq")
    )
    monkeypatch.setattr(worker, "reconcile", lambda redis=None: calls.append(redis))
    maintained = object.__new__(worker.MaintainedWorker)
    maintained.connection = "rq-connection"
    maintained.run_maintenance_tasks()
    assert calls == ["rq", "rq-connection"]


def test_progress_cards_left_by_a_killed_worker_are_closed_once(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(conversation_context, "_client", lambda: fake)
    conversation_context.mark_pending("oc_group", "om_lost_qa", "qa")
    conversation_context.mark_pending("oc_group", "om_lost_alert")
    conversation_context.mark_pending("oc_group", "om_live", "qa")
    for reply_id in ("om_lost_qa", "om_lost_alert"):
        key = conversation_context.PROGRESS_PREFIX + reply_id
        record = json.loads(fake.items[key])
        fake.items[key] = json.dumps({**record, "at": record["at"] - 3600})
    updates = []

    async def update(message_id, title, text, template="green", link=None):
        updates.append((message_id, title, text, template))

    monkeypatch.setattr(feishu_client, "update_card", update)
    worker.close_abandoned_progress()
    worker.close_abandoned_progress()
    texts = {message_id: text for message_id, _, text, _ in updates}
    assert sorted(texts) == ["om_lost_alert", "om_lost_qa"]
    assert worker.QA_RETRY in texts["om_lost_qa"] and "qa-worker" in texts["om_lost_qa"]
    assert worker.RETRY in texts["om_lost_alert"]
    assert all(update[1] == "AI 分析中断" and update[3] == "red" for update in updates)
    assert not conversation_context.is_pending("oc_group", "om_lost_qa")
    assert conversation_context.is_pending("oc_group", "om_live")
    # A finished analysis takes its progress card off the record.
    conversation_context.clear_pending("oc_group", "om_live")
    assert not [key for key in fake.items if "progress" in key]


def test_an_analysis_failing_before_it_starts_frees_its_event(monkeypatch):
    settings(monkeypatch)  # no model configured
    event = alert("994001")
    store_alert(event)
    task, _ = tasks.create({"event": event}, source="alert", event_id="994001")
    assert asyncio.run(worker.handle_alert_analysis(event, task["task_id"]))[
        "ai_failed"
    ]
    assert tasks.get(task["task_id"])["status"] == "failed"
    assert tasks.create({"event": event}, source="alert", event_id="994001")[1]


# OPS-PIPE-06 / 07 / 09


MODEL = {
    "openai_base_url": "https://llm.example.com/v1",
    "openai_model": "fixture",
    "openai_api_key": "sk-fixture",
}


def qa_rig(monkeypatch, *, answer="", state="success", report=None, failure=None):
    """Run one Feishu question; returns (final cards, progress cards, records)."""
    settings(monkeypatch, **MODEL)
    task, _ = tasks.create({"question": "CPU"}, source="qa")
    tasks.finish(task["task_id"], {"answer": answer, **(report or {})}, status=state)
    cards, progress, records = [], [], []

    async def ask(question, context, return_usage=False, actor="system", **kwargs):
        if failure:
            raise failure
        return answer, {"available": False, "task_id": task["task_id"]}

    async def reply_card(message_id, title, body, template="blue"):
        progress.append((title, body))
        return "om_progress"

    async def update_card(message_id, title, body, template="green"):
        cards.append((title, body, template))

    for name, value in {
        "ask": ask,
        "reply_card": reply_card,
        "update_card": update_card,
        "record_ai_question": lambda *args, **kwargs: records.append(args[3]),
        "recall": lambda *args: None,
        "is_pending": lambda *args: False,
        "mark_pending": lambda *args: None,
        "clear_pending": lambda *args: None,
        "remember": lambda *args, **kwargs: None,
    }.items():
        monkeypatch.setattr(qa_worker, name, value)
    question = "<at id=all></at> 查一下 db-test-01 的内存"
    asyncio.run(qa_worker.execute("oc_group", question, "om_question"))
    return cards, progress, records


FALLBACK = (
    "AI 模型请求超时；模型未完成最终诊断。\n"
    "下列仅为已执行的工具及采集状态，不代表故障根因已经确认：\n"
    "- zabbix_mcp / history_get: success（返回 3 条记录）\n"
    "请在下方“证据与工具执行记录”核验具体数值、时间和错误；未采集到的指标不能推断为正常。"
)


def test_unfinished_chat_answer_says_why_and_what_to_do(monkeypatch):
    cards, progress, records = qa_rig(
        monkeypatch,
        answer=FALLBACK,
        state="partial",
        report={
            "limitations": [
                "工具 history_get 未取得完整证据（E3）：可用内存 16265428 kB",
                "主机未配置 Swap",
            ]
        },
    )
    [(title, body, color)] = cards
    assert (title, color) == ("AI 分析结果 · 部分完成", "orange")
    assert body.startswith(
        "AI 模型请求超时；模型未完成最终诊断。\n\n**处理建议**\n"
        "1. " + worker.QA_RETRY + "\n"
        "2. 反复超时时，在 系统配置 → AI 配置 调高「AI 单次请求超时」"
    )
    assert "请在下方" not in body and "history_get: success" not in body
    # The limitations read as the answer does: no ids, GiB, no Swap note.
    assert "- 工具 history_get 未取得完整证据：可用内存 15.51 GiB" in body
    assert "E3" not in body and "Swap" not in body
    assert "/#report/" + tasks.page()["items"][0]["task_id"] + ")" in body
    # The question echoed on the progress card cannot mention everyone.
    assert "<at" not in progress[0][1] and "＜at id=all>" in progress[0][1]
    assert records == ["running", "success"]


def test_failure_cards_say_what_to_do_next(monkeypatch):
    settings(monkeypatch)
    assert "AI 模型尚未配置" in worker.failure_text(RuntimeError("x"))
    assert "验证模型连接" in worker.failure_text(RuntimeError("x"))
    settings(monkeypatch, **MODEL)
    assert worker.failure_text(RuntimeError("x")) == (
        "分析失败，没有形成结论。\n\n**处理建议**\n1. 稍后" + worker.RETRY + "\n"
        "2. 持续失败时，在 系统配置 → AI 配置 点「验证模型连接」检查模型服务"
    )
    assert "1. 需要时" + worker.RETRY in worker.failure_text(tasks.Cancelled("x"))
    cards, _, records = qa_rig(monkeypatch, failure=RuntimeError("model down"))
    [(title, body, color)] = cards
    assert (title, color) == ("AI 分析失败", "red")
    assert "**处理建议**\n1. 稍后" + worker.QA_RETRY in body
    assert records == ["running", "failed"]
    # A manual alert analysis updates its progress card the same way.
    updates = []

    async def broken(event, task_id=None):
        raise RuntimeError("model down")

    async def reply(message_id, title, detail, link=None):
        return "om_progress"

    async def update(message_id, title, detail, template="green", link=None):
        updates.append((title, detail, template))

    monkeypatch.setattr(worker, "analyze", broken)
    monkeypatch.setattr(feishu_client, "reply_card", reply)
    monkeypatch.setattr(feishu_client, "update_card", update)
    for name in ("mark_pending", "clear_pending"):
        monkeypatch.setattr(conversation_context, name, lambda *args: None)
    with pytest.raises(RuntimeError):
        asyncio.run(
            worker.analyze_on_demand(alert("994010"), "om_card", "oc_group", "t")
        )
    assert updates == [("AI 分析失败", worker.failure_text(RuntimeError()), "red")]


def test_unfinished_card_conclusion_does_not_point_at_the_report(monkeypatch):
    settings(monkeypatch)
    text = worker.card_summary(
        {
            "analysis": "本次未形成完整结论，已保存实际采集证据。请查看诊断不足与预算。",
            "_unstructured": True,
            "_diagnostic_status": "partial",
        }
    )
    assert text == (
        "**诊断状态**  部分完成\n\n**诊断结论**\n本次未形成完整结论，已保存实际采集证据。"
        "\n\n**处理建议**\n1. 在 系统配置 → AI 配置 调高该分析模式的「最大轮次」\n"
        "2. " + worker.RETRY
    )


def test_feishu_sizes_are_gib_whatever_unit_the_model_wrote(monkeypatch):
    settings(monkeypatch)
    assert worker.card_text(
        "MemTotal 16265428 kB，磁盘 15.7 GB，内存512MiB，堆 2Gi，归档 1.5 TB；"
        "带宽 100 MB/s，4G 网络，-Xmx4g，速率 10 Mb"
    ) == (
        "MemTotal 15.51 GiB，磁盘 15.70 GiB，内存0.50 GiB，堆 2.00 GiB，"
        "归档 1536.00 GiB；带宽 100 MB/s，4G 网络，-Xmx4g，速率 10 Mb"
    )


def test_only_clauses_that_just_advise_or_miss_swap_are_dropped(monkeypatch):
    settings(monkeypatch)
    info = {
        "cause": "内存使用率 98%（E2），且未配置 Swap。",
        "action": ["建议配置 2 GB Swap 作为缓冲", "重启 dsp-api 释放内存"],
        "_diagnostic_status": "success",
    }
    assert worker.card_summary(info) == (
        "**诊断结论**\n内存使用率 98%。\n\n**处理建议**\n1. 重启 dsp-api 释放内存"
    )
    for kept in ("内存不足且未配置 Swap，导致 OOM。", "Swap 使用率 0%"):
        assert worker.card_text(kept) == kept
    assert (
        worker.without_swap_notes(
            "- 内存：98%\n- Swap：未启用（总量 0 B）\n- 磁盘：40%"
        )
        == "- 内存：98%\n- 磁盘：40%"
    )


def test_model_tool_and_alert_text_cannot_mention_everyone_or_link_out(monkeypatch):
    settings(monkeypatch)
    report = "http://ops.example.com:8088/#report/" + TASK_ID
    card = worker.card_summary(
        {
            "cause": "<at id=all></at> 请立即处理，参考[运维手册](https://phish.example/login)",
            "action": [
                "<font color='red'>重启</font> dsp-api",
                f"查看[报告]({report})",
            ],
        }
    )
    assert "<at" not in card and "<font" not in card and "phish.example" not in card
    assert "参考运维手册" in card and f"[报告]({report})" in card
    assert worker.lark_safe("&lt;at id=all&gt;&lt;/at&gt;").startswith("＜at")
    event = alert(
        "996001", latest_value="ERROR <at id=all></at> [x](https://bad.example)"
    )
    body = worker.make_card(event)["elements"][0]["text"]["content"]
    assert "<at" not in body and "bad.example" not in body
    # The platform's own mention of the muting operator is kept.
    muted = worker.make_card(
        event,
        mute_info={"operator": "<at id=ou_admin></at>", "duration": "1 小时"},
    )
    assert "<at id=ou_admin></at>" in muted["elements"][-1]["text"]["content"]


# OPS-PIPE-08


def test_json_answer_with_other_field_names_still_fills_the_card(monkeypatch):
    from app import mcp_runtime

    settings(monkeypatch, **MODEL)
    answers = iter(
        [
            json.dumps(
                {
                    "conclusion": "dsp-api 堆内存占满（E2）",
                    "suggestions": ["调低 -Xmx", "重启 dsp-api"],
                },
                ensure_ascii=False,
            ),
            '{"result": "内存不足"}',
        ]
    )

    async def run(*args, **kwargs):
        return next(answers), {"available": False}

    monkeypatch.setattr(mcp_runtime, "run", run)
    info = asyncio.run(worker.analyze(alert("995001")))
    assert worker.card_summary(info) == (
        "**诊断结论**\ndsp-api 堆内存占满\n\n**处理建议**\n1. 调低 -Xmx\n2. 重启 dsp-api"
    )
    other = asyncio.run(worker.analyze(alert("995002")))
    assert other["_unstructured"] and "内存不足" in worker.card_summary(other)


# OPS-PIPE-10


def test_automatic_analysis_failure_logs_its_traceback(monkeypatch, caplog):
    async def broken(event, task_id=None):
        raise ValueError("unexpected payload from the gateway")

    monkeypatch.setattr(worker, "analyze", broken)
    with caplog.at_level(logging.ERROR, logger="app.worker"):
        result = asyncio.run(worker.handle_alert_analysis(alert("997001")))
    assert result["ai_failed"]
    [record] = [r for r in caplog.records if "ALERT_ANALYZE_FAILED" in r.getMessage()]
    assert record.exc_info and "unexpected payload from the gateway" in caplog.text
