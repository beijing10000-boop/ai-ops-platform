import asyncio

from app import worker


def configure_frontend(monkeypatch):
    original = worker.read_setting
    monkeypatch.setattr(
        worker,
        "read_setting",
        lambda key: (
            "https://zabbix.example.com"
            if key == "zabbix_frontend_url"
            else original(key)
        ),
    )


def test_alert_output_contract_remains_program_controlled():
    value = worker.alert_instructions()
    assert "host_groups,cause,action,analysis,human_required" in value
    assert "完整中文结论" in value
    assert "先查询 Zabbix" not in value


def test_feishu_card_shows_conclusion_and_actions_without_evidence_ids():
    info = {
        "cause": "每核 5 分钟负载 1.65（E2）超过阈值 1.5，CPU 利用率 33.57%（E5、E6）；负载来自 postgres 周期性任务 (E4)。",
        "action": "1. 核对 postgres 定时任务（E4）\n2. 评估是否扩容 CPU，参考 E3",
        "analysis": "证据之间的关联：E2 与 E4 时间吻合。",
        "human_required": True,
        "_report_answer": "完整报告……\n\n证据核对\n- E2 SSH MCP",
        "_limitations": ["工具 trend_get 未取得完整证据"],
        "_diagnostic_status": "partial",
    }
    assert worker.card_summary(info) == (
        "**诊断状态**  部分完成\n**诊断结论**\n"
        "每核 5 分钟负载 1.65超过阈值 1.5，CPU 利用率 33.57%；负载来自 postgres 周期性任务。\n\n"
        "**处理建议**（需人工处理）\n1. 核对 postgres 定时任务\n2. 评估是否扩容 CPU，参考"
    )
    # Hardware model numbers are not evidence references.
    assert (
        worker.without_evidence_ids("Xeon E5-2680 上 E2 的值") == "Xeon E5-2680 上 的值"
    )
    clean = {
        "cause": "磁盘将满",
        "action": ["清理日志"],
        "_diagnostic_status": "success",
    }
    assert (
        worker.card_summary(clean)
        == "**诊断结论**\n磁盘将满\n\n**处理建议**\n1. 清理日志"
    )
    long = {
        "cause": "负载来自周期性任务，建议核对。" * 20,
        "action": [f"建议 {n}" for n in range(1, 9)],
        "_diagnostic_status": "success",
    }
    text = worker.card_summary(long)
    # The conclusion is cut at a sentence end within 200 characters.
    assert (
        text.split("\n")[1]
        == "负载来自周期性任务，建议核对。" * 13 + "（详见完整报告）"
    )
    assert "6. 建议 6\n其余建议见完整诊断报告。" in text and "建议 7" not in text
    # Body text stays within 300 characters: actions that do not fit are dropped.
    step = "核对定时任务并记录执行时长，必要时调整执行窗口以避开业务高峰。"
    text = worker.card_summary(
        {
            "cause": "负载偏高。" * 30,
            "action": [step] * 4,
            "_diagnostic_status": "success",
        }
    )
    assert "3. " + step in text and "4. " + step not in text
    assert text.endswith("其余建议见完整诊断报告。") and len(text) <= 300
    assert worker.clipped("结论" * 120, 200) == "结论" * 99 + "结…"
    # Model-error fallbacks are plain text: the first line says why.
    partial = {
        "cause": "分析结果需要人工复核",
        "action": "请检查告警相关指标及服务日志",
        "analysis": "AI 模型请求超时；模型未完成最终诊断。\n下列仅为已执行的工具及采集状态…",
        "human_required": True,
        "_unstructured": True,
        "_diagnostic_status": "partial",
    }
    text = worker.card_summary(partial)
    assert text.startswith(
        "**诊断状态**  部分完成\n**诊断结论**\nAI 模型请求超时；模型未完成最终诊断。\n"
    )
    assert "下列仅为" not in text and "分析结果需要人工复核" not in text


def test_report_links_open_inside_the_feishu_client():
    url = "http://192.0.2.10:8088/#report/0123456789abcdef0123456789abcdef"
    assert worker.in_feishu(url) == (
        "https://applink.feishu.cn/client/web_url/open?mode=window&url="
        "http%3A%2F%2F192.0.2.10%3A8088%2F%23report%2F0123456789abcdef0123456789abcdef"
    )


def test_full_report_button_is_signed_and_the_worker_replies_with_the_whole_report(
    monkeypatch, tmp_path
):
    from unittest.mock import AsyncMock
    from app import feishu_client, main
    from app.orchestrator import tasks

    monkeypatch.setenv("APP_ENCRYPTION_KEY", "unit-test-secret")
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    monkeypatch.setattr(
        worker,
        "cfg",
        lambda key: {"web_protocol": "http", "web_public_host": "ops.example.com"}.get(
            key, ""
        ),
    )
    task_id = "0123456789abcdef0123456789abcdef"
    button = worker.report_button({"_task_id": task_id})
    assert button["value"] == {
        "op": "full_report",
        "task_id": task_id,
        "sig": worker.report_signature(task_id),
    }
    assert worker.report_button({"_task_id": "not-a-task"}) is None
    card = worker.make_card(
        {"event_id": "1", "severity": "4", "event_value": "1"},
        {"cause": "负载高", "_task_id": task_id},
        analysis=True,
    )
    buttons = [
        b for e in card["elements"] if e["tag"] == "action" for b in e["actions"]
    ]
    assert [b["value"]["op"] if "value" in b else "url" for b in buttons] == [
        "full_report",
        "url",
    ]
    # The worker job posts what the Web report page shows, as a reply to the card.
    task, _ = tasks.create({"question": "q"}, source="qa")
    tasks.start(task["task_id"])
    tasks.finish(
        task["task_id"],
        {"answer": "完整结论\n\n证据核对\n- E2 SSH MCP", "limitations": ["缺口 A"]},
        {
            "input": 10,
            "output": 5,
            "total": 15,
            "available": True,
            "profile": "standard",
        },
        "partial",
        duration_ms=1234,
    )
    sent = AsyncMock(return_value="om_reply")
    monkeypatch.setattr(feishu_client, "reply_card", sent)
    assert (
        asyncio.run(worker.send_full_report(task["task_id"], "om_card")) == "om_reply"
    )
    (message_id, title, text), _ = sent.call_args
    assert message_id == "om_card" and title == "完整诊断报告"
    assert "完整结论" in text and "E2 SSH MCP" in text and "缺口 A" in text
    assert "**诊断状态**  部分完成" in text
    assert "本轮 Token 消耗：15（输入 10 / 输出 5） · 分析模式：标准分析" in text


def test_card_keeps_complete_report_without_fixed_character_truncation():
    info = {
        "cause": "根因待确认",
        "action": "核查目录",
        "analysis": "证据。" * 70 + "末尾关键证据",
        "human_required": True,
    }
    summary = worker.analysis_summary(info)
    assert "末尾关键证据" in summary and "摘要已省略" not in summary
    assert "需人工核验：是" not in summary
    info["analysis"] *= 5
    summary = worker.analysis_summary(info)
    assert len(summary) > 500
    assert info["analysis"] in summary
    assert "摘要已省略部分内容" not in summary


class FakeQueue:
    jobs = []

    def __init__(self, name, connection=None):
        self.name = name

    def enqueue(self, func, *args, **kwargs):
        self.jobs.append((self.name, func, args, kwargs))


def test_alert_notifies_then_queues_analysis_without_running_the_model(monkeypatch):
    sent, queued = [], []

    async def notify(card, event=None, **kwargs):
        sent.append(card)

    async def analyze(event, task_id=None):
        raise AssertionError("the notification job must not wait for the model")

    def enqueue(queue_name, func, event, *args, **kwargs):
        queued.append((queue_name, func, event["event_id"]))
        return {"task_id": "task-" + event["event_id"]}, True

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(worker, "enqueue_analysis", enqueue)
    monkeypatch.setattr(
        worker, "cfg", lambda key: "4" if key == "ai_min_severity" else ""
    )
    low = asyncio.run(
        worker.handle_alert({"event_id": "low", "severity": "2", "event_value": "1"})
    )
    assert low["ai_skipped"] is True
    assert len(sent) == 1 and queued == []
    high = asyncio.run(
        worker.handle_alert({"event_id": "high", "severity": "4", "event_value": "1"})
    )
    assert high["analysis_queued"] is True and high["diagnosed"] is False
    assert high["task_id"] == "task-high"
    assert len(sent) == 2
    assert queued == [
        ("ai-alert-analysis", "app.worker.process_alert_analysis", "high")
    ]
    recovered = asyncio.run(
        worker.handle_alert(
            {"event_id": "recovered", "severity": "5", "event_value": "0"}
        )
    )
    assert recovered["ai_skipped"] is True
    assert len(sent) == 2 and len(queued) == 1
    assert recovered["recovery_suppressed"] is True


def test_queue_failure_does_not_block_initial_alert(monkeypatch):
    sent = []

    async def notify(card, event=None, **kwargs):
        sent.append(card)

    def down(*args, **kwargs):
        raise ConnectionError("redis offline")

    monkeypatch.setattr(
        worker, "cfg", lambda key: "4" if key == "ai_min_severity" else ""
    )
    monkeypatch.setattr(worker, "enqueue_analysis", down)
    monkeypatch.setattr(worker, "notify", notify)
    result = asyncio.run(
        worker.handle_alert({"event_id": "12345", "severity": "4", "event_value": "1"})
    )
    assert result["ai_failed"] is True and result["notified"] is True
    assert len(sent) == 1


def test_alert_analysis_job_reports_into_the_original_alert(monkeypatch):
    sent, seen = [], []

    async def notify(card, event=None, **kwargs):
        sent.append(kwargs.get("analysis_info"))

    async def analyze(event, task_id=None):
        seen.append(task_id)
        return {"cause": "负载偏高", "action": "核对进程", "analysis": "证据"}

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(worker, "analyze", analyze)
    result = asyncio.run(
        worker.handle_alert_analysis(
            {"event_id": "770010", "severity": "4", "event_value": "1"}, "task-1"
        )
    )
    assert result["diagnosed"] is True and seen == ["task-1"]
    assert sent[0]["cause"] == "负载偏高"


def test_model_failure_in_analysis_job_sends_no_extra_card(monkeypatch):
    sent = []

    async def notify(card, event=None, **kwargs):
        sent.append(card)

    async def broken(event, task_id=None):
        raise RuntimeError("model offline")

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(worker, "analyze", broken)
    result = asyncio.run(
        worker.handle_alert_analysis(
            {"event_id": "770011", "severity": "4", "event_value": "1"}, "task-2"
        )
    )
    assert result["ai_failed"] is True and sent == []


def test_jobs_for_tasks_cancelled_while_queued_are_skipped(monkeypatch):
    from app.main import connection
    from app.orchestrator import tasks

    async def analyze(event, task_id=None):
        raise AssertionError("a cancelled task must not reach the model")

    async def reply(*args, **kwargs):
        raise AssertionError("a cancelled task must not post a progress card")

    from app import feishu_client

    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(feishu_client, "reply_card", reply)
    for event_id, run in (
        (
            "770030",
            lambda event, task_id: worker.process_alert_analysis(event, task_id),
        ),
        (
            "770031",
            lambda event, task_id: worker.process_manual_analysis(
                event, "om_card", "oc_group", task_id
            ),
        ),
    ):
        event = {"event_id": event_id, "event_value": "1", "severity": "4"}
        with connection() as db:
            db.execute(
                "INSERT INTO alert_events(event_id,event_value,severity,ai_status) VALUES (?,'1',4,'pending')",
                (event_id,),
            )
        task, _ = tasks.create({"event": event}, source="alert", event_id=event_id)
        with connection() as db:
            db.execute(
                "UPDATE diagnostic_tasks SET status='cancelled' WHERE task_id=?",
                (task["task_id"],),
            )
        assert run(event, task["task_id"])["skipped"] is True
        with connection() as db:
            assert (
                db.execute(
                    "SELECT ai_status FROM alert_events WHERE event_id=?", (event_id,)
                ).fetchone()[0]
                == "cancelled"
            )


def test_enqueue_creates_the_queued_task_first_and_refuses_duplicates(monkeypatch):
    from types import SimpleNamespace
    import pytest
    from app.orchestrator import tasks

    FakeQueue.jobs = []
    lost = set()
    monkeypatch.setattr(worker, "Queue", FakeQueue)
    monkeypatch.setattr(
        worker,
        "Job",
        SimpleNamespace(exists=lambda job_id, connection=None: job_id not in lost),
    )
    event = {
        "event_id": "770020",
        "event_value": "1",
        "severity": "4",
        "event_name": "Linux: Load average is too high",
        "host_id": "10913",
    }
    task, created = worker.enqueue_analysis(
        "ai-alert-manual", "app.worker.process_manual_analysis", event, "om_1", "oc_1"
    )
    assert created and tasks.get(task["task_id"])["status"] == "queued"
    assert tasks.get(task["task_id"], private=True)["request"]["event"] == event
    name, func, args, kwargs = FakeQueue.jobs[0]
    assert (name, func) == ("ai-alert-manual", "app.worker.process_manual_analysis")
    assert args == (event, "om_1", "oc_1", task["task_id"])
    assert kwargs["job_id"] == task["task_id"] and kwargs["job_timeout"] == -1
    again, created = worker.enqueue_analysis(
        "ai-alert-manual", "app.worker.process_manual_analysis", event, "om_1", "oc_1"
    )
    assert not created and again["task_id"] == task["task_id"]
    assert len(FakeQueue.jobs) == 1
    # A queued task whose job vanished must not block the event forever.
    lost.add(task["task_id"])
    fresh, created = worker.enqueue_analysis(
        "ai-alert-manual", "app.worker.process_manual_analysis", event, "om_1", "oc_1"
    )
    assert created and fresh["task_id"] != task["task_id"]
    assert tasks.get(task["task_id"])["error_type"] == "QueueLost"
    assert len(FakeQueue.jobs) == 2

    class Down(FakeQueue):
        def enqueue(self, *args, **kwargs):
            raise ConnectionError("redis offline")

    monkeypatch.setattr(worker, "Queue", Down)
    other = {**event, "event_id": "770021"}
    with pytest.raises(ConnectionError):
        worker.enqueue_analysis(
            "ai-alert-analysis", "app.worker.process_alert_analysis", other
        )
    from app.main import connection

    with connection() as db:
        row = db.execute(
            "SELECT status,error_type FROM diagnostic_tasks WHERE event_id='770021'"
        ).fetchone()
    assert row == ("failed", "QueueUnavailable")


def test_enterprise_app_alert_notifier(monkeypatch):
    from app import feishu_client

    sent = []
    monkeypatch.setattr(
        worker,
        "cfg",
        lambda k: {
            "feishu_enabled": "true",
            "feishu_alert_chat_ids": "oc_test_1,oc_test_2",
            "allowed_chat_ids": "",
        }.get(k, ""),
    )

    async def token(_client):
        return "mock-token"

    async def request(_client, method, url, auth, **kwargs):
        sent.append(kwargs["json"]["receive_id"])
        return {"code": 0}

    monkeypatch.setattr(feishu_client, "get_token", token)
    monkeypatch.setattr(feishu_client, "request", request)
    asyncio.run(worker.notify({"header": {"title": {"content": "test"}}}))
    assert sent == ["oc_test_1", "oc_test_2"]


def test_feishu_reply_card_uses_original_message(monkeypatch):
    from app import feishu_client
    import json

    sent = []

    async def fake_token(client):
        return "test-token"

    async def fake_request(client, method, url, token=None, **kwargs):
        sent.append((method, url, kwargs["json"]))
        return {"data": {"message_id": "om_reply"}}

    monkeypatch.setattr(feishu_client, "get_token", fake_token)
    monkeypatch.setattr(feishu_client, "request", fake_request)
    result = asyncio.run(feishu_client.reply_card("om_source", "AI 分析中", "正在分析"))
    assert result == "om_reply"
    assert sent[0][0] == "POST"
    assert sent[0][1].endswith("/im/v1/messages/om_source/reply")
    assert sent[0][2]["reply_in_thread"] is False
    assert (
        json.loads(sent[0][2]["content"])["header"]["title"]["content"] == "AI 分析中"
    )


def test_compact_alert_card_and_recovery():
    event = {
        "event_id": "6056231",
        "severity": "2",
        "event_value": "1",
        "host_name": "DESKTOP",
        "host_ip": "198.51.100.2",
        "host_groups": "Office",
    }
    card = worker.make_card(event)
    body = str(card)
    assert "Office" in body
    assert "故障原因" not in body and "处理建议" not in body
    assert "AI 分析" not in body and "需人工核验" not in body
    recovered = worker.make_card({**event, "event_value": "0"})
    assert recovered["header"]["template"] == "green"
    assert "告警恢复" in recovered["header"]["title"]["content"]


def test_severe_analysis_has_detail():
    event = {"event_id": "6056232", "severity": "4", "event_value": "1"}
    details = {"cause": "CPU 排队", "action": "核对进程", "analysis": "指标趋势"}
    initial = worker.make_card(event, details)
    analyzed = worker.make_card(event, details, analysis=True)
    assert "故障原因" not in str(initial)
    assert "诊断结论" in str(analyzed)


def test_alert_card_newlines_are_real():
    card = worker.make_card(
        {
            "event_id": "12345",
            "severity": "3",
            "event_value": "1",
            "host_name": "C15-HX-M",
            "host_ip": "198.51.100.3",
            "event_name": "Link down",
        }
    )
    body = card["elements"][0]["text"]["content"]
    assert "\n" in body
    assert "\\n" not in body
    assert body.splitlines()[0] == "**主机名称**  C15-HX-M"


def test_zabbix_alarm_and_recovery_event_times():
    event = {
        "event_id": "600001",
        "severity": "2",
        "event_value": "1",
        "event_date": "2026.10.19",
        "event_time": "19:53:20",
        "recovery_date": "2026.10.19",
        "recovery_time": "20:01:21",
    }
    problem = str(worker.make_card(event))
    assert "发生时间" in problem and "19:53:20" in problem
    recovered = str(worker.make_card({**event, "event_value": "0"}))
    assert "恢复时间" in recovered and "20:01:21" in recovered
    unresolved = str(worker.make_card({**event, "event_date": "{EVENT.DATE}"}))
    assert "发生时间" not in unresolved


def test_recovery_duration_and_group_are_rendered():
    event = {
        "event_id": "123456",
        "event_value": "0",
        "severity": "4",
        "host_name": "C15-HX-M",
        "host_groups": "Core/Switch",
        "event_date": "2026.10.20",
        "event_time": "10:00:00",
        "recovery_date": "2026.10.20",
        "recovery_time": "10:18:02",
        "event_duration": "18m 02s",
    }
    card = worker.make_card(event)
    body = card["elements"][0]["text"]["content"]
    assert card["header"]["template"] == "green"
    assert "所属分组" in body and "Core/Switch" in body
    assert "持续时间" in body and "18m 02s" in body
    assert "恢复时间" in body and "10:18:02" in body
    assert "故障原因" not in body


def test_duration_calculated_when_macro_unresolved():
    from app.worker import event_duration

    assert (
        event_duration(
            {
                "event_date": "2026.10.20",
                "event_time": "10:00:00",
                "recovery_date": "2026.10.20",
                "recovery_time": "10:03:27",
                "event_duration": "{EVENT.DURATION}",
            }
        )
        == "00:03:27"
    )


def test_zabbix_event_deep_link(monkeypatch):
    original = worker.read_setting
    monkeypatch.setattr(
        worker,
        "read_setting",
        lambda key: (
            "https://zabbix.example.com"
            if key == "zabbix_frontend_url"
            else original(key)
        ),
    )
    event = {
        "event_id": "6057922",
        "trigger_id": "102345",
        "severity": "3",
        "event_value": "1",
        "event_name": "Link down",
    }
    card = worker.make_card(event)
    body = card["elements"][0]["text"]["content"]
    assert "事件来源" not in body
    assert any(
        b.get("url", "").endswith("triggerid=102345&eventid=6057922")
        for e in card["elements"]
        if e["tag"] == "action"
        for b in e["actions"]
    )
    assert "192.0.2.10 转发" not in body
    recovery = worker.make_card({**event, "event_value": "0"})
    assert any(
        "eventid=6057922" in b.get("url", "")
        for e in recovery["elements"]
        if e["tag"] == "action"
        for b in e["actions"]
    )
    no_id = worker.make_card({**event, "trigger_id": "{TRIGGER.ID}"})
    assert "tr_events.php" not in str(no_id)
    monkeypatch.setattr(worker, "read_setting", lambda key: "")
    assert worker.zabbix_event_link(event) == ""
    monkeypatch.setattr(worker, "read_setting", lambda key: "javascript:alert(1)")
    assert worker.zabbix_event_link(event) == ""


def test_alert_mute_button_targets_host_and_trigger(monkeypatch):
    configure_frontend(monkeypatch)
    event = {
        "event_id": "777001",
        "host_id": "101",
        "trigger_id": "202",
        "severity": "2",
        "event_value": "1",
        "event_name": "Load high",
    }
    card = worker.make_card(event)
    buttons = [
        a for el in card["elements"] if el["tag"] == "action" for a in el["actions"]
    ]
    assert len(buttons) == 3
    actions = [b for b in buttons if "value" in b]
    assert {b["value"]["op"] for b in actions} == {"choose_mute", "analyze_alert"}
    assert all(
        b["value"]["trigger_id"] == "202" and b["value"]["event_id"] == "777001"
        for b in actions
    )
    assert buttons[0]["url"].startswith("http")
    recovery = worker.make_card({**event, "event_value": "0"})
    assert [
        b["value"]["op"]
        for el in recovery["elements"]
        if el["tag"] == "action"
        for b in el["actions"]
        if "value" in b
    ] == ["analyze_alert"]


def test_alert_mute_requires_matching_identity():
    event = {
        "event_id": "777002",
        "host_id": "{HOST.ID}",
        "trigger_id": "202",
        "severity": "2",
        "event_value": "1",
    }
    card = worker.make_card(event)
    assert all(
        b.get("value", {}).get("op") != "choose_mute"
        for e in card["elements"]
        if e["tag"] == "action"
        for b in e["actions"]
    )


def test_recovery_sent_only_for_original_feishu_sent_problem(monkeypatch):
    from app.main import connection

    sent = []

    async def notify(card, event=None, **kwargs):
        sent.append(card)

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(
        worker, "cfg", lambda key: "true" if key == "feishu_enabled" else "4"
    )
    for eid, state in [
        ("paired001", "sent"),
        ("muted001", "muted"),
        ("failed001", "failed"),
        ("disabled001", "disabled"),
    ]:
        with connection() as db:
            db.execute(
                """INSERT OR REPLACE INTO alert_events
                (event_id,event_value,event_name,host_name,severity,notify_status)
                VALUES (?, '1', 'test', 'host', 2, ?)""",
                (eid, state),
            )
    for eid in ("muted001", "failed001", "disabled001", "missing001"):
        result = asyncio.run(
            worker.handle_alert({"event_id": eid, "event_value": "0", "severity": "2"})
        )
        assert result["recovery_suppressed"] is True
    assert sent == []
    result = asyncio.run(
        worker.handle_alert(
            {"event_id": "paired001", "event_value": "0", "severity": "2"}
        )
    )
    assert result["notified"] is True
    assert len(sent) == 1


def test_mute_summary_follows_action_buttons():
    event = {
        "event_id": "773310",
        "host_id": "101",
        "trigger_id": "202",
        "severity": "2",
        "event_value": "1",
        "event_name": "CPU high",
    }
    card = worker.make_card(
        event,
        mute_info={
            "operator": "ou_admin",
            "duration": "4 小时",
            "time": "2026-10-21 10:00:00",
            "expires": "2026-10-21 14:00:00",
        },
    )
    assert card["config"]["update_multi"] is True
    assert "临时屏蔽仅影响后续飞书通知" not in str(card)
    assert not any(el["tag"] == "column_set" for el in card["elements"])
    assert "ou_admin" in str(card["elements"][-1])
    assert "4 小时" in str(card["elements"][-1])
    assert card["elements"][-1]["extra"]["value"]["op"] == "unmute_alert"


def test_manual_analysis_progress_updates_and_context_for_both_states(monkeypatch):
    from app import feishu_client, conversation_context

    events = []
    task_ids = []

    async def analyze(event, task_id=None):
        task_ids.append(task_id)
        return {
            "cause": "负载较高",
            "action": "检查进程",
            "analysis": "CPU趋势连续上升",
        }

    async def reply(message_id, title, detail, **kwargs):
        events.append(("reply", message_id, title, detail, kwargs.get("actions")))
        return "om_progress"

    async def update(message_id, title, detail, template="green", **kwargs):
        events.append(("update", message_id, title, detail, kwargs.get("actions")))

    async def chat(message_id):
        return "oc_group"

    saved = []
    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(feishu_client, "reply_card", reply)
    monkeypatch.setattr(feishu_client, "update_card", update)
    monkeypatch.setattr(
        conversation_context, "remember", lambda *args, **kwargs: saved.append(args)
    )
    monkeypatch.setattr(conversation_context, "mark_pending", lambda *args: None)
    monkeypatch.setattr(conversation_context, "clear_pending", lambda *args: None)
    for state in ("1", "0"):
        events.clear()
        result = asyncio.run(
            worker.analyze_on_demand(
                {
                    "event_id": "773311",
                    "severity": "2",
                    "event_value": state,
                    "event_name": "CPU high",
                    "host_name": "node1",
                    "host_ip": "198.51.100.21",
                },
                "om_original",
                "oc_group",
                "task-" + state,
            )
        )
        assert result["diagnosed"] and task_ids[-1] == "task-" + state
        assert len(events) == 2
        assert events[0][0:3] == ("reply", "om_original", "AI 分析中")
        assert events[1][0:3] == ("update", "om_progress", "AI 分析结果")
        # The card carries the conclusion and actions; the analysis stays in
        # the conversation context for follow-up questions and on the Web.
        assert "负载较高" in events[1][3] and "检查进程" in events[1][3]
        assert "CPU趋势连续上升" not in events[1][3]
        assert saved[-1][0:3] == ("oc_group", "om_original", "om_progress")
        assert "CPU趋势连续上升" in saved[-1][4]


def test_recovery_replies_to_matching_chat_messages(monkeypatch):
    from app import feishu_client
    from app.main import connection

    sent = []
    event = {"event_id": "recovery-link-900", "event_value": "1"}

    async def token(_client):
        return "token"

    async def request(_client, method, url, auth, **kwargs):
        sent.append((url, kwargs))
        return (
            {"data": {"message_id": "om_" + kwargs["json"]["receive_id"]}}
            if "receive_id" in kwargs.get("json", {})
            else {"data": {"message_id": "om_reply"}}
        )

    monkeypatch.setattr(feishu_client, "get_token", token)
    monkeypatch.setattr(feishu_client, "request", request)
    monkeypatch.setattr(
        worker,
        "cfg",
        lambda key: {
            "feishu_enabled": "true",
            "feishu_alert_chat_ids": "oc_chat1,oc_chat2",
        }.get(key, ""),
    )
    asyncio.run(worker.notify({"elements": []}, event=event))
    with connection() as db:
        ids = db.execute(
            "SELECT chat_id,message_id FROM alert_message_links WHERE event_id=? ORDER BY chat_id",
            (event["event_id"],),
        ).fetchall()
    assert ids == [("oc_chat1", "om_oc_chat1"), ("oc_chat2", "om_oc_chat2")]
    sent.clear()
    asyncio.run(worker.notify({"elements": []}, event={**event, "event_value": "0"}))
    assert len(sent) == 2
    assert sent[0][0].endswith("/om_oc_chat1/reply")
    assert sent[1][0].endswith("/om_oc_chat2/reply")
    assert all(entry[1]["json"]["reply_in_thread"] is False for entry in sent)


def test_feishu_card_does_not_nest_action_inside_column():
    event = {
        "event_id": "100200",
        "host_id": "101",
        "trigger_id": "202",
        "severity": "2",
        "event_value": "1",
    }
    from app.worker import make_card

    card = make_card(event)
    assert any(el["tag"] == "action" for el in card["elements"])
    assert not any(el["tag"] == "column_set" for el in card["elements"])
    assert [
        b["value"]["op"]
        for e in card["elements"]
        if e["tag"] == "action"
        for b in e["actions"]
        if "value" in b
    ] == ["analyze_alert", "choose_mute"]


def test_source_button_precedes_actions_for_problem_and_recovery(monkeypatch):
    configure_frontend(monkeypatch)
    event = {
        "event_id": "6180279",
        "host_id": "101",
        "trigger_id": "202",
        "severity": "3",
        "event_value": "1",
    }
    problem = worker.make_card(event)
    recovery = worker.make_card({**event, "event_value": "0"})
    for card, expected in (
        (problem, ["url", "analyze_alert", "choose_mute"]),
        (recovery, ["url", "analyze_alert"]),
    ):
        assert "**告警操作**" not in str(card)
        buttons = next(e["actions"] for e in card["elements"] if e["tag"] == "action")
        found = ["url" if "url" in b else b["value"]["op"] for b in buttons]
        assert found == expected
        assert buttons[0]["url"].startswith("http")
    recovery_buttons = next(
        e["actions"] for e in recovery["elements"] if e["tag"] == "action"
    )
    assert recovery_buttons[1]["value"]["event_value"] == "0"


def test_latest_value_for_problem_and_recovery():
    base = {
        "event_id": "700001",
        "trigger_id": "800001",
        "host_id": "100001",
        "severity": "2",
        "event_name": "CPU high",
    }
    problem = worker.make_card({**base, "event_value": "1", "latest_value": "89.4 %"})
    restored = worker.make_card(
        {**base, "event_value": "0", "latest_value": "31.2 %", "recovery_value": "29 %"}
    )
    assert "**事件数值**  89.4 %" in problem["elements"][0]["text"]["content"]
    assert "**事件数值**  31.2 %" in restored["elements"][0]["text"]["content"]
    fallback = worker.make_card({**base, "event_value": "0", "recovery_value": "0"})
    assert "**事件数值**  未提供" in fallback["elements"][0]["text"]["content"]
    unknown = worker.make_card(
        {**base, "event_value": "1", "latest_value": "{ITEM.LASTVALUE1}"}
    )
    assert "**事件数值**  未提供" in unknown["elements"][0]["text"]["content"]
    zero = worker.make_card({**base, "event_value": "1", "latest_value": "0"})
    assert "**事件数值**  0" in zero["elements"][0]["text"]["content"]


def test_event_detail_overrides_latest_value():
    event = {
        "event_id": "910001",
        "event_value": "1",
        "event_name": "Link down",
        "event_detail": "Current state: down (2)",
        "latest_value": "2",
    }
    card = worker.make_card(event)
    assert "**事件数值**  2" in card["elements"][0]["text"]["content"]
    assert "Current state: down (2)" not in card["elements"][0]["text"]["content"]
    recovery = worker.make_card(
        {**event, "event_value": "0", "event_detail": "Current state: up (1)"}
    )
    assert "**事件数值**  2" in recovery["elements"][0]["text"]["content"]


def test_recovery_status_is_not_event_detail():
    card = worker.make_card(
        {
            "event_id": "6190507",
            "event_value": "0",
            "recovery_value": "0",
            "event_detail": "",
        }
    )
    assert "**事件数值**  未提供" in card["elements"][0]["text"]["content"]


def test_automatic_analysis_card_shows_token_usage():
    event = {"event_id": "123", "severity": "4", "event_value": "1"}
    info = {
        "cause": "CPU高",
        "action": "查看指标",
        "analysis": "历史趋势",
        "_token_usage": {
            "input": 750,
            "output": 250,
            "total": 1000,
            "available": True,
            "profile": "standard",
        },
    }
    card = worker.make_card(event, info, analysis=True)
    assert "本轮 Token 消耗：1,000（输入 750 / 输出 250） · 分析模式：标准分析" in str(
        card
    )


def test_token_footer_separate_from_body_in_feishu_card():
    from app.feishu_client import make_card

    card = make_card(
        "AI 分析结果",
        "故障原因：测试\n\n---\n本轮 Token 消耗：1,234（输入 1,000 / 输出 234）",
    )
    assert len(card["elements"]) == 3
    assert card["elements"][1]["tag"] == "hr"
    assert "Token 消耗" not in card["elements"][0]["text"]["content"]
    assert card["elements"][2]["tag"] == "note"
    assert "1,234" in card["elements"][2]["elements"][0]["content"]


def test_native_feishu_token_footer():
    from app.feishu_client import make_card

    card = make_card(
        "AI 分析结果", "结果文本\n\n---\n本轮 Token 消耗：300（输入 250 / 输出 50）"
    )
    assert [e["tag"] for e in card["elements"]] == ["div", "hr", "note"]
    assert "Token 消耗" not in card["elements"][0]["text"]["content"]
    assert "300" in card["elements"][2]["elements"][0]["content"]


def test_alert_token_usage_is_persisted():
    from app.main import connection
    from app.worker import store_alert_usage

    event = {"event_id": "test_usage_001", "event_value": "1"}
    with connection() as db:
        db.execute(
            "INSERT OR IGNORE INTO alert_events(event_id,event_value,event_name) VALUES (?,'1','token test')",
            (event["event_id"],),
        )
    store_alert_usage(
        event, {"available": True, "total": 120, "input": 100, "output": 20}
    )
    with connection() as db:
        row = db.execute(
            "SELECT token_total,token_input,token_output FROM alert_events WHERE event_id=? AND event_value='1'",
            (event["event_id"],),
        ).fetchone()
    assert row == (120, 100, 20)


def test_card_footer_combines_usage_profile_and_elapsed_time():
    card = worker.make_card(
        {"event_id": "887", "severity": "4", "event_value": "1"},
        {
            "cause": "当前内存高",
            "analysis": "RSS 已采集",
            "_token_usage": {
                "available": True,
                "total": 500,
                "input": 400,
                "output": 100,
                "profile": "standard",
            },
            "_duration_ms": 57100,
        },
        analysis=True,
    )
    note = card["elements"][-1]["elements"][0]["content"]
    assert "分析模式：标准分析" in note
    assert "执行耗时：57.1 秒" in note
    assert "执行耗时" not in str(card["elements"][1:-1])
