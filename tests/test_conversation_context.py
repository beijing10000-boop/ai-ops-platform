import json
from app import conversation_context as ctx

class FakeRedis:
    def __init__(self):
        self.items = {}
    def set(self, key, value, ex=None):
        self.items[key] = value
    def get(self, key):
        return self.items.get(key)
    def delete(self, key):
        self.items.pop(key, None)

def test_reply_context_is_scoped_by_chat_and_message(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    ctx.remember("oc_group1", "om_q1", "om_a1", "172.20.200.6有什么告警", "Swap使用率过高，事件6042005")
    stored = ctx.recall("oc_group1", "om_a1")
    assert len(stored["turns"]) == 1
    assert "Swap使用率" in ctx.format_context(stored)
    assert ctx.recall("oc_group2", "om_a1") is None
    assert ctx.recall("oc_group1", "om_unknown") is None
    ctx.remember("oc_group1", "om_q2", "om_a2", "更深入分析", "请核实Swap趋势", stored)
    followup = ctx.recall("oc_group1", "om_a2")
    assert len(followup["turns"]) == 2
    assert "172.20.200.6" in ctx.format_context(followup)

def test_context_depth_is_counted_for_worker_limit(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    data = None
    for i in range(4):
        ctx.remember("oc_test", "om_q" + str(i), "om_a" + str(i), "question" + str(i), "answer" + str(i), data)
        data = ctx.recall("oc_test", "om_a" + str(i))
    assert len(data["turns"]) == 4
    assert data["turns"][-1]["question"] == "question3"

def test_thread_context_survives_third_and_fourth_reply(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    ctx.remember("oc_group1", "om_alert", "om_analysis", "分析事件6202260",
                 "主机172-20-2-113 (172.20.2.113)负载偏高", root_id="om_alert")
    first = ctx.recall_thread("oc_group1", "om_alert")
    assert first is not None
    ctx.remember("oc_group1", "om_question2", "om_answer2",
                 "这台机器还有什么问题", "内存可用率较低", first, root_id="om_alert")
    second = ctx.recall_thread("oc_group1", "om_alert")
    ctx.remember("oc_group1", "om_question3", "om_answer3",
                 "那磁盘呢", "需要核验磁盘延迟", second, root_id="om_alert")
    third = ctx.recall_thread("oc_group1", "om_alert")
    assert len(third["turns"]) == 3
    assert "172.20.2.113" in ctx.format_context(third)
    assert ctx.recall_thread("oc_other", "om_alert") is None
    assert ctx.recall_thread("oc_group1", "om_unrelated") is None

def test_pending_progress_card(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    ctx.mark_pending("oc_group", "om_progress")
    assert ctx.is_pending("oc_group", "om_progress")
    assert not ctx.is_pending("oc_other", "om_progress")
    ctx.clear_pending("oc_group", "om_progress")
    assert not ctx.is_pending("oc_group", "om_progress")


def test_reply_to_older_branch_does_not_inherit_newer_answers(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    ctx.remember("oc", "om_alert", "om_A", "分析", "回答A",
                 {"origin": "告警172.20.2.101", "turns": []})
    a = ctx.recall("oc", "om_A")
    ctx.remember("oc", "om_qB", "om_B", "问题B", "回答B", a)
    ctx.remember("oc", "om_qC", "om_C", "问题C", "回答C", ctx.recall("oc", "om_B"))
    ctx.remember("oc", "om_other", "om_other_reply", "从A重新追问", "不同分支", ctx.recall("oc", "om_A"))
    payload = ctx.recall("oc", "om_other_reply")
    assert len(payload["turns"]) == 2
    assert "回答B" not in ctx.format_context(payload)
    assert "告警172.20.2.101" in ctx.format_context(payload)

def test_reply_to_analysis_in_progress_never_calls_ai(monkeypatch):
    import asyncio
    from app import qa_worker
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    ctx.mark_pending("oc_group", "om_progress")
    replies = []
    async def reply(message_id, title, body, template="blue"):
        replies.append((title, body))
        return "om_rejected"
    async def forbidden_ai(*args, **kwargs):
        raise AssertionError("AI must not run for a progress card")
    monkeypatch.setattr(qa_worker, "reply_card", reply)
    monkeypatch.setattr(qa_worker, "ask", forbidden_ai)
    monkeypatch.setattr(qa_worker, "record_ai_question", lambda *args, **kwargs: None)
    asyncio.run(qa_worker.execute("oc_group", "这台机器还有什么问题",
                                  "om_new", parent_id="om_progress"))
    assert replies == [("AI 分析中", "分析中，请勿重复分析")]


def test_fifth_ai_answer_is_rejected_without_model_call(monkeypatch):
    import asyncio
    from app import qa_worker
    fake = FakeRedis()
    monkeypatch.setattr(ctx, "_client", lambda: fake)
    previous = {"origin": "原始告警", "turns": []}
    for i in range(4):
        ctx.remember("oc_group", "om_q" + str(i), "om_A" + str(i),
                     "问题" + str(i), "回答" + str(i), previous)
        previous = ctx.recall("oc_group", "om_A" + str(i))
    replies = []
    async def reply(message_id, title, body, template="blue"):
        replies.append((title, body))
        return "om_rejected"
    async def forbidden_ai(*args, **kwargs):
        raise AssertionError("AI must not run past the four-answer limit")
    monkeypatch.setattr(qa_worker, "reply_card", reply)
    monkeypatch.setattr(qa_worker, "ask", forbidden_ai)
    monkeypatch.setattr(qa_worker, "record_ai_question", lambda *args, **kwargs: None)
    monkeypatch.setattr(qa_worker, "recall", ctx.recall)
    monkeypatch.setattr(qa_worker, "is_pending", ctx.is_pending)
    asyncio.run(qa_worker.execute("oc_group", "第五次提问",
                                  "om_next", parent_id="om_A3"))
    assert "关联消息超过5个" in replies[0][1]
