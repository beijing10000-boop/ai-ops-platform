import asyncio
import json
from unittest.mock import AsyncMock

from app import feishu_client, conversation_context as context, worker
from app.feishu_cards import MessageID, message_ids, split_card, wire_size, CARD_BYTES


def body_text(cards):
    return "".join(
        element["text"]["content"]
        for card in cards
        for element in card["elements"]
        if element.get("tag") == "div"
    )


def test_short_and_long_unicode_reports_preserve_every_character_and_footer():
    for text in (
        "完整报告超过500字。" * 70,
        '磁盘使用率：81%；路径/data；中文、emoji🙂和引号"\\\n' * 2000,
    ):
        original = feishu_client.make_card(
            "AI 分析结果",
            text + "\n\n---\n本轮 Token 消耗：16,080（输入 15,461 / 输出 619）",
        )
        cards = split_card(original)
        assert body_text(cards) == text
        assert all(wire_size(card) <= CARD_BYTES for card in cards)
        assert (
            sum(
                element.get("tag") == "note"
                for card in cards
                for element in card["elements"]
            )
            == 1
        )
        if len(cards) > 1:
            assert "第 1/" in cards[0]["header"]["title"]["content"]
    assert body_text([original]) == text  # Splitting never mutates the source.


def test_conversation_context_keeps_the_complete_answer_while_the_card_is_short():
    answer = "故障原因（AI 推断）\n" + "证据与建议。" * 300
    info = {
        "cause": "磁盘将满（E1）",
        "action": ["清理日志"],
        "_report_answer": answer,
        "_limitations": ["需要补查历史"],
        "_diagnostic_status": "partial",
        "_duration_ms": 1234,
    }
    result = worker.analysis_summary(info)
    assert answer in result and "需要补查历史" in result
    assert "执行耗时" not in result
    assert "摘要已省略" not in result
    card = worker.card_summary(info)
    assert "证据与建议。" not in card and "E1" not in card
    assert "磁盘将满" in card and "1. 清理日志" in card


def test_update_long_report_patches_first_card_and_replies_with_all_remaining_segments(
    monkeypatch,
):
    sent = []

    async def request(client, method, url, token=None, **kwargs):
        sent.append((method, url, kwargs["json"]))
        return {"data": {"message_id": "om_part_" + str(len(sent))}}

    monkeypatch.setattr(feishu_client, "request", request)
    monkeypatch.setattr(feishu_client, "get_token", AsyncMock(return_value="fixture"))
    original = MessageID("om_progress")
    text = "完整报告证据🙂\n" * 6000
    asyncio.run(feishu_client.update_card(original, "AI 分析完成", text))
    assert sent[0][0] == "PATCH" and all(method == "POST" for method, _, _ in sent[1:])
    assert all(url.endswith("/om_progress/reply") for _, url, _ in sent[1:])
    cards = [json.loads(payload["content"]) for _, _, payload in sent]
    assert body_text(cards) == text
    assert len(message_ids(original)) == len(cards) > 1
    assert all(
        len(json.dumps(payload, ensure_ascii=False).encode()) < 30000
        for _, _, payload in sent
    )


def test_reply_to_any_report_segment_recalls_the_same_full_context(monkeypatch):
    class Memory:
        def __init__(self):
            self.values = {}

        def set(self, key, value, **kwargs):
            self.values[key] = value

        def get(self, key):
            return self.values.get(key)

    memory = Memory()
    monkeypatch.setattr(context, "_client", lambda: memory)
    answer = "完整的后半段依据。" * 2000
    reply = MessageID("om_one", ["om_one", "om_two", "om_three"])
    context.remember("oc_group", "om_question", reply, "查看目录", answer)
    for part in message_ids(reply):
        stored = context.recall("oc_group", part)
        assert stored["turns"][0]["answer"] == answer
        assert answer in context.format_context(stored)
        assert context.recall("oc_other", part) is None
