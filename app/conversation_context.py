"""Per-replied-message Feishu AI context. Chat-scoped and bounded to four AI answers."""

import json
from redis import Redis
from .main import REDIS_URL

TTL = 1800
MAX_DEPTH = 4
PREFIX = "feishu-ai:context:"
THREAD_PREFIX = "feishu-ai:thread:"
PENDING_PREFIX = "feishu-ai:pending:"


def _client():
    return Redis.from_url(REDIS_URL, decode_responses=True)


def mark_pending(chat_id, reply_id):
    if chat_id and reply_id:
        _client().set(PENDING_PREFIX + chat_id + ":" + reply_id, "1", ex=TTL)


def is_pending(chat_id, reply_id):
    return bool(
        chat_id
        and reply_id
        and _client().get(PENDING_PREFIX + chat_id + ":" + reply_id)
    )


def clear_pending(chat_id, reply_id):
    if chat_id and reply_id:
        _client().delete(PENDING_PREFIX + chat_id + ":" + reply_id)


def remember(
    chat_id, source_id, reply_id, question, answer, parent_context=None, root_id=None
):
    """Each AI answer retains its own immutable reply chain, not the thread's latest answer."""
    if not chat_id or not source_id:
        return
    previous = (parent_context or {}).get("turns", [])
    turn = {"question": str(question)[:3000], "answer": str(answer)}
    payload = {
        "chat_id": chat_id,
        "turns": previous + [turn],
        "origin": (parent_context or {}).get("origin", ""),
        "event": (parent_context or {}).get("event"),
    }
    client = _client()
    encoded = json.dumps(payload, ensure_ascii=False)
    from .feishu_cards import message_ids

    for message_id in (source_id, *message_ids(reply_id)):
        if message_id:
            client.set(PREFIX + message_id, encoded, ex=TTL)
    # Retained for compatibility with old data; no fallback to a different reply branch.
    if root_id:
        client.set(THREAD_PREFIX + chat_id + ":" + root_id, encoded, ex=TTL)


def recall(chat_id, parent_id):
    if not parent_id:
        return None
    data = _client().get(PREFIX + parent_id)
    if not data:
        return None
    try:
        payload = json.loads(data)
        if payload.get("chat_id") != chat_id:
            return None
        if not isinstance(payload.get("turns"), list):
            return None
        return payload
    except (ValueError, TypeError):
        return None


def recall_thread(chat_id, root_id):
    if not chat_id or not root_id:
        return None
    data = _client().get(THREAD_PREFIX + chat_id + ":" + root_id)
    if not data:
        return None
    try:
        payload = json.loads(data)
        return (
            payload
            if payload.get("chat_id") == chat_id
            and isinstance(payload.get("turns"), list)
            else None
        )
    except (ValueError, TypeError):
        return None


def format_context(payload):
    if not payload:
        return ""
    turns = payload.get("turns", [])
    lines = [
        "以下是被回复消息的完整历史上下文，按顺序引用。历史监控数据不能视为实时指标，必须通过只读 MCP 重新核验："
    ]
    origin = payload.get("origin")
    if origin:
        lines.append("原始告警消息：" + str(origin)[:11000])
    for index, turn in enumerate(turns, 1):
        lines.append(f"第{index}轮用户：{str(turn.get('question', ''))[:3000]}")
        lines.append(f"第{index}轮AI回答：{str(turn.get('answer', ''))}")
    return "\n".join(lines)
