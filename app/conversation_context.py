"""Per-replied-message Feishu AI context. Chat-scoped and bounded to four AI answers."""

import json
import time
from redis import Redis
from .main import REDIS_URL

TTL = 1800
MAX_DEPTH = 4
PREFIX = "feishu-ai:context:"
THREAD_PREFIX = "feishu-ai:thread:"
PENDING_PREFIX = "feishu-ai:pending:"
# Progress cards on record until their analysis ends (worker.reconcile).
PROGRESS_PREFIX = "feishu-ai:progress:"
PROGRESS_TTL = 86400


def _client():
    return Redis.from_url(REDIS_URL, decode_responses=True)


def mark_pending(chat_id, reply_id, kind="alert"):
    """`reply_id` is a progress card: replies to it wait for the analysis, and
    it stays on record so a card a killed worker left can be closed. `kind`:
    "alert" (manual alert analysis) or "qa" (chat question)."""
    if chat_id and reply_id:
        client = _client()
        client.set(PENDING_PREFIX + chat_id + ":" + reply_id, "1", ex=TTL)
        client.set(
            PROGRESS_PREFIX + reply_id,
            json.dumps({"chat_id": chat_id, "kind": kind, "at": int(time.time())}),
            ex=PROGRESS_TTL,
        )


def is_pending(chat_id, reply_id):
    return bool(
        chat_id
        and reply_id
        and _client().get(PENDING_PREFIX + chat_id + ":" + reply_id)
    )


def clear_pending(chat_id, reply_id):
    if chat_id and reply_id:
        client = _client()
        client.delete(PENDING_PREFIX + chat_id + ":" + reply_id)
        client.delete(PROGRESS_PREFIX + reply_id)


def abandoned_progress(older_than):
    """Claim the progress cards on record for over `older_than` seconds, whose
    analysis can no longer be running: (reply_id, record) pairs, each claimed
    by one caller only."""
    client = _client()
    cutoff = time.time() - older_than
    for key in list(client.scan_iter(PROGRESS_PREFIX + "*")):
        try:
            record = json.loads(client.get(key) or "")
        except (ValueError, TypeError):
            continue
        if (
            isinstance(record, dict)
            and record.get("at", 0) <= cutoff
            and client.delete(key)
        ):
            yield key[len(PROGRESS_PREFIX) :], record


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
    # Thread-root copy: nothing reads it, since replies resolve only by the exact
    # replied-to message (no fallback to a different reply branch).
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
