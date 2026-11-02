"""Single Feishu WebSocket receiver. Never perform AI operations in callbacks."""

import asyncio
import json
import logging
import re
import threading
from redis import Redis
from rq import Queue, Worker
from rq.registry import StartedJobRegistry
import lark_oapi as lark
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1
from lark_oapi.event.callback.model.p2_card_action_trigger import (
    P2CardActionTrigger,
    P2CardActionTriggerResponse,
)
from .alert_mute import handle_mute_action
from .alert_actions import (
    card_after_mute,
    handle_analyze_action,
    handle_choose_mute,
    handle_unmute_action,
)
from . import feishu_client
from .main import read_setting, REDIS_URL
from .orchestrator import queues

log = logging.getLogger(__name__)
redis = Redis.from_url(REDIS_URL)
queue = Queue(queues.QUESTIONS, connection=redis)


def questions_ahead():
    """(questions waiting or being answered before a new one, qa-workers
    serving the queue), or None when Redis cannot tell. Plain counts: the
    receiver runs no registry cleanup."""
    try:
        running = StartedJobRegistry(queue=queue).get_job_count(cleanup=False)
        return queue.count + running, Worker.count(queue=queue)
    except Exception as exc:
        log.warning("FEISHU_QUEUE_COUNT_FAILED error=%s", type(exc).__name__)
        return None


def waiting_text(counts):
    """Why a question about to be queued will wait, from questions_ahead():
    other questions are ahead of it (how many) or no qa-worker is running.
    None when it starts at once (or Redis could not tell): its worker
    replies "AI 分析中" itself, as before."""
    if counts is None:
        return None
    ahead, workers = counts
    if ahead == 0 and workers:
        return None
    return (
        f"前面还有 {ahead} 个问题，轮到后自动开始分析"
        if workers
        else "问答分析服务暂未运行，恢复后按顺序开始分析"
    )


def acknowledge(message_id, question, wait):
    """Reply "AI 排队中" to a queued question and hand the card to its worker
    (offer_queued_card), which turns it into the progress card and then the
    answer. Runs on a thread of its own: the WebSocket client runs callbacks
    on its event loop, and card buttons must be answered within 3 seconds.

    The question is queued already, so nothing here can lose it. A worker
    that began it before the card was out replied "AI 分析中" itself: the
    card is not sent then, or, sent meanwhile, says so instead of staying
    "排队中". A card that failed is simply missing; the worker replies."""
    from .conversation_context import offer_queued_card, question_started
    from .worker import lark_safe

    asked = "**问题：** " + lark_safe(question[:180])
    try:
        if question_started(message_id):
            return
        card = asyncio.run(
            feishu_client.reply_card(
                message_id, "AI 排队中", asked + "\n\n⏳ 已排队，" + wait + "。"
            )
        )
        if offer_queued_card(message_id, card):
            log.info("FEISHU_QUEUED_CARD_SENT message_id=%s", message_id)
            return
        asyncio.run(
            feishu_client.update_card(
                card,
                "AI 分析已开始",
                asked + "\n\n已开始分析，进度和结果见本问题下的另一条回复。",
                "grey",
            )
        )
        log.info("FEISHU_QUEUED_CARD_LATE message_id=%s", message_id)
    except Exception:
        log.exception("FEISHU_QUEUED_CARD_FAILED message_id=%s", message_id)


def on_message(data: P2ImMessageReceiveV1):
    message = data.event.message
    sender = data.event.sender
    msg_id = message.message_id
    log.warning("FEISHU_RECEIVED chat_id=%s message_id=%s", message.chat_id, msg_id)
    if (
        sender.sender_type != "user"
        or message.chat_type != "group"
        or message.message_type != "text"
    ):
        log.info("FEISHU_FILTERED reason=type message_id=%s", msg_id)
        return
    groups = {
        s.strip() for s in read_setting("allowed_chat_ids").split(",") if s.strip()
    }
    if message.chat_id not in groups:
        log.warning("FEISHU_FILTERED reason=chat_not_allowed message_id=%s", msg_id)
        return
    try:
        question = json.loads(message.content).get("text", "")
        question = re.sub(r"@_user_\d+", "", question).strip()
    except (ValueError, TypeError, AttributeError):
        log.warning("FEISHU_FILTERED reason=invalid_content message_id=%s", msg_id)
        return
    if not question:
        log.info("FEISHU_FILTERED reason=empty_question message_id=%s", msg_id)
        return
    key = "feishu-ai:message:" + msg_id
    if not redis.set(key, "queued", nx=True, ex=86400):
        log.info("FEISHU_DUPLICATE message_id=%s", msg_id)
        return
    sender_id = getattr(getattr(sender, "sender_id", None), "open_id", None)
    from .security.rbac import permits

    if not sender_id or not permits(sender_id, "diagnostics.run"):
        redis.delete(key)
        log.info("FEISHU_QUESTION_DENIED message_id=%s", msg_id)
        return
    parent_id = getattr(message, "parent_id", None)
    root_id = getattr(message, "root_id", None)
    # Counted before this question joins the queue: the ones ahead of it.
    wait = waiting_text(questions_ahead())
    try:
        queue.enqueue(
            "app.qa_worker.process_question",
            message.chat_id,
            question[:3000],
            msg_id,
            sender_id,
            parent_id or root_id,
            root_id,
            job_timeout=-1,
        )
        log.warning("FEISHU_QUEUED message_id=%s waits=%s", msg_id, bool(wait))
    except Exception:
        redis.delete(key)
        log.exception("FEISHU_ENQUEUE_FAILED message_id=%s", msg_id)
        raise
    if wait:
        threading.Thread(
            target=acknowledge,
            args=(msg_id, question, wait),
            name="feishu-queued-card",
            daemon=True,
        ).start()


def on_card_action(data: P2CardActionTrigger) -> P2CardActionTriggerResponse:
    """Callback must finish within three seconds. Never log tokens or signatures."""
    try:
        event = data.event
        action = getattr(event, "action", None)
        value = getattr(action, "value", None) or {}
        if isinstance(value, str):
            value = json.loads(value)
        operator = getattr(event, "operator", None)
        open_id = getattr(operator, "open_id", None) or getattr(
            operator, "operator_id", None
        )
        context = getattr(event, "context", None)
        message_id = getattr(context, "open_message_id", None)
        if value.get("op") == "choose_mute":
            ok, message, card = handle_choose_mute(value, open_id)
            if ok:
                return P2CardActionTriggerResponse(
                    {
                        "toast": {"type": "info", "content": message},
                        "card": {"type": "raw", "data": card},
                    }
                )
        elif value.get("op") == "unmute_alert":
            ok, message, card = handle_unmute_action(value, open_id)
            if ok:
                return P2CardActionTriggerResponse(
                    {
                        "toast": {"type": "success", "content": message},
                        "card": {"type": "raw", "data": card},
                    }
                )
        elif value.get("op") == "analyze_alert":
            ok, message = handle_analyze_action(
                value,
                open_id,
                message_id,
                getattr(context, "chat_id", None)
                or getattr(context, "open_chat_id", None),
            )
            log.info("FEISHU_ANALYZE_ACTION success=%s", ok)
        else:
            ok, message = handle_mute_action(value, open_id)
            log.info("FEISHU_MUTE_ACTION success=%s", ok)
            if ok:
                card = card_after_mute(value, open_id)
                return P2CardActionTriggerResponse(
                    {
                        "toast": {"type": "success", "content": "暂时屏蔽成功"},
                        "card": {"type": "raw", "data": card},
                    }
                )
        return P2CardActionTriggerResponse(
            {"toast": {"type": "success" if ok else "error", "content": message}}
        )
    except Exception:
        log.exception("FEISHU_MUTE_ACTION_FAILED")
        return P2CardActionTriggerResponse(
            {"toast": {"type": "error", "content": "操作失败，请稍后再试"}}
        )


handler = (
    lark.EventDispatcherHandler.builder("", "")
    .register_p2_im_message_receive_v1(on_message)
    .register_p2_card_action_trigger(on_card_action)
    .build()
)


def main():
    app_id = read_setting("lark_app_id")
    secret = read_setting("lark_app_secret")
    if not app_id or not secret:
        raise RuntimeError("在 Web 后台先设置飞书 App ID 和 Secret")
    lark.ws.Client(
        app_id, secret, event_handler=handler, log_level=lark.LogLevel.INFO
    ).start()


if __name__ == "__main__":
    main()
