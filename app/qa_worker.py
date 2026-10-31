"""Feishu Q&A and exact-message alert follow-ups."""

import asyncio
import logging
import json
from redis import Redis
from rq import Worker, Queue
from .main import REDIS_URL, record_ai_question
from .ai_agent import ask
from .alert_context import resolve_replied_event
from .conversation_context import (
    remember,
    recall,
    format_context,
    MAX_DEPTH,
    mark_pending,
    is_pending,
    clear_pending,
)
from .feishu_client import reply_card, update_card
from .orchestrator import queues

log = logging.getLogger(__name__)


def reply_text(report, answer):
    """Chat reply: the conclusion and the platform's scope without evidence ids.

    Ids only mean something next to the Web report's evidence list; that page,
    linked from the reply, keeps them and the citation check (as alert cards do).
    """
    from .mcp_runtime import readable_report_answer
    from .worker import without_evidence_ids

    return "\n\n".join(
        part
        for part in (
            without_evidence_ids(readable_report_answer(answer)),
            report.get("chat_scope"),
        )
        if part
    )


async def execute(
    chat_id, question, message_id, sender_open_id=None, parent_id=None, root_id=None
):
    """Only the directly replied-to message determines the chain and depth."""
    if sender_open_id:
        from .security.rbac import permits

        if not permits(sender_open_id, "diagnostics.run"):
            await reply_card(
                message_id,
                "无诊断权限",
                "当前账号没有诊断权限，请联系平台管理员。",
                "orange",
            )
            record_ai_question("feishu", message_id, question, "rejected")
            return
    stored = recall(chat_id, parent_id)
    if is_pending(chat_id, parent_id):
        await reply_card(
            message_id, "AI 分析中", "正在分析中，请勿重复提交。", "orange"
        )
        record_ai_question("feishu", message_id, question, "rejected")
        log.info("FEISHU_CONTEXT_PENDING message_id=%s", message_id)
        return
    if stored and len(stored.get("turns", [])) >= MAX_DEPTH:
        await reply_card(
            message_id,
            "关联消息超过5个",
            "关联消息超过5个，不支持分析，请更换方式。",
            "orange",
        )
        record_ai_question("feishu", message_id, question, "rejected")
        log.info("FEISHU_CONTEXT_LIMIT message_id=%s", message_id)
        return

    context = format_context(stored)
    if parent_id and not stored:
        from .integrations.feishu_links import event_for_message

        trusted_event = event_for_message(parent_id, chat_id)
        if trusted_event:
            stored = {
                "origin": json.dumps(trusted_event, ensure_ascii=False),
                "turns": [],
                "event": trusted_event,
            }
            context = format_context(stored)
    if parent_id and not stored:
        try:
            event_id = await resolve_replied_event(parent_id, chat_id)
            if event_id:
                context = (
                    "用户直接回复的 Zabbix 告警事件 ID 为 "
                    + event_id
                    + "；使用 MCP 重新核验状态。"
                )
                log.info(
                    "FEISHU_REPLIED_ALERT message_id=%s event_id=%s",
                    message_id,
                    event_id,
                )
        except Exception:
            log.exception("FEISHU_REPLY_LOOKUP_FAILED message_id=%s", message_id)
    record_ai_question("feishu", message_id, question, "running")
    log.info(
        "FEISHU_CONTEXT_RESOLVED message_id=%s found=%s parent=%s root=%s depth=%s",
        message_id,
        bool(stored),
        bool(parent_id),
        bool(root_id),
        len(stored.get("turns", [])) if stored else 0,
    )
    progress_id = None
    try:
        progress_id = await reply_card(
            message_id,
            "AI 分析中",
            "**问题：** " + question[:180] + "\n\n⏳ 正在查询后台MCP服务并进行分析……",
        )
        mark_pending(chat_id, progress_id)
        log.info("FEISHU_PROGRESS_SENT message_id=%s", message_id)
    except Exception:
        log.exception("FEISHU_PROGRESS_FAILED message_id=%s", message_id)
    try:
        from .mcp_runtime import format_usage

        verified_event = (stored or {}).get("event")
        result, usage = await ask(
            question,
            context,
            return_usage=True,
            actor=sender_open_id or "feishu",
            **({"event": verified_event} if verified_event else {}),
        )
        from .worker import report_url
        from .orchestrator import tasks

        task = tasks.get(usage.get("task_id")) if usage.get("task_id") else None
        state = (task or {}).get("status")
        title, color = {
            "partial": ("AI 分析结果 · 部分完成", "orange"),
            "failed": ("AI 分析未完成", "red"),
        }.get(state, ("AI 分析完成", "green"))
        report = (task or {}).get("report") or {}
        display_result = reply_text(report, result)
        if report.get("limitations"):
            display_result += "\n\n**诊断不足与待核验**\n" + "\n".join(
                "- " + str(item) for item in report["limitations"]
            )
        if task and task.get("duration_ms") is not None:
            display_result += f"\n\n执行耗时：{task['duration_ms'] / 1000:.1f} 秒"
        url = report_url({"_token_usage": usage})
        if url:
            display_result += "\n\n[查看完整诊断报告](" + url + ")"
        display_result += "\n\n---\n" + format_usage(usage)
        record_ai_question(
            "feishu",
            message_id,
            question,
            "failed" if state == "failed" else "success",
            token_usage=usage,
        )
        if progress_id:
            try:
                await update_card(progress_id, title, display_result, color)
                remember(
                    chat_id,
                    message_id,
                    progress_id,
                    question,
                    result,
                    stored,
                    root_id=root_id or parent_id or message_id,
                )
                log.info("FEISHU_CARD_UPDATED message_id=%s", message_id)
                return
            except Exception:
                log.exception("FEISHU_CARD_UPDATE_FAILED message_id=%s", message_id)
        fallback_id = await reply_card(message_id, title, display_result, color)
        remember(
            chat_id,
            message_id,
            fallback_id,
            question,
            result,
            stored,
            root_id=root_id or parent_id or message_id,
        )
    except Exception as exc:
        record_ai_question("feishu", message_id, question, "failed", type(exc).__name__)
        log.exception("FEISHU_QA_FAILED message_id=%s", message_id)
        if progress_id:
            try:
                await update_card(
                    progress_id,
                    "AI 分析失败",
                    "分析失败，请稍后重试或联系管理员。",
                    "red",
                )
                return
            except Exception:
                log.exception("FEISHU_ERROR_UPDATE_FAILED message_id=%s", message_id)
        await reply_card(
            message_id, "AI 分析失败", "分析失败，请稍后重试或联系管理员。", "red"
        )
    finally:
        clear_pending(chat_id, progress_id)


def process_question(
    chat_id, question, message_id, sender_open_id=None, parent_id=None, root_id=None
):
    return asyncio.run(
        execute(chat_id, question, message_id, sender_open_id, parent_id, root_id)
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    redis = Redis.from_url(REDIS_URL)
    Worker([Queue(queues.QUESTIONS, connection=redis)], connection=redis).work()
