"""Feishu progress-card adapter for existing worker.process_question (integration required)."""
import asyncio
import json
import logging
import os
import re
import httpx

logger = logging.getLogger(__name__)
API = "https://open.feishu.cn/open-apis"

def card(title, body, color="blue"):
    return {
        "config": {"wide_screen_mode": True, "update_multi": True},
        "header": {"title": {"tag": "plain_text", "content": title}, "template": color},
        "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": body}}],
    }

def display_text(value):
    text = str(value or "").strip()
    text = re.sub(r"^```(?:markdown)?\s*|\s*```$", "", text, flags=re.I)
    return text[:11000] if text else "没有收到有效的分析内容，请查看后台日志。"

async def api_call(client, method, url, *, token=None, **kwargs):
    headers = {"Authorization": "Bearer " + token} if token else {}
    response = await client.request(method, url, headers=headers, **kwargs)
    response.raise_for_status()
    result = response.json()
    if result.get("code", 0) != 0:
        raise RuntimeError("Feishu business error code=%s msg=%s" % (
            result.get("code"), str(result.get("msg", ""))[:250]))
    return result

async def get_token(client):
    result = await api_call(
        client, "POST", API + "/auth/v3/tenant_access_token/internal",
        json={"app_id": os.environ["LARK_APP_ID"], "app_secret": os.environ["LARK_APP_SECRET"]},
    )
    return result["tenant_access_token"]

async def send_progress(chat_id, question):
    async with httpx.AsyncClient(timeout=20) as client:
        token = await get_token(client)
        payload = {
            "receive_id": chat_id,
            "msg_type": "interactive",
            "content": json.dumps(
                card("AI 分析中", "**问题：** " + question[:160].replace("`", "＇")
                     + "\n\n⏳ 已收到，正在查询 Zabbix 监控数据并进行 AI 分析，请稍候……"),
                ensure_ascii=False),
        }
        result = await api_call(client, "POST", API + "/im/v1/messages",
                                token=token, params={"receive_id_type": "chat_id"}, json=payload)
        message_id = result.get("data", {}).get("message_id")
        if not message_id:
            raise RuntimeError("Feishu response missing progress message_id")
        return message_id

async def update_progress(message_id, result_text, *, failed=False):
    async with httpx.AsyncClient(timeout=20) as client:
        token = await get_token(client)
        payload = {"content": json.dumps(
            card("AI 分析失败" if failed else "AI 分析完成",
                 display_text(result_text), "red" if failed else "green"),
            ensure_ascii=False)}
        return await api_call(client, "PATCH", API + "/im/v1/messages/" + message_id,
                              token=token, json=payload)

def process_question_with_card(chat_id, question, original_message_id):
    """Wrapper around existing worker.process_question; requires old worker implementation."""
    import worker
    progress_id = None
    try:
        progress_id = asyncio.run(send_progress(chat_id, question))
        logger.info("FEISHU_PROGRESS_SENT message_id=%s", original_message_id)
    except Exception:
        logger.exception("FEISHU_PROGRESS_SEND_FAILED message_id=%s", original_message_id)

    original = getattr(worker, "send_app_bot", None)
    if original is None:
        raise RuntimeError("worker.send_app_bot not found")

    async def replacement(*args, **kwargs):
        target = args[0] if args else kwargs.get("chat_id")
        content = args[1] if len(args) > 1 else kwargs.get("text")
        if not progress_id or target != chat_id or content is None:
            return await original(*args, **kwargs)
        try:
            await update_progress(progress_id, content)
            logger.info("FEISHU_CARD_UPDATED message_id=%s", original_message_id)
        except Exception:
            logger.exception("FEISHU_CARD_UPDATE_FAILED message_id=%s", original_message_id)
            await original(*args, **kwargs)

    worker.send_app_bot = replacement
    try:
        return worker.process_question(chat_id, question, original_message_id)
    except Exception:
        if progress_id:
            try:
                asyncio.run(update_progress(
                    progress_id, "分析失败，请稍后重试。错误详情请查看服务器日志。", failed=True))
            except Exception:
                logger.exception("FEISHU_CARD_ERROR_UPDATE_FAILED message_id=%s",
                                 original_message_id)
        raise
    finally:
        worker.send_app_bot = original
