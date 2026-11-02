"""Feishu tenant app message and interactive card operations."""

import hashlib
import json
import threading
import time
import httpx
from .main import read_setting
from .feishu_cards import CardBody, MessageID, message_ids, split_card

ROOT = "https://open.feishu.cn/open-apis"
# A cached tenant token is renewed this long before Feishu says it expires.
TOKEN_MARGIN = 300
_token = {}
_token_lock = threading.Lock()


def make_card(title, text, template="blue", link=None):
    """Render the line carrying token consumption as a separated muted footer,
    not body copy; ``link`` adds a 查看完整诊断报告 button under the body.

    A CardBody (the "AI 分析结果" body, worker.analysis_body) brings its own
    elements, button and footer included, and is sent as it is."""
    if isinstance(text, CardBody):
        return {
            "config": {"wide_screen_mode": True, "update_multi": True},
            "header": {
                "title": {"tag": "plain_text", "content": title},
                "template": template,
            },
            "elements": list(text.elements),
        }
    body = str(text)
    token_line = None
    separator = "\n\n---\n"
    if separator in body:
        before, after = body.rsplit(separator, 1)
        if "本轮 Token 消耗：" in after and "\n" not in after:
            body, token_line = before, after
    elements = [{"tag": "div", "text": {"tag": "lark_md", "content": body}}]
    if link:
        elements.append(
            {
                "tag": "action",
                "actions": [
                    {
                        "tag": "button",
                        "text": {"tag": "plain_text", "content": "查看完整诊断报告"},
                        "type": "default",
                        "url": link,
                    }
                ],
            }
        )
    if token_line:
        elements.extend(
            [
                {"tag": "hr"},
                {
                    "tag": "note",
                    "elements": [
                        {"tag": "plain_text", "content": "◉ " + token_line[:300]}
                    ],
                },
            ]
        )
    return {
        "config": {"wide_screen_mode": True, "update_multi": True},
        "header": {
            "title": {"tag": "plain_text", "content": title},
            "template": template,
        },
        "elements": elements,
    }


def refused_token(response):
    """Feishu turned the request's token down (HTTP 401, or an error code of
    its authentication family, 999916xx)."""
    if response.status_code == 401:
        return True
    try:
        code = int(response.json().get("code") or 0)
    except Exception:
        return False
    return code // 100 == 999916


async def request(client, method, url, token=None, **kwargs):
    headers = {"Authorization": "Bearer " + token} if token else {}
    response = await client.request(method, url, headers=headers, **kwargs)
    if token and refused_token(response):
        forget_token(token)
    response.raise_for_status()
    data = response.json()
    if data.get("code", 0) != 0:
        raise RuntimeError(
            "Feishu API error code=%s message=%s"
            % (data.get("code"), str(data.get("msg", ""))[:120])
        )
    return data


def forget_token(token=None):
    """Drop the cached tenant token (only if it is `token`, when given)."""
    with _token_lock:
        if token is None or _token.get("value") == token:
            _token.clear()


async def get_token(client):
    """The app's tenant_access_token, reused until TOKEN_MARGIN seconds before
    the expiry Feishu gives with it (2 hours; Feishu itself hands out the
    same token until its last 30 minutes). Every alert card, reply and card
    update used to fetch one first. Another App ID or Secret fetches anew;
    so does the next call after Feishu refuses the token (request())."""
    app_id = read_setting("lark_app_id")
    secret = read_setting("lark_app_secret")
    key = (app_id, hashlib.sha256(secret.encode()).hexdigest())
    with _token_lock:
        cached = dict(_token)
    if cached.get("key") == key and cached["until"] > time.monotonic():
        return cached["value"]
    data = await request(
        client,
        "POST",
        ROOT + "/auth/v3/tenant_access_token/internal",
        json={"app_id": app_id, "app_secret": secret},
    )
    token = data["tenant_access_token"]
    try:
        lifetime = int(data.get("expire") or 0)
    except (TypeError, ValueError):
        lifetime = 0
    # Kept only for as long as Feishu says it lasts.
    if lifetime > TOKEN_MARGIN:
        with _token_lock:
            _token.clear()
            _token.update(
                key=key, value=token, until=time.monotonic() + lifetime - TOKEN_MARGIN
            )
    return token


async def send_rendered_card(client, token, card, *, chat_id=None, reply_to=None):
    parts = split_card(card)
    first = None
    ids = []
    for part in parts:
        payload = {
            "msg_type": "interactive",
            "content": json.dumps(part, ensure_ascii=False),
        }
        kwargs = {}
        url = ROOT + "/im/v1/messages"
        if reply_to:
            url += "/" + reply_to + "/reply"
            payload["reply_in_thread"] = False
        else:
            payload["receive_id"] = chat_id
            kwargs["params"] = {"receive_id_type": "chat_id"}
        response = await request(client, "POST", url, token, json=payload, **kwargs)
        if first is None:
            first = response
        result_id = (response.get("data") or {}).get("message_id")
        if result_id:
            ids.append(result_id)
        elif len(parts) > 1:
            raise RuntimeError("飞书分段回复未返回消息 ID")
    if ids:
        first.setdefault("data", {})["message_id"] = MessageID(ids[0], ids)
    return first


async def reply_card(message_id, title, text, template="blue", link=None):
    """Reply to the original Feishu message; return the reply message ID.

    The reply stays associated with the user's message. Later progress updates
    PATCH this reply rather than posting additional group messages.
    """
    if not message_id:
        raise ValueError("original message ID is required for a reply")
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        result = await send_rendered_card(
            client, token, make_card(title, text, template, link), reply_to=message_id
        )
        reply_id = (result.get("data") or {}).get("message_id")
        if not reply_id:
            raise RuntimeError("飞书回复成功但未返回消息 ID")
        return reply_id


async def update_card(message_id, title, text, template="green", link=None):
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        parts = split_card(make_card(title, text, template, link))
        response = await request(
            client,
            "PATCH",
            ROOT + "/im/v1/messages/" + message_id,
            token,
            json={"content": json.dumps(parts[0], ensure_ascii=False)},
        )
        ids = [str(message_id)]
        for part in parts[1:]:
            sent = await send_rendered_card(client, token, part, reply_to=message_id)
            ids.extend(message_ids((sent.get("data") or {}).get("message_id")))
        if isinstance(message_id, MessageID):
            message_id.message_ids = tuple(ids)
        return response
