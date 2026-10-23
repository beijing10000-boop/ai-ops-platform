"""Feishu tenant app message and interactive card operations."""
import json
import logging
import httpx
from .main import read_setting
log = logging.getLogger(__name__)
ROOT = "https://open.feishu.cn/open-apis"

def make_card(title, text, template="blue"):
    """Render token consumption as a separated muted footer, not body copy."""
    body = str(text)
    token_line = None
    separator = "\n\n---\n"
    if separator in body:
        before, after = body.rsplit(separator, 1)
        if after.startswith("本轮 Token 消耗：") and "\n" not in after:
            body, token_line = before, after
    elements = [{"tag": "div", "text": {"tag": "lark_md", "content": body[:11000]}}]
    if token_line:
        elements.extend([
            {"tag": "hr"},
            {"tag": "note", "elements": [{"tag": "plain_text",
                "content": "◉ " + token_line[:220]}]},
        ])
    return {"config":{"wide_screen_mode":True,"update_multi":True},
            "header":{"title":{"tag":"plain_text","content":title},"template":template},
            "elements":elements}

async def request(client, method, url, token=None, **kwargs):
    headers = {"Authorization": "Bearer "+token} if token else {}
    response = await client.request(method,url,headers=headers,**kwargs)
    response.raise_for_status()
    data = response.json()
    if data.get("code",0) != 0:
        raise RuntimeError("Feishu API error code=%s message=%s" % (data.get("code"),str(data.get("msg",""))[:120]))
    return data

async def get_token(client):
    data = await request(client,"POST",ROOT+"/auth/v3/tenant_access_token/internal",
                         json={"app_id":read_setting("lark_app_id"),"app_secret":read_setting("lark_app_secret")})
    return data["tenant_access_token"]

async def send_card(chat_id,title,text,template="blue"):
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        result = await request(client,"POST",ROOT+"/im/v1/messages",token,
            params={"receive_id_type":"chat_id"},
            json={"receive_id":chat_id,"msg_type":"interactive",
                  "content":json.dumps(make_card(title,text,template),ensure_ascii=False)})
        return result.get("data",{}).get("message_id")

async def reply_card(message_id, title, text, template="blue"):
    """Reply to the original Feishu message; return the reply message ID.

    The reply stays associated with the user's message. Later progress updates
    PATCH this reply rather than posting additional group messages.
    """
    if not message_id:
        raise ValueError("original message ID is required for a reply")
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        result = await request(client, "POST",
            ROOT + "/im/v1/messages/" + message_id + "/reply", token,
            json={"msg_type": "interactive",
                  "content": json.dumps(make_card(title, text, template), ensure_ascii=False),
                  "reply_in_thread": False})
        reply_id = (result.get("data") or {}).get("message_id")
        if not reply_id:
            raise RuntimeError("飞书回复成功但未返回消息 ID")
        return reply_id


async def update_card(message_id,title,text,template="green"):
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        return await request(client,"PATCH",ROOT+"/im/v1/messages/"+message_id,token,
            json={"content":json.dumps(make_card(title,text,template),ensure_ascii=False)})

async def send_text(chat_id,text):
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        return await request(client,"POST",ROOT+"/im/v1/messages",token,
            params={"receive_id_type":"chat_id"},
            json={"receive_id":chat_id,"msg_type":"text",
                  "content":json.dumps({"text":text},ensure_ascii=False)})


async def get_message_chat_id(message_id):
    """Fetch the source chat to bind follow-up context to that exact Feishu group."""
    if not message_id or not str(message_id).startswith("om_"):
        return None
    async with httpx.AsyncClient(timeout=20) as client:
        token = await get_token(client)
        result = await request(client, "GET", ROOT + "/im/v1/messages/" + message_id, token)
    for message in (result.get("data") or {}).get("items") or []:
        if message.get("message_id") == message_id or len((result.get("data") or {}).get("items") or []) == 1:
            return message.get("chat_id")
    return None
