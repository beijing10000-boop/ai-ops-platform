"""Single Feishu WebSocket receiver. Never perform AI operations in callbacks."""
import json
import logging
import re
from redis import Redis
from rq import Queue
import lark_oapi as lark
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1
from lark_oapi.event.callback.model.p2_card_action_trigger import P2CardActionTrigger, P2CardActionTriggerResponse
from .alert_mute import handle_mute_action
from .alert_actions import handle_analyze_action, handle_choose_mute, handle_unmute_action
from .main import read_setting, REDIS_URL

log = logging.getLogger(__name__)
redis = Redis.from_url(REDIS_URL)
queue = Queue("ai-questions",connection=redis)

def on_message(data: P2ImMessageReceiveV1):
    message = data.event.message
    sender = data.event.sender
    msg_id = message.message_id
    log.warning("FEISHU_RECEIVED chat_id=%s message_id=%s",message.chat_id,msg_id)
    if sender.sender_type != "user" or message.chat_type != "group" or message.message_type != "text":
        log.info("FEISHU_FILTERED reason=type message_id=%s",msg_id)
        return
    groups = {s.strip() for s in read_setting("allowed_chat_ids").split(",") if s.strip()}
    if message.chat_id not in groups:
        log.warning("FEISHU_FILTERED reason=chat_not_allowed message_id=%s",msg_id)
        return
    try:
        question = json.loads(message.content).get("text","")
        question = re.sub(r"@_user_\d+","",question).strip()
    except (ValueError,TypeError,AttributeError):
        log.warning("FEISHU_FILTERED reason=invalid_content message_id=%s",msg_id)
        return
    if not question:
        log.info("FEISHU_FILTERED reason=empty_question message_id=%s",msg_id)
        return
    key="feishu-ai:message:"+msg_id
    if not redis.set(key,"queued",nx=True,ex=86400):
        log.info("FEISHU_DUPLICATE message_id=%s",msg_id)
        return
    sender_id = getattr(getattr(sender,"sender_id",None),"open_id",None)
    parent_id = getattr(message,"parent_id",None)
    root_id = getattr(message,"root_id",None)
    try:
        queue.enqueue("app.qa_worker.process_question", message.chat_id,question[:3000],msg_id,
                      sender_id, parent_id or root_id, root_id,
                      job_timeout=360)
        log.warning("FEISHU_QUEUED message_id=%s",msg_id)
    except Exception:
        redis.delete(key)
        log.exception("FEISHU_ENQUEUE_FAILED message_id=%s",msg_id)
        raise

def on_card_action(data: P2CardActionTrigger) -> P2CardActionTriggerResponse:
    """Callback must finish within three seconds. Never log tokens or signatures."""
    try:
        event=data.event
        action=getattr(event,"action",None)
        value=getattr(action,"value",None) or {}
        if isinstance(value,str):
            value=json.loads(value)
        operator=getattr(event,"operator",None)
        open_id=getattr(operator,"open_id",None) or getattr(operator,"operator_id",None)
        context=getattr(event,"context",None)
        message_id=getattr(context,"open_message_id",None)
        if value.get("op") == "choose_mute":
            ok, message, card = handle_choose_mute(value, open_id)
            if ok:
                return P2CardActionTriggerResponse({"toast": {"type": "info", "content": message}, "card": {"type": "raw", "data": card}})
        elif value.get("op") == "unmute_alert":
            ok,message,card=handle_unmute_action(value,open_id)
            if ok:
                return P2CardActionTriggerResponse({"toast":{"type":"success","content":message}, "card":{"type":"raw","data":card}})
        elif value.get("op") == "analyze_alert":
            ok,message=handle_analyze_action(value,open_id,message_id,
                    getattr(context,"chat_id",None) or getattr(context,"open_chat_id",None))
            log.info("FEISHU_ANALYZE_ACTION success=%s",ok)
        else:
            ok,message=handle_mute_action(value,open_id)
            log.info("FEISHU_MUTE_ACTION success=%s",ok)
            if ok:
                from .alert_actions import card_after_mute
                card=card_after_mute(value,open_id)
                return P2CardActionTriggerResponse({"toast":{"type":"success","content":"暂时屏蔽成功"},"card":{"type":"raw","data":card}})
        return P2CardActionTriggerResponse({
            "toast":{"type":"success" if ok else "error","content":message}
        })
    except Exception:
        log.exception("FEISHU_MUTE_ACTION_FAILED")
        return P2CardActionTriggerResponse({
            "toast":{"type":"error","content":"操作失败，请稍后再试"}
        })

handler=(lark.EventDispatcherHandler.builder("","")
         .register_p2_im_message_receive_v1(on_message)
         .register_p2_card_action_trigger(on_card_action)
         .build())

def main():
    app_id=read_setting("lark_app_id")
    secret=read_setting("lark_app_secret")
    if not app_id or not secret:
        raise RuntimeError("在 Web 后台先设置飞书 App ID 和 Secret")
    lark.ws.Client(app_id,secret,event_handler=handler,log_level=lark.LogLevel.INFO).start()

if __name__ == "__main__":
    main()
