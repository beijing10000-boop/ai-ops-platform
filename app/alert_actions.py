"""Signed Feishu alert actions and personalized duration selector."""
import hmac
import json
import logging
from redis import Redis
from rq import Queue
from .alert_mute import action_signature
from .main import connection, REDIS_URL, read_setting

log = logging.getLogger(__name__)

def _event(value):
    event_id = str(value.get("event_id") or "")
    trigger_id = str(value.get("trigger_id") or "")
    if not (event_id.isdigit() and trigger_id.isdigit()):
        return None
    expected = action_signature(event_id, trigger_id, 0)
    if not hmac.compare_digest(str(value.get("sig") or ""), expected):
        return None
    state = str(value.get("event_value") or "1")
    if state not in ("0", "1"):
        return None
    with connection() as db:
        row = db.execute("SELECT event_json FROM alert_events WHERE event_id=? AND event_value=?",
                         (event_id, state)).fetchone()
    if not row or not row[0]:
        return None
    try:
        event = json.loads(row[0])
    except (ValueError, TypeError):
        return None
    if (str(event.get("trigger_id")) != trigger_id or str(event.get("event_id")) != event_id
            or str(event.get("event_value")) != state):
        return None
    return event

def _authorized(operator_open_id):
    import os
    ids = read_setting("feishu_admin_open_ids")
    admins = {s.strip() for s in ids.split(",") if s.strip()}
    return operator_open_id in admins if operator_open_id else False

def handle_choose_mute(value, operator_open_id):
    """Return a replacement card visible only to clicking user (update_multi=False)."""
    if not _authorized(operator_open_id):
        return False, "仅飞书管理员可以暂停告警通知", None
    event = _event(value)
    if event is None or str(event.get("event_value")) != "1":
        return False, "告警已过期或卡片签名无效", None
    from .worker import make_card
    card = make_card(event)
    host = str(event["host_id"])
    trigger = str(event["trigger_id"])
    buttons = []
    for hours, label in ((1, "1小时"), (4, "4小时"), (24, "24小时"),
                         (72, "3天"), (168, "7天")):
        buttons.append({"tag": "button", "text": {"tag": "plain_text", "content": label},
            "type": "primary" if hours == 1 else "default",
            "value": {"op": "mute_alert", "event_id": str(event["event_id"]), "host_id": host, "trigger_id": trigger,
                      "hours": hours, "sig": action_signature(host, trigger, hours)}})
    card["config"]["update_multi"] = True
    # Replace exactly the action row, not positional trailing card elements.
    actions = card["elements"]
    index = next((i for i, item in enumerate(actions) if item.get("tag") == "action" and
                  any(a.get("value", {}).get("op") == "choose_mute" for a in item.get("actions", []))), -1)
    if index < 0:
        return False, "告警卡片缺少操作区", None
    actions[index:index + 1] = [
        {"tag": "div", "text": {"tag": "lark_md", "content": "**选择暂时屏蔽时长**"}},
        {"tag": "action", "actions": buttons}]
    return True, "请选择屏蔽时长", card

def handle_analyze_action(value, operator_open_id, message_id=None, chat_id=None):
    if not _authorized(operator_open_id):
        return False, "仅飞书管理员可以触发 AI 分析"
    event = _event(value)
    if event is None:
        return False, "告警已过期或卡片签名无效"
    if not message_id or not str(message_id).startswith("om_"):
        return False, "无法定位原告警卡片，请使用新告警重试"
    redis = Redis.from_url(REDIS_URL)
    key = "zabbix-ai:manual-analysis:" + event["event_id"]
    if not redis.set(key, "queued", ex=300, nx=True):
        return True, "此告警的 AI 分析已提交，请勿重复点击"
    try:
        Queue("ai-alerts", connection=redis).enqueue(
            "app.worker.process_manual_analysis", event, message_id, chat_id, job_timeout=360)
    except Exception:
        redis.delete(key)
        log.exception("MANUAL_ANALYSIS_ENQUEUE_FAILED")
        return False, "AI 分析任务提交失败"
    return True, "已提交 AI 分析，结果将回复原告警消息"

def card_after_mute(value, operator_open_id):
    """Render the updated shared source card with auditable mute metadata."""
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    from .worker import make_card
    from .main import connection
    host = str(value.get("host_id", ""))
    trigger = str(value.get("trigger_id", ""))
    if not _authorized(operator_open_id):
        raise ValueError("not authorized")
    event_id = str(value.get("event_id") or "")
    if not event_id.isdigit():
        raise ValueError("missing alert event id")
    with connection() as db:
        row = db.execute("SELECT event_json FROM alert_events WHERE event_id=? AND event_value='1'",
                         (event_id,)).fetchone()
        mute = db.execute("SELECT expires_at FROM alert_mutes WHERE host_id=? AND trigger_id=?",
                          (host, trigger)).fetchone()
    event = json.loads(row[0]) if row and row[0] else None
    if not event or not mute or str(event.get("host_id")) != host or str(event.get("trigger_id")) != trigger:
        raise ValueError("original alert not found")
    now = datetime.now(ZoneInfo("Asia/Shanghai"))
    expires = datetime.fromtimestamp(mute[0], ZoneInfo("Asia/Shanghai"))
    info = {"operator": "<at id=" + operator_open_id + "></at>", "duration": str(value["hours"]) + " 小时",
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expires": expires.strftime("%Y-%m-%d %H:%M:%S")}
    card = make_card(event, mute_info=info)
    card["config"]["update_multi"] = True
    return card

def handle_unmute_action(value, operator_open_id):
    """Authorize, verify clicked event identity, and revoke only its matching mute."""
    import time
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from .worker import make_card
    if not _authorized(operator_open_id):
        return False, "仅飞书管理员可以解除屏蔽", None
    event = _event(value)
    if not event or str(event.get("host_id")) != str(value.get("host_id")):
        return False, "告警信息校验失败", None
    host = str(event["host_id"])
    trigger = str(event["trigger_id"])
    if not (host.isdigit() and trigger.isdigit()):
        return False, "无效的主机或触发器", None
    with connection() as db:
        record = db.execute("SELECT expires_at FROM alert_mutes WHERE host_id=? AND trigger_id=?",
                            (host, trigger)).fetchone()
        if not record or record[0] <= int(time.time()):
            return False, "屏蔽已失效，无需重复解除", None
        db.execute("DELETE FROM alert_mutes WHERE host_id=? AND trigger_id=?", (host, trigger))
        db.execute("INSERT INTO audit(action,key) VALUES (?,?)",
                   ("alert_unmute_feishu", host + ":" + trigger))
    at = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    card = make_card(event, mute_info={
        "operator": "<at id=" + operator_open_id + "></at>",
        "duration": "已手动解除", "time": at, "expires": "不再屏蔽", "active": False})
    return True, "已解除屏蔽，后续飞书告警正常发送", card
