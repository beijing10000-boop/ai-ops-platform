"""Signed Feishu card actions: mute only application notifications, never Zabbix."""
import hashlib
import hmac
import os
import time
from .main import connection, read_setting

DURATIONS={1,4,24,72,168}

def action_signature(host_id, trigger_id, hours):
    key=os.environ.get("APP_ENCRYPTION_KEY","")
    if not key:
        raise RuntimeError("APP_ENCRYPTION_KEY missing")
    payload=f"mute_alert:{host_id}:{trigger_id}:{hours}".encode()
    return hmac.new(key.encode(),payload,hashlib.sha256).hexdigest()

def handle_mute_action(value, operator_open_id):
    if not isinstance(value,dict) or value.get("op")!="mute_alert":
        return False,"不支持的操作"
    ids = read_setting("feishu_admin_open_ids")
    admins={x.strip() for x in ids.split(",") if x.strip()}
    if not operator_open_id or operator_open_id not in admins:
        return False,"仅飞书管理员可以暂停告警通知"
    host=str(value.get("host_id",""))
    trigger=str(value.get("trigger_id",""))
    try:
        hours=int(value.get("hours"))
    except (TypeError,ValueError):
        return False,"无效屏蔽时长"
    if not(host.isdigit() and trigger.isdigit() and hours in DURATIONS):
        return False,"无效的告警或屏蔽时长"
    signature=str(value.get("sig",""))
    if not hmac.compare_digest(signature,action_signature(host,trigger,hours)):
        return False,"卡片校验失败，请使用最新的告警卡片"
    expires=int(time.time())+hours*3600
    with connection() as db:
        db.execute("""INSERT INTO alert_mutes(host_id,trigger_id,expires_at)
             VALUES(?,?,?) ON CONFLICT(host_id,trigger_id)
             DO UPDATE SET expires_at=excluded.expires_at,created_at=CURRENT_TIMESTAMP""",
             (host,trigger,expires))
        db.execute("INSERT INTO audit(action,key) VALUES (?,?)",
            ("alert_mute_feishu",f"{host}:{trigger}"))
    return True,f"已屏蔽此主机同一触发器的飞书告警 {hours} 小时；Zabbix 与恢复通知不受影响"
