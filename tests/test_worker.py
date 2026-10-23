import asyncio
from unittest.mock import AsyncMock

from app import worker

def test_alert_prompt_keeps_required_json_contract():
    value = worker.alert_instructions("请重点分析网络性能")
    assert "host_groups,cause,action,analysis,human_required" in value
    assert "重点分析网络性能" in value

def test_all_alerts_notified_before_ai_and_severity_gate(monkeypatch):
    sent=[]
    async def notify(card, event=None):
        sent.append(card)
    async def analyze(event):
        assert len(sent) == 2  # low-priority card + original severe card
        return {"host_groups":"test","cause":"原因","action":"处理","analysis":"AI诊断","human_required":False}
    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(worker, "analyze", analyze)
    monkeypatch.setattr(worker, "cfg",lambda key: "4" if key=="ai_min_severity" else "")
    low=asyncio.run(worker.handle_alert({"event_id":"low","severity":"2","event_value":"1"}))
    assert low["ai_skipped"] is True
    assert len(sent)==1
    high=asyncio.run(worker.handle_alert({"event_id":"high","severity":"4","event_value":"1"}))
    assert high["diagnosed"] is True
    assert len(sent)==3
    recovered=asyncio.run(worker.handle_alert({"event_id":"recovered","severity":"5","event_value":"0"}))
    assert recovered["ai_skipped"] is True
    assert len(sent)==3
    assert recovered["recovery_suppressed"] is True


def test_ai_failure_does_not_block_initial_alert(monkeypatch):
    async def broken(_):
        raise RuntimeError("model offline")
    sent=[]
    async def notify(card, event=None):
        sent.append(card)
    monkeypatch.setattr(worker, "cfg",lambda key:"4" if key=="ai_min_severity" else "")
    monkeypatch.setattr(worker, "analyze", broken)
    monkeypatch.setattr(worker, "notify", notify)
    result=asyncio.run(worker.handle_alert({"event_id":"12345","severity":"4","event_value":"1"}))
    assert result["ai_failed"] is True and result["notified"] is True
    assert len(sent)==1


def test_enterprise_app_alert_notifier(monkeypatch):
    from app import feishu_client
    sent = []
    monkeypatch.setattr(worker, "cfg", lambda k: {
        "feishu_enabled": "true",
        "feishu_alert_chat_ids": "oc_test_1,oc_test_2",
        "allowed_chat_ids": "",
    }.get(k, ""))
    async def token(_client):
        return "mock-token"
    async def request(_client, method, url, auth, **kwargs):
        sent.append(kwargs["json"]["receive_id"])
        return {"code": 0}
    monkeypatch.setattr(feishu_client, "get_token", token)
    monkeypatch.setattr(feishu_client, "request", request)
    asyncio.run(worker.notify({"header": {"title": {"content": "test"}}}))
    assert sent == ["oc_test_1", "oc_test_2"]

def test_feishu_reply_card_uses_original_message(monkeypatch):
    from app import feishu_client
    import json
    sent = []
    async def fake_token(client):
        return "test-token"
    async def fake_request(client, method, url, token=None, **kwargs):
        sent.append((method, url, kwargs["json"]))
        return {"data":{"message_id":"om_reply"}}
    monkeypatch.setattr(feishu_client,"get_token",fake_token)
    monkeypatch.setattr(feishu_client,"request",fake_request)
    result=asyncio.run(feishu_client.reply_card("om_source","AI 分析中","正在分析"))
    assert result=="om_reply"
    assert sent[0][0]=="POST"
    assert sent[0][1].endswith("/im/v1/messages/om_source/reply")
    assert sent[0][2]["reply_in_thread"] is False
    assert json.loads(sent[0][2]["content"])["header"]["title"]["content"]=="AI 分析中"

def test_compact_alert_card_and_recovery():
    event={"event_id":"6056231","severity":"2","event_value":"1",
           "host_name":"DESKTOP","host_ip":"172.20.108.2","host_groups":"Office"}
    card=worker.make_card(event)
    body=str(card)
    assert "Office" in body
    assert "故障原因" not in body and "处理建议" not in body
    assert "AI 分析" not in body and "需人工核验" not in body
    recovered=worker.make_card({**event,"event_value":"0"})
    assert recovered["header"]["template"]=="green"
    assert "告警恢复" in recovered["header"]["title"]["content"]

def test_severe_analysis_has_detail():
    event={"event_id":"6056232","severity":"4","event_value":"1"}
    details={"cause":"CPU 排队","action":"核对进程","analysis":"指标趋势"}
    initial=worker.make_card(event,details)
    analyzed=worker.make_card(event,details,analysis=True)
    assert "故障原因" not in str(initial)
    assert "故障原因" in str(analyzed)

def test_alert_card_newlines_are_real():
    card = worker.make_card({"event_id":"12345","severity":"3","event_value":"1",
        "host_name":"C15-HX-M","host_ip":"172.20.202.1","event_name":"Link down"})
    body = card["elements"][0]["text"]["content"]
    assert "\n" in body
    assert "\\n" not in body
    assert body.splitlines()[0] == "**主机名称**  C15-HX-M"

def test_zabbix_alarm_and_recovery_event_times():
    event={"event_id":"600001","severity":"2","event_value":"1",
           "event_date":"2026.10.19","event_time":"19:53:20",
           "recovery_date":"2026.10.19","recovery_time":"20:01:21"}
    problem=str(worker.make_card(event))
    assert "发生时间" in problem and "19:53:20" in problem
    recovered=str(worker.make_card({**event,"event_value":"0"}))
    assert "恢复时间" in recovered and "20:01:21" in recovered
    unresolved=str(worker.make_card({**event,"event_date":"{EVENT.DATE}"}))
    assert "发生时间" not in unresolved

def test_recovery_duration_and_group_are_rendered():
    event = {"event_id":"123456","event_value":"0","severity":"4",
        "host_name":"C15-HX-M","host_groups":"Core/Switch",
        "event_date":"2026.10.20","event_time":"10:00:00",
        "recovery_date":"2026.10.20","recovery_time":"10:18:02",
        "event_duration":"18m 02s"}
    card=worker.make_card(event)
    body=card["elements"][0]["text"]["content"]
    assert card["header"]["template"]=="green"
    assert "所属分组" in body and "Core/Switch" in body
    assert "持续时间" in body and "18m 02s" in body
    assert "恢复时间" in body and "10:18:02" in body
    assert "故障原因" not in body

def test_duration_calculated_when_macro_unresolved():
    from app.worker import event_duration
    assert event_duration({"event_date":"2026.10.20","event_time":"10:00:00",
        "recovery_date":"2026.10.20","recovery_time":"10:03:27",
        "event_duration":"{EVENT.DURATION}"})=="00:03:27"

def test_zabbix_event_deep_link():
    event={"event_id":"6057922","trigger_id":"102345","severity":"3",
        "event_value":"1","event_name":"Link down"}
    card=worker.make_card(event)
    body=card["elements"][0]["text"]["content"]
    assert "事件来源" not in body
    assert any(b.get("url","").endswith("triggerid=102345&eventid=6057922") for e in card["elements"] if e["tag"]=="action" for b in e["actions"])
    assert "172.20.200.93 转发" not in body
    recovery=worker.make_card({**event,"event_value":"0"})
    assert any("eventid=6057922" in b.get("url","") for e in recovery["elements"] if e["tag"]=="action" for b in e["actions"])
    no_id=worker.make_card({**event,"trigger_id":"{TRIGGER.ID}"})
    assert "tr_events.php" not in str(no_id)

def test_alert_mute_button_targets_host_and_trigger():
    event={"event_id":"777001","host_id":"101","trigger_id":"202",
           "severity":"2","event_value":"1","event_name":"Load high"}
    card=worker.make_card(event)
    buttons=[a for el in card["elements"] if el["tag"]=="action" for a in el["actions"]]
    assert len(buttons)==3
    actions=[b for b in buttons if "value" in b]
    assert {b["value"]["op"] for b in actions}=={"choose_mute","analyze_alert"}
    assert all(b["value"]["trigger_id"]=="202" and b["value"]["event_id"]=="777001" for b in actions)
    assert buttons[0]["url"].startswith("http")
    recovery=worker.make_card({**event,"event_value":"0"})
    assert [b["value"]["op"] for el in recovery["elements"] if el["tag"]=="action" for b in el["actions"] if "value" in b] == ["analyze_alert"]

def test_alert_mute_requires_matching_identity():
    event={"event_id":"777002","host_id":"{HOST.ID}","trigger_id":"202",
           "severity":"2","event_value":"1"}
    card=worker.make_card(event)
    assert all(b.get("value", {}).get("op") != "choose_mute" for e in card["elements"] if e["tag"]=="action" for b in e["actions"])

def test_recovery_sent_only_for_original_feishu_sent_problem(monkeypatch):
    from app.main import connection
    sent=[]
    async def notify(card, event=None):
        sent.append(card)
    monkeypatch.setattr(worker,"notify",notify)
    monkeypatch.setattr(worker,"cfg",lambda key:"true" if key=="feishu_enabled" else "4")
    for eid,state in [("paired001","sent"),("muted001","muted"),
                      ("failed001","failed"),("disabled001","disabled")]:
        with connection() as db:
            db.execute("""INSERT OR REPLACE INTO alert_events
                (event_id,event_value,event_name,host_name,severity,notify_status)
                VALUES (?, '1', 'test', 'host', 2, ?)""",(eid,state))
    for eid in ("muted001","failed001","disabled001","missing001"):
        result=asyncio.run(worker.handle_alert({"event_id":eid,"event_value":"0","severity":"2"}))
        assert result["recovery_suppressed"] is True
    assert sent==[]
    result=asyncio.run(worker.handle_alert({"event_id":"paired001","event_value":"0","severity":"2"}))
    assert result["notified"] is True
    assert len(sent)==1

def test_mute_summary_follows_action_buttons():
    event={"event_id":"773310","host_id":"101","trigger_id":"202","severity":"2",
           "event_value":"1","event_name":"CPU high"}
    card=worker.make_card(event,mute_info={"operator":"ou_admin","duration":"4 小时",
        "time":"2026-10-21 10:00:00","expires":"2026-10-21 14:00:00"})
    assert card["config"]["update_multi"] is True
    assert "临时屏蔽仅影响后续飞书通知" not in str(card)
    assert not any(el["tag"]=="column_set" for el in card["elements"])
    assert "ou_admin" in str(card["elements"][-1])
    assert "4 小时" in str(card["elements"][-1])
    assert card["elements"][-1]["extra"]["value"]["op"]=="unmute_alert"

def test_manual_analysis_progress_updates_and_context_for_both_states(monkeypatch):
    from app import feishu_client, conversation_context
    from app.main import connection
    events=[]
    async def analyze(event):
        return {"cause":"负载较高","action":"检查进程","analysis":"CPU趋势连续上升"}
    async def reply(message_id,title,detail):
        events.append(("reply",message_id,title,detail))
        return "om_progress"
    async def update(message_id,title,detail,template="green"):
        events.append(("update",message_id,title,detail))
    async def chat(message_id):
        return "oc_group"
    saved=[]
    monkeypatch.setattr(worker,"analyze",analyze)
    monkeypatch.setattr(feishu_client,"reply_card",reply)
    monkeypatch.setattr(feishu_client,"update_card",update)
    monkeypatch.setattr(conversation_context,"remember",lambda *args, **kwargs: saved.append(args))
    monkeypatch.setattr(conversation_context,"mark_pending",lambda *args: None)
    monkeypatch.setattr(conversation_context,"clear_pending",lambda *args: None)
    for state in ("1","0"):
        events.clear()
        result=asyncio.run(worker.analyze_on_demand(
            {"event_id":"773311","severity":"2","event_value":state,"event_name":"CPU high","host_name":"node1","host_ip":"172.20.2.101"},"om_original","oc_group"))
        assert result["diagnosed"]
        assert len(events)==2
        assert events[0][0:3]==("reply","om_original","AI 分析中")
        assert events[1][0:3]==("update","om_progress","AI 分析结果")
        assert "CPU趋势连续上升" in events[1][3]
        assert saved[-1][0:3]==("oc_group","om_original","om_progress")


def test_recovery_replies_to_matching_chat_messages(monkeypatch):
    from app import feishu_client
    from app.main import connection
    sent=[]
    event={"event_id":"recovery-link-900","event_value":"1"}
    async def token(_client):
        return "token"
    async def request(_client,method,url,auth,**kwargs):
        sent.append((url,kwargs))
        return {"data":{"message_id":"om_" + kwargs["json"]["receive_id"]}} if "receive_id" in kwargs.get("json",{}) else {"data":{"message_id":"om_reply"}}
    monkeypatch.setattr(feishu_client,"get_token",token)
    monkeypatch.setattr(feishu_client,"request",request)
    monkeypatch.setattr(worker,"cfg",lambda key: {
        "feishu_enabled":"true","feishu_alert_chat_ids":"oc_chat1,oc_chat2"}.get(key,""))
    asyncio.run(worker.notify({"elements":[]},event=event))
    with connection() as db:
        ids=db.execute("SELECT chat_id,message_id FROM alert_message_links WHERE event_id=? ORDER BY chat_id",
                       (event["event_id"],)).fetchall()
    assert ids==[("oc_chat1","om_oc_chat1"),("oc_chat2","om_oc_chat2")]
    sent.clear()
    asyncio.run(worker.notify({"elements":[]},event={**event,"event_value":"0"}))
    assert len(sent)==2
    assert sent[0][0].endswith("/om_oc_chat1/reply")
    assert sent[1][0].endswith("/om_oc_chat2/reply")
    assert all(entry[1]["json"]["reply_in_thread"] is False for entry in sent)

def test_feishu_card_does_not_nest_action_inside_column():
    event={"event_id":"100200","host_id":"101","trigger_id":"202","severity":"2","event_value":"1"}
    from app.worker import make_card
    card=make_card(event)
    assert any(el["tag"]=="action" for el in card["elements"])
    assert not any(el["tag"]=="column_set" for el in card["elements"])
    assert [b["value"]["op"] for e in card["elements"] if e["tag"]=="action" for b in e["actions"] if "value" in b] == ["analyze_alert","choose_mute"]

def test_source_button_precedes_actions_for_problem_and_recovery():
    event={"event_id":"6180279","host_id":"101","trigger_id":"202","severity":"3","event_value":"1"}
    problem=worker.make_card(event)
    recovery=worker.make_card({**event,"event_value":"0"})
    for card, expected in ((problem,["url","analyze_alert","choose_mute"]),
                           (recovery,["url","analyze_alert"])):
        assert "**告警操作**" not in str(card)
        buttons=next(e["actions"] for e in card["elements"] if e["tag"]=="action")
        found=["url" if "url" in b else b["value"]["op"] for b in buttons]
        assert found==expected
        assert buttons[0]["url"].startswith("http")
    recovery_buttons=next(e["actions"] for e in recovery["elements"] if e["tag"]=="action")
    assert recovery_buttons[1]["value"]["event_value"]=="0"

def test_latest_value_for_problem_and_recovery():
    base={"event_id":"700001","trigger_id":"800001","host_id":"100001",
          "severity":"2","event_name":"CPU high"}
    problem=worker.make_card({**base,"event_value":"1","latest_value":"89.4 %"})
    restored=worker.make_card({**base,"event_value":"0","latest_value":"31.2 %","recovery_value":"29 %"})
    assert "**事件数值**  89.4 %" in problem["elements"][0]["text"]["content"]
    assert "**事件数值**  31.2 %" in restored["elements"][0]["text"]["content"]
    fallback=worker.make_card({**base,"event_value":"0","recovery_value":"0"})
    assert "**事件数值**  未提供" in fallback["elements"][0]["text"]["content"]
    unknown=worker.make_card({**base,"event_value":"1","latest_value":"{ITEM.LASTVALUE1}"})
    assert "**事件数值**  未提供" in unknown["elements"][0]["text"]["content"]
    zero=worker.make_card({**base,"event_value":"1","latest_value":"0"})
    assert "**事件数值**  0" in zero["elements"][0]["text"]["content"]

def test_event_detail_overrides_latest_value():
    event={"event_id":"910001","event_value":"1","event_name":"Link down","event_detail":"Current state: down (2)","latest_value":"2"}
    card=worker.make_card(event)
    assert "**事件数值**  2" in card["elements"][0]["text"]["content"]
    assert "Current state: down (2)" not in card["elements"][0]["text"]["content"]
    recovery=worker.make_card({**event,"event_value":"0","event_detail":"Current state: up (1)"})
    assert "**事件数值**  2" in recovery["elements"][0]["text"]["content"]


def test_recovery_status_is_not_event_detail():
    card=worker.make_card({"event_id":"6190507","event_value":"0","recovery_value":"0","event_detail":""})
    assert "**事件数值**  未提供" in card["elements"][0]["text"]["content"]

def test_automatic_analysis_card_shows_token_usage():
    event={"event_id":"123","severity":"4","event_value":"1"}
    info={"cause":"CPU高","action":"查看指标","analysis":"历史趋势",
          "_token_usage":{"input":750,"output":250,"total":1000,"available":True}}
    card=worker.make_card(event,info,analysis=True)
    assert "本轮 Token 消耗：1,000（输入 750 / 输出 250）" in str(card)

def test_token_footer_separate_from_body_in_feishu_card():
    from app.feishu_client import make_card
    card = make_card("AI 分析结果", "故障原因：测试\n\n---\n本轮 Token 消耗：1,234（输入 1,000 / 输出 234）")
    assert len(card["elements"]) == 3
    assert card["elements"][1]["tag"] == "hr"
    assert "Token 消耗" not in card["elements"][0]["text"]["content"]
    assert card["elements"][2]["tag"] == "note"
    assert "1,234" in card["elements"][2]["elements"][0]["content"]

def test_native_feishu_token_footer():
    from app.feishu_client import make_card
    card=make_card("AI 分析结果","结果文本\n\n---\n本轮 Token 消耗：300（输入 250 / 输出 50）")
    assert [e["tag"] for e in card["elements"]]==["div","hr","note"]
    assert "Token 消耗" not in card["elements"][0]["text"]["content"]
    assert "300" in card["elements"][2]["elements"][0]["content"]


def test_alert_token_usage_is_persisted():
    from app.main import connection
    from app.worker import store_alert_usage
    event={"event_id":"test_usage_001","event_value":"1"}
    with connection() as db:
        db.execute("INSERT OR IGNORE INTO alert_events(event_id,event_value,event_name) VALUES (?,'1','token test')",
                   (event["event_id"],))
    store_alert_usage(event, {"available":True,"total":120,"input":100,"output":20})
    with connection() as db:
        row=db.execute("SELECT token_total,token_input,token_output FROM alert_events WHERE event_id=? AND event_value='1'",
                       (event["event_id"],)).fetchone()
    assert row==(120,100,20)
