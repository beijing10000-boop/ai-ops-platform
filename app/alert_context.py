"""Resolve Feishu replied alert message and extract a Zabbix event id."""
import json
import re
from .feishu_client import ROOT, get_token, request
import httpx

EVENT_RE = re.compile(r'(?:事件\s*ID|Event\s*ID|event_id|事件ID)\s*[：:=" ]+\s*(\d{3,20})',re.I)
def extract_event_id(content):
    if not content: return None
    if isinstance(content,dict):
        for k,v in content.items():
            if k == "event_id" and str(v).isdigit():return str(v)
            found=extract_event_id(v)
            if found:return found
        return None
    if isinstance(content,list):
        for entry in content:
            found=extract_event_id(entry)
            if found:return found
        return None
    if isinstance(content,str):
        hit=EVENT_RE.search(content)
        if hit:return hit.group(1)
        try:
            parsed=json.loads(content)
        except (ValueError,TypeError):
            return None
        if parsed != content:
            return extract_event_id(parsed)
    return None

async def resolve_replied_event(parent_id, chat_id):
    if not parent_id or not parent_id.startswith("om_"):
        return None
    async with httpx.AsyncClient(timeout=20) as client:
        token=await get_token(client)
        payload=await request(client,"GET",ROOT+"/im/v1/messages/"+parent_id,token=token)
    items=payload.get("data",{}).get("items",[])
    for item in items:
        if item.get("chat_id") != chat_id:
            continue
        value=extract_event_id(item.get("body",{}).get("content",""))
        if value:return value
    return None
