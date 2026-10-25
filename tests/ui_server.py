"""Isolated desktop QA server. Never included in the application Docker image."""

import os
import json
import secrets
import tempfile
import time
from typing import Literal
from cryptography.fernet import Fernet

if os.getenv("AIOPS_UI_TEST") != "1":
    raise RuntimeError("Explicit AIOPS_UI_TEST=1 required")
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="aiops-desktop-qa-")
os.environ["APP_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["ALLOW_LEGACY_ADMIN_TOKEN"] = "false"
from app.main import app, connection
from app import feishu_auth
from app.integrations import zabbix
from app.orchestrator import tasks
from fastapi.responses import RedirectResponse

with connection() as db:
    db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_ui_test',0)")
    db.execute("INSERT INTO settings VALUES ('web_public_host','127.0.0.1:8765',0)")
    for index in range(32):
        event = {
            "event_id": str(8000 + index),
            "event_value": "1",
            "host_id": "10001",
            "host_name": "测试主机-" + str(index),
            "event_name": "CPU high",
        }
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,host_name,event_name,severity,notify_status,event_json) VALUES (?,'1',?,?,?,?,?)",
            (
                event["event_id"],
                event["host_name"],
                event["event_name"],
                index % 6,
                "sent",
                json.dumps(event),
            ),
        )
        if index < 8:
            db.execute(
                "INSERT INTO alert_events(event_id,event_value) VALUES (?,'0')",
                (event["event_id"],),
            )
# Enough real rows to exercise page boundaries and status filtering.
for index in range(28):
    previous, _ = tasks.create({"question": "分页验证"}, source="ui_test")
    tasks.finish(previous["task_id"], {"answer": "分页验证记录"})
# Fixture data exists only in this isolated QA entry point, never in the production inventory.
QA_HOSTS = [
    {
        "zabbix_hostid": "10001",
        "name": "UI 测试 · Linux 主机",
        "device_type": "linux",
        "monitored": True,
    },
    {
        "zabbix_hostid": "10002",
        "name": "UI 测试 · 网络设备",
        "device_type": "network",
        "monitored": True,
    },
    {
        "zabbix_hostid": "10003",
        "name": '<img src=x onerror="window.__storedXss=1">',
        "device_type": "unknown",
        "monitored": True,
    },
]


async def qa_monitoring_hosts(read, query="", host_id=None):
    rows = [
        h
        for h in QA_HOSTS
        if (
            h["zabbix_hostid"] == host_id
            if host_id
            else not query
            or query.lower() in h["name"].lower()
            or query == h["zabbix_hostid"]
        )
    ]
    if host_id and not rows:
        raise ValueError("所选主机不存在")
    return rows


zabbix.monitoring_hosts = qa_monitoring_hosts
running, _ = tasks.create({"question": "进度刷新测试"}, source="ui_test")
tasks.start(running["task_id"])
tasks.evidence(
    running["task_id"], "zabbix_mcp", "host_get", {"summary": "进度刷新测试证据"}
)
task, _ = tasks.create(
    {
        "event": {
            "event_name": "UI 测试记录 · CPU 诊断",
            "host_name": QA_HOSTS[0]["name"],
            "host_id": "10001",
        }
    },
    source="ui_test",
    diagnostic_type="cpu",
)
tasks.start(task["task_id"])
tasks.evidence(
    task["task_id"],
    "zabbix_mcp",
    "history_get",
    {
        "summary": {"note": "隔离界面测试数据，用于验证布局，不代表生产观测"},
        "status": "success",
    },
    120,
)
tasks.finish(
    task["task_id"],
    {
        "answer": "## 结论\n隔离界面测试记录，**已有监控证据**。\n\n## 建议\n- 核验主机与时间窗口。\n- 结合实时证据检查原因。\n\n## 依据\n此处展示报告结构，不代表生产观测。",
        "device_type": "linux",
        "limitations": ["尚未连接生产 Zabbix、飞书或 SSH 主机"],
    },
    status="partial",
    duration_ms=1500,
)


@app.get("/__ui_running")
def running_fixture():
    return {"task_id": running["task_id"]}


@app.post("/__ui_progress")
def progress_fixture():
    tasks.evidence(
        running["task_id"], "zabbix_mcp", "history_get", {"summary": "新增证据"}
    )
    tasks.stage(running["task_id"], "ai_reasoning")
    return {"ok": True}


@app.get("/__ui_login")
def test_login(
    role: Literal["super_admin", "ops_admin", "operator", "auditor"] = "super_admin",
):
    raw = secrets.token_urlsafe(32)
    open_id = "ou_ui_test" if role == "super_admin" else "ou_ui_" + role
    with connection() as db:
        feishu_auth._tables(db)
        if role != "super_admin":
            db.execute("INSERT OR REPLACE INTO members VALUES (?,?,1)", (open_id, role))
        db.execute(
            "INSERT INTO admin_sessions VALUES (?,?,?,?,?)",
            (
                feishu_auth._hash(raw),
                open_id,
                "桌面界面测试",
                secrets.token_urlsafe(32),
                int(time.time()) + 3600,
            ),
        )
    response = RedirectResponse("/")
    response.set_cookie(feishu_auth.COOKIE, raw, httponly=True, samesite="lax")
    return response
