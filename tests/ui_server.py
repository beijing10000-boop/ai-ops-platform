"""Isolated desktop QA server. Never included in the application Docker image."""

import os
import secrets
import tempfile
import time
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
        "answer": "隔离界面测试记录。\n\n此处展示报告结构、任务追踪和证据分区，不代表真实环境诊断。",
        "device_type": "linux",
        "limitations": ["尚未连接生产 Zabbix、飞书或 SSH 主机"],
    },
    status="partial",
    duration_ms=1500,
)


@app.get("/__ui_login")
def test_login():
    raw = secrets.token_urlsafe(32)
    with connection() as db:
        feishu_auth._tables(db)
        db.execute(
            "INSERT INTO admin_sessions VALUES (?,?,?,?,?)",
            (
                feishu_auth._hash(raw),
                "ou_ui_test",
                "桌面界面测试",
                secrets.token_urlsafe(32),
                int(time.time()) + 3600,
            ),
        )
    response = RedirectResponse("/")
    response.set_cookie(feishu_auth.COOKIE, raw, httponly=True, samesite="lax")
    return response
