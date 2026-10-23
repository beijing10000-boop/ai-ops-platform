"""Isolated desktop QA server. Never included in the application Docker image."""

import os
import secrets
import tempfile
import time
from pathlib import Path
from cryptography.fernet import Fernet

if os.getenv("AIOPS_UI_TEST") != "1":
    raise RuntimeError("Explicit AIOPS_UI_TEST=1 required")
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="aiops-desktop-qa-")
os.environ["APP_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["ALLOW_LEGACY_ADMIN_TOKEN"] = "false"
from app.main import app, connection
from app import feishu_auth, inventory
from app.orchestrator import tasks
from fastapi.responses import RedirectResponse

with connection() as db:
    db.execute("INSERT INTO settings VALUES ('feishu_admin_open_ids','ou_ui_test',0)")
    db.execute("INSERT INTO settings VALUES ('web_public_host','127.0.0.1:8765',0)")
asset = inventory.save_asset(
    inventory.AssetInput(
        name="UI 测试 · Linux 资产", device_type="linux", zabbix_hostid="10001"
    ),
    "ui-test",
)
inventory.save_asset(
    inventory.AssetInput(
        name="UI 测试 · 网络设备", device_type="network", zabbix_hostid="10002"
    ),
    "ui-test",
)
task, _ = tasks.create(
    {
        "event": {
            "event_name": "UI 测试记录 · CPU 诊断",
            "host_name": asset["name"],
            "host_id": "10001",
        }
    },
    source="ui_test",
    asset_id=asset["id"],
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
