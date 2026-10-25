"""Authenticated management API for live MCP hosts, tools, tasks and evidence."""

import json
import sqlite3
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from .platform_db import row_dict, archived_asset
from .integrations import zabbix
from .main import connection, read_setting, SettingsUpdate, draft_reader
from .security.rbac import require, enforce, ROLES, audit
from .orchestrator import tasks
from .integrations.ssh_mcp import SERVICE
from .diagnostics.playbooks import PLAYBOOKS, classify

router = APIRouter(prefix="/api/v1/platform")


def write(call):
    try:
        return call()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except sqlite3.IntegrityError:
        raise HTTPException(409, "名称、Host ID 重复，或关联对象不存在") from None


@router.get("/overview")
def overview(who=Depends(require("overview.read"))):
    with connection() as db:
        active = db.execute(
            "SELECT COUNT(*) FROM alert_events a WHERE a.event_value='1' AND NOT EXISTS(SELECT 1 FROM alert_events r WHERE r.event_id=a.event_id AND r.event_value='0')"
        ).fetchone()[0]
        counts = dict(
            db.execute(
                "SELECT status,COUNT(*) FROM diagnostic_tasks WHERE created_at>=datetime('now','-1 day') GROUP BY status"
            )
        )
        tokens = db.execute(
            "SELECT SUM(token_total),COUNT(token_total),AVG(duration_ms) FROM diagnostic_tasks WHERE completed_at>=datetime('now','-1 day')"
        ).fetchone()
        health = [
            dict(zip(("provider", "status", "checked_at", "detail"), r))
            for r in db.execute(
                "SELECT provider,status,checked_at,detail FROM integration_health"
            )
        ]
    with connection() as db:
        ai_counts = dict(
            db.execute(
                "SELECT status,COUNT(*) FROM diagnostic_tasks WHERE kind='analysis' AND created_at>=datetime('now','-1 day') GROUP BY status"
            )
        )
    ai_finished = sum(ai_counts.get(k, 0) for k in ("success", "partial", "failed"))
    finished = sum(counts.get(k, 0) for k in ("success", "partial", "failed"))
    from .main import settings_snapshot

    configured = settings_snapshot()
    return {
        "scope": "平台已接收的告警；任务与用量为最近 24 小时",
        "unrecovered_received_events": active,
        "tasks_24h": sum(counts.values()),
        "ai_runs_24h": sum(ai_counts.values()),
        "ai_success_rate_24h": round(100 * ai_counts.get("success", 0) / ai_finished, 1)
        if ai_finished
        else None,
        "completed_24h": counts.get("success", 0),
        "partial_24h": counts.get("partial", 0),
        "failed_24h": counts.get("failed", 0),
        "completion_rate_24h": round(
            100 * (counts.get("success", 0) + counts.get("partial", 0)) / finished, 1
        )
        if finished
        else None,
        "token_total_24h": tokens[0],
        "usage_available_runs_24h": tokens[1],
        "average_duration_ms_24h": tokens[2],
        "mcp_configured": bool(configured.get("mcp_url")),
        "ssh_mcp_configured": bool(
            configured.get("ssh_mcp_url")
            and configured.get("ssh_mcp_token")
            and configured.get("ssh_mcp_enabled") == "true"
        ),
        "health": health,
        "running": counts.get("running", 0),
        "queued": counts.get("queued", 0),
        "readiness": {
            "model": all(
                configured.get(k)
                for k in ("openai_base_url", "openai_model", "openai_api_key")
            ),
            "zabbix_mcp": bool(configured.get("mcp_url")),
            "ssh_mcp": configured.get("ssh_mcp_enabled") == "true"
            and all(configured.get(k) for k in ("ssh_mcp_url", "ssh_mcp_token")),
            "feishu": all(
                configured.get(k) for k in ("lark_app_id", "lark_app_secret")
            ),
            "webhook": bool(configured.get("zabbix_webhook_secret")),
        },
    }


@router.get("/alerts")
def alerts_page(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Literal["all", "active", "recovered"] = "all",
    severity: int | None = Query(None, ge=0, le=5),
    q: str = Query("", max_length=160),
    who=Depends(require("reports.read")),
):
    from .operations import alert_page

    return alert_page(page, page_size, status, severity, q)


@router.get("/diagnostic-options")
def diagnostic_options(who=Depends(require("diagnostics.run"))):
    return {"default_profile": read_setting("ai_analysis_profile") or "standard"}


class TaskInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    zabbix_hostid: str | None = Field(default=None, pattern=r"^[0-9]{1,32}$")
    event_id: str | None = Field(default=None, pattern=r"^[0-9]{1,32}$")
    diagnostic_type: str = "auto"
    profile: str | None = None
    question: str = Field(default="请根据实际证据诊断故障并给出建议", max_length=3000)
    service: str | None = Field(default=None, max_length=64)
    time_window: int = Field(default=30, ge=1, le=120)


async def live_hosts(query="", host_id=None):
    try:
        return await zabbix.monitoring_hosts(read_setting, query, host_id)
    except Exception as exc:
        raise HTTPException(
            502,
            str(exc)
            if isinstance(exc, ValueError)
            else "Zabbix MCP 主机查询失败：" + type(exc).__name__,
        ) from None


@router.get("/hosts")
async def hosts(
    q: str = Query("", max_length=160), who=Depends(require("diagnostics.run"))
):
    rows = await live_hosts(q)
    return {
        "items": rows,
        "at_limit": len(rows) == 100,
        "note": "来自 Zabbix MCP，未在平台保存资产；单次最多100台，可按名称或Host ID搜索。",
    }


async def validate_task(body):
    body.profile = body.profile or read_setting("ai_analysis_profile") or "standard"
    if body.diagnostic_type not in set(PLAYBOOKS) | {"auto"} or body.profile not in {
        "quick",
        "standard",
        "deep",
    }:
        raise HTTPException(422, "诊断类型或模式无效")
    if body.service and not SERVICE.fullmatch(body.service):
        raise HTTPException(422, "服务名称无效")
    if not body.question.strip():
        raise HTTPException(422, "请输入诊断问题")
    event = {}
    if body.event_id:
        with connection() as db:
            row = db.execute(
                "SELECT event_json FROM alert_events WHERE event_id=? AND event_value='1'",
                (body.event_id,),
            ).fetchone()
        if not row or not row[0]:
            raise HTTPException(404, "未找到已接收的告警")
        event = json.loads(row[0])
        if body.zabbix_hostid and body.zabbix_hostid != str(event.get("host_id", "")):
            raise HTTPException(422, "所选主机与告警 Host ID 不匹配")
    host_id = str(event.get("host_id") or body.zabbix_hostid or "")
    host = None
    if host_id:
        host = (await live_hosts(host_id=host_id))[0]
        if not event:
            event = {
                "host_id": host["zabbix_hostid"],
                "host_name": host["name"],
                "event_name": body.question,
            }
    if body.diagnostic_type == "auto":
        body.diagnostic_type = classify(event.get("event_name") or body.question)
    return host, event


@router.post("/tasks/validate")
async def validate_diagnostic(body: TaskInput, who=Depends(require("diagnostics.run"))):
    import asyncio
    from .integrations import ssh_mcp

    host, event = await validate_task(body)
    if (
        host
        and host["device_type"] == "linux"
        and body.profile != "quick"
        and read_setting("ssh_mcp_enabled") == "true"
    ):
        try:
            async with asyncio.timeout(20):
                async with ssh_mcp.configured(read_setting, timeout=15) as adapter:
                    binding = await adapter.resolve(host["zabbix_hostid"])
            audit(who["open_id"], "ssh_mcp_binding_verified", host["zabbix_hostid"])
            return {
                "ok": True,
                "message": "监控主机与 SSH MCP Host ID 映射验证通过；未执行 SSH 或 AI 分析。",
                "ssh_host_id": binding.host_id,
                "host_revision": binding.revision,
            }
        except Exception as exc:
            raise HTTPException(
                502,
                str(exc)
                if isinstance(exc, ssh_mcp.IntegrationError)
                else "SSH MCP 关联验证失败：" + type(exc).__name__,
            ) from None
    return {
        "ok": True,
        "message": "诊断参数验证通过；本次未执行 SSH 或 AI 分析。实际任务按监控设备类型和 SSH MCP 配置决定是否补查。",
    }


@router.post("/tasks", status_code=202)
async def submit(body: TaskInput, who=Depends(require("diagnostics.run"))):
    host, event = await validate_task(body)
    request = {**body.model_dump(), "event": event}
    task, created = tasks.create(
        request,
        source="web",
        actor=who["open_id"],
        event_id=body.event_id,
        diagnostic_type=body.diagnostic_type,
        profile=body.profile,
    )
    if created:
        enqueue_task(task["task_id"])
    audit(who["open_id"], "analysis_submitted", task["task_id"], task["trace_id"])
    return {
        "task_id": task["task_id"],
        "trace_id": task["trace_id"],
        "duplicate": not created,
    }


@router.get("/tasks")
def task_page(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Literal[
        "all", "queued", "running", "success", "partial", "failed", "cancelled"
    ] = "all",
    q: str = Query("", max_length=160),
    who=Depends(require("reports.read")),
):
    return tasks.page(page, page_size, status, q)


@router.get("/tasks/{task_id}/status")
def task_status(task_id: str, who=Depends(require("reports.read"))):
    result = tasks.progress(task_id)
    if not result:
        raise HTTPException(404, "任务不存在")
    return result


def enqueue_task(task_id):
    try:
        tasks.enqueue(task_id)
    except tasks.QueueUnavailable:
        raise HTTPException(
            503,
            {
                "message": "诊断队列不可用，任务已记录为失败。请在系统配置检查服务状态后重试。",
                "task_id": task_id,
            },
        ) from None


@router.get("/tasks/{task_id}")
def task_detail(
    task_id: str, include_logs: bool = False, who=Depends(require("reports.read"))
):
    task = tasks.get(task_id, private=True)
    if not task:
        raise HTTPException(404, "任务不存在")
    request = task.pop("request")
    event = request.get("event") or {}
    task["alert"] = {
        k: event.get(k)
        for k in (
            "event_id",
            "event_name",
            "host_id",
            "host_name",
            "severity",
            "event_date",
            "event_time",
        )
    }
    asset = archived_asset(task["asset_id"]) if task["asset_id"] else None
    task["asset"] = (
        {k: asset.get(k) for k in ("id", "name", "device_type", "zabbix_hostid")}
        if asset
        else None
    )
    if include_logs:
        enforce(who["open_id"], "logs.read")
    task["evidence"] = tasks.evidence_page(task_id, include_logs)
    audit(who["open_id"], "report_read", task_id, task["trace_id"])
    return task


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str, who=Depends(require("diagnostics.run"))):
    with connection() as db:
        if not db.execute(
            "UPDATE diagnostic_tasks SET cancel_requested=1,stage=CASE WHEN status='queued' THEN 'cancelled' ELSE stage END,completed_at=CASE WHEN status='queued' THEN CURRENT_TIMESTAMP ELSE completed_at END,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END WHERE task_id=? AND status IN ('queued','running')",
            (task_id,),
        ).rowcount:
            raise HTTPException(409, "任务不存在或已结束")
    audit(who["open_id"], "task_cancelled", task_id)
    return {"ok": True}


@router.post("/tasks/{task_id}/retry", status_code=202)
def retry_task(task_id: str, who=Depends(require("diagnostics.run"))):
    old = tasks.get(task_id, private=True)
    if not old or old["status"] not in ("failed", "partial", "cancelled"):
        raise HTTPException(409, "仅失败、部分完成或取消的任务可重试")
    if old["kind"] != "analysis":
        raise HTTPException(409, "旧版 SSH 或导入任务不能重试，请发起新的 AI 诊断")
    request = {k: v for k, v in old["request"].items() if k != "limits"}
    task, created = tasks.create(
        request,
        source=old["source"],
        actor=who["open_id"],
        kind=old["kind"],
        event_id=old["event_id"],
        diagnostic_type=old["diagnostic_type"],
        profile=old["profile"],
    )
    if created:
        enqueue_task(task["task_id"])
    audit(who["open_id"], "task_retried", task_id)
    return {"task_id": task["task_id"], "duplicate": not created}


@router.get("/tools")
def tool_registry(who=Depends(require("tools.read"))):
    from .integrations.zabbix import READ_TOOLS, enabled_names, input_schema

    enabled = enabled_names(read_setting)
    rows = [
        {
            "name": n,
            "provider": "zabbix_mcp",
            "device_types": [
                "linux",
                "windows",
                "vmware",
                "network",
                "other",
                "unknown",
            ],
            "description": "受限 Zabbix 只读查询",
            "read_only": True,
            "risk": "read",
            "timeout": 18,
            "max_output_chars": 10000,
            "required_scope": "diagnostics.run",
            "enabled": n in enabled,
            "input_schema": input_schema(n),
            "output_schema": {
                "type": "object",
                "properties": {
                    "data": {"type": "string"},
                    "is_error": {"type": "boolean"},
                    "error": {"type": "string"},
                },
            },
        }
        for n in sorted(READ_TOOLS)
    ]
    rows.append(
        {
            "name": "diagnose_linux_host",
            "provider": "ssh_mcp",
            "device_types": ["linux"],
            "description": "通过独立 SSH MCP 按 Zabbix Host ID 执行受限诊断",
            "read_only": True,
            "risk": "bounded_read",
            "timeout": int(read_setting("ssh_mcp_timeout_seconds") or 90),
            "max_output_chars": 32768,
            "required_scope": "diagnostics.run",
            "enabled": read_setting("ssh_mcp_enabled") == "true"
            and bool(read_setting("ssh_mcp_url") and read_setting("ssh_mcp_token")),
            "input_schema": {
                "diagnostic_type": list(PLAYBOOKS),
                "service": "validated unit",
                "time_window": "1–120 minutes",
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "output": {"type": "string"},
                },
            },
        }
    )
    return {
        "tools": rows,
        "playbooks": PLAYBOOKS,
    }


@router.post("/tools/discover")
async def discover(
    provider: str = "zabbix_mcp",
    body: SettingsUpdate | None = None,
    who=Depends(require("settings.manage")),
):
    import asyncio
    from .integrations import zabbix, ssh_mcp

    reader = draft_reader(body, who)
    if provider not in {"zabbix_mcp", "ssh_mcp"}:
        raise HTTPException(422, "MCP 提供方无效")
    try:
        async with asyncio.timeout(20):
            if provider == "zabbix_mcp":
                async with zabbix.connect(reader) as session:
                    listed = await zabbix.discover(session)
                    names = sorted(
                        t.name for t in listed if t.name in zabbix.enabled_names(reader)
                    )
                if not names:
                    raise ValueError("未发现授权的 Zabbix 只读工具")
            else:
                async with ssh_mcp.configured(reader, timeout=15) as adapter:
                    listed = await adapter.session.list_tools()
                    available = {t.name for t in listed.tools}
                    if "ssh_resolve_host" not in available:
                        raise ValueError(
                            "SSH MCP 需升级至支持 Host ID 解析的 v0.2.0 或更新版"
                        )
                    names = sorted(
                        available & ({"ssh_resolve_host"} | set(ssh_mcp.TOOLS.values()))
                    )
        status = "success"
        detail = json.dumps({"authorized_tools": names}, ensure_ascii=False)
    except Exception as exc:
        status, names = "failed", []
        detail = (
            str(exc)
            if isinstance(exc, (ValueError, ssh_mcp.IntegrationError))
            else type(exc).__name__
        )
        detail = detail[:250]
    keys = (
        ("mcp_url", "mcp_token", "disabled_tools")
        if provider == "zabbix_mcp"
        else (
            "ssh_mcp_url",
            "ssh_mcp_token",
            "ssh_mcp_enabled",
            "ssh_mcp_timeout_seconds",
        )
    )
    # A successful unsaved draft must not claim the active configuration is healthy.
    if all(reader(key) == read_setting(key) for key in keys):
        with connection() as db:
            db.execute(
                "INSERT INTO integration_health(provider,status,detail) VALUES (?,?,?) ON CONFLICT(provider) DO UPDATE SET status=excluded.status,checked_at=CURRENT_TIMESTAMP,detail=excluded.detail",
                (provider, status, detail),
            )
    audit(who["open_id"], "mcp_connection_test", provider)
    return {
        "ok": status == "success",
        "provider": provider,
        "authorized_tools": names,
        "detail": detail,
        "note": "发现工具仅验证连接和协议；主机映射、远端动作授权及 SSH 连通性在实际诊断时核验",
    }


class MemberInput(BaseModel):
    open_id: str = Field(pattern=r"^ou_[A-Za-z0-9_-]{2,128}$")
    role: str
    enabled: bool = True


@router.get("/members")
def members(who=Depends(require("*"))):
    with connection() as db:
        return [
            dict(zip(("open_id", "role", "enabled"), r))
            for r in db.execute("SELECT * FROM members")
        ]


@router.put("/members")
def save_member(body: MemberInput, who=Depends(require("*"))):
    if body.role not in ROLES or body.role == "super_admin":
        raise HTTPException(422, "超级管理员仅通过初始化管理员名单管理")
    with connection() as db:
        db.execute(
            "INSERT INTO members VALUES (?,?,?) ON CONFLICT(open_id) DO UPDATE SET role=excluded.role,enabled=excluded.enabled",
            (body.open_id, body.role, int(body.enabled)),
        )
    audit(who["open_id"], "member_updated", body.open_id)
    return {"ok": True}


@router.get("/audit")
def audit_page(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    who=Depends(require("audit.read")),
):
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        cur = db.execute(
            "SELECT id,action,key,actor,trace_id,created_at FROM audit ORDER BY id DESC LIMIT ? OFFSET ?",
            (page_size, (page - 1) * page_size),
        )
        return {
            "items": [row_dict(r, cur) for r in cur.fetchall()],
            "total": total,
            "page": page,
            "page_size": page_size,
        }


@router.post("/members/validate")
def validate_member(body: MemberInput, who=Depends(require("*"))):
    if body.role not in ROLES or body.role == "super_admin":
        raise HTTPException(422, "角色无效；超级管理员请在名单管理")
    return {"ok": True, "message": "成员信息验证通过；未保存。"}
