"""Authenticated management API for live MCP hosts, tools, tasks and evidence."""

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from . import skill_mcp
from .platform_db import row_dict, archived_asset
from .integrations import log_mcp, ssh_mcp, zabbix
from .main import (
    connection,
    draft_reader,
    read_setting,
    settings_snapshot,
    SettingsUpdate,
)
from .security.rbac import require, enforce, ROLES, audit
from .security.redact import redact, redact_data
from .orchestrator import tasks
from .orchestrator.tasks import SENSITIVE_TOOL
from .diagnostics.playbooks import PLAYBOOKS, classify
from .skill_mcp import (
    ACTION_TOOLS,
    SSH_META,
    SkillMCP,
    authorized_ssh_tools,
    payload,
    ssh_allowed,
)

router = APIRouter(prefix="/api/v1/platform")

SSH_CACHE_SECONDS = 60
PROBE_SECONDS = 60
ASSET_CATEGORY = "资产解析"
RISKS = {"low", "medium", "high"}
# A diagnostic test sends only the resolved SSH asset and its revision.
PROBE_ARGUMENTS = frozenset({"host_id", "expected_revision"})
# Last live SSH MCP tool list: {settings digest: (monotonic time, registry)}.
SSH_REGISTRY_CACHE = {}


def _root(exc):
    """The one exception anyio wrapped (possibly nested) while an MCP session closed."""
    while isinstance(exc, BaseExceptionGroup):
        inner = [e for e in exc.exceptions if not isinstance(e, asyncio.CancelledError)]
        if len(inner) != 1:
            break
        exc = inner[0]
    return exc


def _reason(exc):
    """A safe, bounded failure text; never a token or remote traceback."""
    exc = _root(exc)
    if isinstance(exc, (ValueError, ssh_mcp.IntegrationError)):
        return str(exc)[:250]
    if isinstance(exc, TimeoutError):
        return "SSH MCP 响应超时"
    return "SSH MCP 连接失败：" + type(exc).__name__


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
        ai_counts = dict(
            db.execute(
                "SELECT status,COUNT(*) FROM diagnostic_tasks WHERE kind='analysis' AND created_at>=datetime('now','-1 day') GROUP BY status"
            )
        )
    ai_finished = sum(ai_counts.get(k, 0) for k in ("success", "partial", "failed"))
    finished = sum(counts.get(k, 0) for k in ("success", "partial", "failed"))
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
        "log_mcp_configured": log_mcp.configured(configured.get),
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
            "logs": log_mcp.configured(configured.get),
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
    if body.service and not ssh_mcp.SERVICE.fullmatch(body.service):
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
    # Skills decide which sources to query; the selected Host ID is the target.
    if host_id and not event:
        event = {"host_id": host_id, "event_name": body.question}
    if body.diagnostic_type == "auto":
        body.diagnostic_type = classify(event.get("event_name") or body.question)
    return host_id, event


@router.post("/tasks/validate")
async def validate_diagnostic(body: TaskInput, who=Depends(require("diagnostics.run"))):
    host_id, event = await validate_task(body)
    if (
        host_id
        and body.profile != "quick"
        and read_setting("ssh_mcp_enabled") == "true"
    ):
        try:
            async with asyncio.timeout(20):
                async with ssh_mcp.configured(read_setting, timeout=15) as adapter:
                    binding = await adapter.resolve(host_id)
            audit(who["open_id"], "ssh_mcp_binding_verified", host_id)
            return {
                "ok": True,
                "message": "监控主机与 SSH MCP Host ID 映射验证通过；未执行 SSH 或 AI 分析。",
                "ssh_host_id": binding.host_id,
                "host_revision": binding.revision,
            }
        except Exception as exc:
            # Errors raised inside the MCP session arrive wrapped by anyio.
            exc = _root(exc)
            raise HTTPException(
                502,
                str(exc)
                if isinstance(exc, ssh_mcp.IntegrationError)
                else "SSH MCP 关联验证失败：" + type(exc).__name__,
            ) from None
    return {
        "ok": True,
        "message": "诊断参数验证通过；本次未执行 SSH 或 AI 分析。实际查询按已启用的 Skill 决定（默认为平台基础 Skill）。",
    }


@router.post("/tasks", status_code=202)
async def submit(body: TaskInput, who=Depends(require("diagnostics.run"))):
    _, event = await validate_task(body)
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
    from .skill_store import applied_names, summary

    # The snapshot holds every enabled Skill; `applied` marks the ones the
    # model received (device and alert-type Skills may not apply).
    task["skills"] = summary(
        request.get("skills", []), applied_names(task.get("report"))
    )
    # capabilities / coverage / facts stay inside task["report"] as recorded.
    budget = (task.get("report") or {}).get("budget") or {
        "limits": request.get("limits", {}),
        "used": {"calls": task["tools"]},
        "reasons": [],
    }
    # Budget limits that shaped the run; reports before v1.2 have none.
    task["budget"] = {**budget, "limits_hit": budget.get("limits_hit") or []}
    event = request.get("event") or {}
    target = (task.get("report") or {}).get("target") or {}
    task["alert"] = {
        k: event.get(k) or target.get(k)
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
    task["evidence"] = tasks.evidence_page(task_id, include_logs=include_logs)
    audit(who["open_id"], "report_read", task_id, task["trace_id"])
    return task


@router.get("/tasks/{task_id}/model-interactions")
def model_interactions(
    task_id: str,
    include_content: bool = False,
    who=Depends(require("reports.read")),
):
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    if include_content:
        enforce(who["open_id"], "logs.read")
        audit(who["open_id"], "model_interactions_content_read", task_id)
    return {
        "task_id": task_id,
        "items": tasks.model_interaction_page(task_id, include_content=include_content),
        "content_visible": include_content,
        "note": "按模型请求记录；内容为脱敏、限长预览，不包含模型内部推理。仅升级后的新任务留存。",
    }


@router.get("/tasks/{task_id}/detailed-report")
def download_detailed_report(
    task_id: str,
    who=Depends(require("reports.read")),
):
    """Download all stored evidence and model previews, only for logs.read users."""
    enforce(who["open_id"], "logs.read")
    task = tasks.get(task_id, private=True)
    if task is None:
        raise HTTPException(404, "任务不存在")
    from .detailed_report import build_detailed_report

    document = build_detailed_report(task_id, task=task)
    audit(who["open_id"], "detailed_report_export", task_id, task["trace_id"])
    filename = "diagnostic-detailed-" + task_id[:12] + ".md"
    return Response(
        content=document,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


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


def _ssh_unavailable(read):
    if read("ssh_mcp_enabled") != "true":
        return "SSH MCP 未启用；在连接管理开启并保存后可读取实时工具目录"
    if not (read("ssh_mcp_url") and read("ssh_mcp_token")):
        return "SSH MCP 地址或专用令牌未配置"
    return None


async def _list_tools(session):
    """Every tool the server lists, across pages."""
    tools, cursor, seen = [], None, set()
    for _ in range(20):
        result = (
            await session.list_tools(cursor=cursor)
            if cursor
            else await session.list_tools()
        )
        tools.extend(result.tools)
        cursor = getattr(result, "nextCursor", None)
        if not cursor:
            return tools
        if cursor in seen:
            raise ValueError("MCP 工具分页重复")
        seen.add(cursor)
    raise ValueError("MCP 工具分页超过限制")


async def _read_catalog(session):
    """ssh_list_tool_catalog entries: the actions this client token may run."""
    response = await session.call_tool("ssh_list_tool_catalog", {})
    if response.isError:
        raise ValueError("SSH MCP 拒绝读取工具目录；请检查专用客户端令牌")
    entries = payload(response)
    if not isinstance(entries, list):
        raise ValueError("SSH MCP 工具目录格式无效")
    return [e for e in entries if isinstance(e, dict) and isinstance(e.get("id"), str)]


def _catalog_index(entries):
    """Catalog entries by MCP tool name, the same rule as authorized_ssh_tools."""
    index = {}
    for entry in entries:
        tool = entry.get("tool")
        name = (
            tool
            if isinstance(tool, str)
            else ACTION_TOOLS.get(entry["id"], "ssh_diagnose_" + entry["id"])
        )
        index[name] = entry
    return index


def _schema_params(schema):
    """Parameter rows from an MCP input schema, for tools the catalog omits."""
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return []
    required = set(schema.get("required") or [])
    rows = []
    for name, spec in properties.items():
        # host_id/expected_revision come from the resolved asset; detail is format.
        if name in PROBE_ARGUMENTS | {"detail"} or not isinstance(spec, dict):
            continue
        option = next(
            (
                o
                for o in spec.get("anyOf") or []
                if isinstance(o, dict) and o.get("type") != "null"
            ),
            {},
        )
        merged = {**option, **{k: v for k, v in spec.items() if k != "anyOf"}}
        kind = merged.get("type")
        row = {
            "name": name,
            "type": kind if isinstance(kind, str) else "string",
            "required": name in required,
        }
        for key in ("default", "minimum", "maximum", "pattern", "description"):
            if merged.get(key) is not None:
                row[key] = merged[key]
        choices = merged.get("enum") or (merged.get("items") or {}).get("enum")
        if isinstance(choices, list):
            row["choices"] = choices
        rows.append(row)
    return rows


def _ssh_entry(tool, entry, authorized, timeout):
    """One registry row: MCP description/schema plus this token's catalog entry."""
    meta = tool.name in SSH_META
    entry = entry or {}
    params = entry.get("params")
    notes = entry.get("notes")
    estimated = entry.get("estimated_seconds")
    return {
        "name": tool.name,
        "provider": "ssh_mcp",
        "title": str(entry["name"])[:80]
        if isinstance(entry.get("name"), str)
        else None,
        "description": (tool.description or "")[:1000],
        "question": str(entry["question"])[:300]
        if isinstance(entry.get("question"), str)
        else None,
        "category": str(entry["category"])[:40]
        if isinstance(entry.get("category"), str)
        else ASSET_CATEGORY
        if meta
        else None,
        "params": [
            p for p in params if isinstance(p, dict) and isinstance(p.get("name"), str)
        ]
        if isinstance(params, list)
        else _schema_params(tool.inputSchema),
        "risk": entry.get("risk")
        if entry.get("risk") in RISKS
        else "low"
        if meta
        else None,
        "sensitive": bool(entry["sensitive"])
        if "sensitive" in entry
        else not meta and bool(SENSITIVE_TOOL.search(tool.name)),
        "extension": bool(entry.get("extension")),
        "standard_only": bool(entry.get("standard_only")),
        "notes": [str(n)[:200] for n in notes[:6]] if isinstance(notes, list) else [],
        "estimated_seconds": estimated if type(estimated) is int else None,
        # In the token's catalog (or a resolve/list tool) = authorized for this
        # client; None when the server cannot say (no or unreadable catalog).
        "authorized": authorized,
        "enabled": authorized is not False,
        "device_types": ["linux"],
        "read_only": True,
        "timeout": timeout,
        "required_scope": "diagnostics.run",
        "input_schema": tool.inputSchema,
    }


async def _read_ssh_registry(read):
    """Live SSH MCP tools through the Skill bridge, with the token's catalog."""
    timeout = min(120, int(read("ssh_mcp_timeout_seconds") or 90))
    async with SkillMCP(read, ["ssh_mcp"], deadline=time.monotonic() + 20) as bridge:
        await bridge.catalog("ssh_mcp")
        session = bridge.sessions["ssh_mcp"]
        # Read fresh (the bridge may reuse a cached view) and keep the tools the
        # bridge hides from the model as unauthorized, so the registry shows them.
        listed = [tool for tool in await _list_tools(session) if ssh_allowed(tool)]
        entries, catalog_error = None, None
        if "ssh_list_tool_catalog" in {tool.name for tool in listed}:
            try:
                entries = await _read_catalog(session)
            except Exception as exc:
                catalog_error = "读取工具目录失败：" + _reason(exc)
        else:
            catalog_error = "SSH MCP 未提供 ssh_list_tool_catalog（旧版本），无法确认本令牌的动作授权"
    index = _catalog_index(entries) if entries is not None else None
    order = {name: i for i, name in enumerate(index or {})}

    def rank(tool):
        if tool.name in SSH_META:
            return 0, 0, tool.name
        return (1, order[tool.name], "") if tool.name in order else (2, 0, tool.name)

    rows = [
        _ssh_entry(
            tool,
            (index or {}).get(tool.name),
            True
            if tool.name in SSH_META
            else None
            if index is None
            else tool.name in index,
            timeout,
        )
        for tool in sorted({t.name: t for t in listed}.values(), key=rank)
    ]
    return {
        "tools": rows,
        "error": None if rows else "SSH MCP 未返回平台允许的只读工具",
        "catalog": index is not None,
        "catalog_error": catalog_error,
    }


def _ssh_key(read):
    keys = (
        "ssh_mcp_enabled",
        "ssh_mcp_url",
        "ssh_mcp_token",
        "ssh_mcp_timeout_seconds",
    )
    return hashlib.sha256(json.dumps([read(k) for k in keys]).encode()).hexdigest()


def _forget_ssh_catalogs():
    """After an explicit refresh or check, the next read, test or task sees new grants."""
    SSH_REGISTRY_CACHE.clear()
    skill_mcp.clear_catalog_cache()
    # Worker processes keep their own catalog cache keyed by this epoch.
    with connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES (?,?,0)",
            (skill_mcp.EPOCH_SETTING, str(time.time_ns())),
        )


async def ssh_registry(refresh=False):
    """SSH rows for the tool registry; cached per configuration, never raises."""
    unavailable = _ssh_unavailable(read_setting)
    if unavailable:
        return {
            "tools": [],
            "error": unavailable,
            "catalog": False,
            "catalog_error": None,
            "checked_at": None,
            "cached": False,
        }
    if refresh:
        _forget_ssh_catalogs()
    key = _ssh_key(read_setting)
    cached = SSH_REGISTRY_CACHE.get(key)
    if cached and time.monotonic() - cached[0] < SSH_CACHE_SECONDS:
        return {**cached[1], "cached": True}
    limit = asyncio.timeout(25)
    try:
        async with limit:
            value = await _read_ssh_registry(read_setting)
    except BaseException as exc:
        root = _root(exc)
        if limit.expired():
            reason = "读取 SSH MCP 工具目录超时；请检查服务后点击“刷新目录”"
        elif isinstance(root, Exception):
            reason = _reason(root)
        else:
            raise
        value = {"tools": [], "error": reason, "catalog": False, "catalog_error": None}
    value["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Failures are cached too: an unreachable service must not slow every page.
    SSH_REGISTRY_CACHE.clear()
    SSH_REGISTRY_CACHE[key] = (time.monotonic(), value)
    return {**value, "cached": False}


@router.get("/tools")
async def tool_registry(refresh: bool = False, who=Depends(require("tools.read"))):
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
    ssh = await ssh_registry(refresh)
    return {
        "tools": rows + ssh["tools"],
        # Diagnostic types classify tasks; Skills decide which tools run.
        "playbooks": PLAYBOOKS,
        "ssh_mcp_error": ssh["error"],
        "ssh_catalog": ssh["catalog"],
        "ssh_catalog_error": ssh["catalog_error"],
        "ssh_checked_at": ssh["checked_at"],
        "ssh_cached": ssh["cached"],
    }


@router.post("/tools/discover")
async def discover(
    provider: str = "zabbix_mcp",
    body: SettingsUpdate | None = None,
    who=Depends(require("settings.manage")),
):
    reader = draft_reader(body, who)
    if provider not in {"zabbix_mcp", "ssh_mcp", "logs"}:
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
            elif provider == "logs":
                names = await _log_tools(reader)
            else:
                async with ssh_mcp.configured(reader, timeout=15) as adapter:
                    listed = await _list_tools(adapter.session)
                    available = {t.name for t in listed}
                    if "ssh_resolve_host" not in available:
                        raise ValueError(
                            "SSH MCP 需升级至支持 Host ID 解析的 v0.2.0 或更新版"
                        )
                    if "ssh_list_tool_catalog" in available:
                        # What this client token may run, by MCP tool name.
                        names = sorted(
                            authorized_ssh_tools(await _read_catalog(adapter.session))
                        )
                    else:
                        # Servers before the catalog: their read-only SSH tools.
                        names = sorted(
                            t.name
                            for t in listed
                            if t.name.startswith("ssh_")
                            and getattr(t, "annotations", None)
                            and t.annotations.readOnlyHint is True
                            and t.annotations.destructiveHint is not True
                        )
        status = "success"
        detail = json.dumps({"authorized_tools": names}, ensure_ascii=False)
    except Exception as exc:
        status, names = "failed", []
        # Errors raised inside the MCP session arrive wrapped by anyio.
        exc = _root(exc)
        detail = (
            log_mcp.reason(exc)
            if provider == "logs"
            else str(exc)
            if isinstance(exc, (ValueError, ssh_mcp.IntegrationError))
            else type(exc).__name__
        )[:250]
    keys = {
        "zabbix_mcp": ("mcp_url", "mcp_token", "disabled_tools"),
        "ssh_mcp": (
            "ssh_mcp_url",
            "ssh_mcp_token",
            "ssh_mcp_enabled",
            "ssh_mcp_timeout_seconds",
        ),
        "logs": ("log_mcp_url", "log_mcp_token"),
    }[provider]
    # A successful unsaved draft must not claim the active configuration is healthy.
    if all(reader(key) == read_setting(key) for key in keys):
        with connection() as db:
            db.execute(
                "INSERT INTO integration_health(provider,status,detail) VALUES (?,?,?) ON CONFLICT(provider) DO UPDATE SET status=excluded.status,checked_at=CURRENT_TIMESTAMP,detail=excluded.detail",
                (provider, status, detail),
            )
        if provider != "zabbix_mcp":
            # The registry and later diagnostics re-read the token's catalog.
            _forget_ssh_catalogs()
    audit(who["open_id"], "mcp_connection_test", provider)
    return {
        "ok": status == "success",
        "provider": provider,
        "authorized_tools": names,
        "detail": detail,
        "note": "发现工具仅验证连接和协议；主机映射、远端动作授权及 SSH 连通性在实际诊断时核验",
    }


async def _log_tools(read):
    """Log tools the platform keeps and this log MCP token may run."""
    async with log_mcp.connect(read, timeout=15) as session:
        listed = [tool for tool in await _list_tools(session) if log_mcp.allowed(tool)]
        available = {tool.name for tool in listed}
        if "log_resolve_target" not in available:
            raise ValueError(
                "日志 MCP 未提供 log_resolve_target，请确认地址指向日志分析平台"
            )
        granted = None
        if "log_list_tool_catalog" in available:
            response = await session.call_tool("log_list_tool_catalog", {})
            if response.isError:
                raise ValueError("日志 MCP 拒绝读取工具目录；请检查令牌")
            granted = log_mcp.authorized_tools(payload(response, "日志 MCP"))
            if granted is None:
                raise ValueError("日志 MCP 工具目录格式无效")
    return sorted(
        name
        for name in available
        if granted is None or name in granted or name in log_mcp.META
    )


class ProbeRejected(ValueError):
    """The selected tool cannot run as a one-off, host-only diagnostic test."""


class ProbeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["ssh_mcp"] = "ssh_mcp"
    tool: str = Field(min_length=1, max_length=100)
    zabbix_hostid: str = Field(pattern=r"^[0-9]{1,32}$")


def _probe_text(value):
    return redact(value, 500) if value else None


async def _probe(body, who, deadline):
    """Resolve the monitored host, then run the tool once with host arguments only."""
    async with SkillMCP(
        read_setting,
        ["ssh_mcp"],
        deadline=deadline,
        target=("hostid", body.zabbix_hostid),
    ) as bridge:
        tools = await bridge.catalog("ssh_mcp")
        tool = tools.get(body.tool)
        if tool is None:
            raise ProbeRejected(
                "该工具不在本令牌授权的只读目录中；请在 SSH MCP 控制台为客户端开启对应动作"
            )
        entry = {}
        if "ssh_list_tool_catalog" in tools:
            try:
                entry = _catalog_index(
                    await _read_catalog(bridge.sessions["ssh_mcp"])
                ).get(body.tool, {})
            except Exception:
                entry = {}
        schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
        properties = schema.get("properties")
        params = entry.get("params") if isinstance(entry.get("params"), list) else []
        required = {str(name) for name in schema.get("required") or []} | {
            p["name"]
            for p in params
            if isinstance(p, dict)
            and p.get("required")
            and isinstance(p.get("name"), str)
        }
        if not isinstance(properties, dict) or "host_id" not in properties:
            raise ProbeRejected("该工具不按 SSH 资产 host_id 采集，不能用于诊断测试")
        if required - PROBE_ARGUMENTS:
            raise ProbeRejected(
                "该工具需要 "
                + "、".join(sorted(required - PROBE_ARGUMENTS))
                + " 等参数；诊断测试只调用仅需主机的只读工具，请在 AI 诊断中由 Skill 调用"
            )
        sensitive = (
            bool(entry["sensitive"])
            if "sensitive" in entry
            else bool(SENSITIVE_TOOL.search(body.tool))
        )
        if sensitive:
            # Log-type results are shown in full only to users who may read logs.
            enforce(who["open_id"], "logs.read")
        resolved = await bridge.call(
            "ssh_mcp", "ssh_resolve_host", {"zabbix_hostid": body.zabbix_hostid}
        )
        found = resolved.get("data") if isinstance(resolved.get("data"), dict) else {}
        ident = found.get("host_id")
        if type(ident) is not int or ident not in bridge.bindings:
            return {
                "status": "failed",
                "stage": "resolve",
                "sensitive": sensitive,
                "summary": None,
                "findings": [],
                "duration_ms": None,
                "error_code": str(found.get("error_code") or "mapping_unresolved")[:40],
                "error": _probe_text(
                    found.get("error")
                    or resolved.get("error")
                    or "SSH MCP 未返回该 Zabbix Host ID 的授权映射"
                ),
            }
        began = time.monotonic()
        outcome = await bridge.call("ssh_mcp", body.tool, {"host_id": ident})
        elapsed = int((time.monotonic() - began) * 1000)
        data = outcome.get("data") if isinstance(outcome.get("data"), dict) else {}
        findings = data.get("findings")
        return {
            "status": "failed"
            if outcome.get("is_error")
            else str(data.get("status") or outcome.get("status") or "success")[:20],
            "stage": "diagnose",
            "sensitive": sensitive,
            "ssh_host_id": ident,
            "host_revision": bridge.bindings[ident].get("revision"),
            "summary": redact_data(data.get("summary")),
            "findings": redact_data(findings[:50])
            if isinstance(findings, list)
            else [],
            "duration_ms": data["duration_ms"]
            if type(data.get("duration_ms")) is int
            else elapsed,
            "error_code": str(data["error_code"])[:40]
            if data.get("error_code")
            else None,
            "error": _probe_text(outcome.get("error") or data.get("error")),
        }


@router.post("/tools/probe")
async def probe_tool(body: ProbeInput, who=Depends(require("settings.manage"))):
    """诊断测试: one read-only SSH tool call on one host; no task, no AI."""
    if not re.fullmatch(r"ssh_[a-z0-9_]{1,90}", body.tool) or not body.tool.startswith(
        ("ssh_test_connection", "ssh_diagnose_")
    ):
        raise HTTPException(
            422, "诊断测试仅支持 ssh_test_connection 与 ssh_diagnose_* 只读工具"
        )
    unavailable = _ssh_unavailable(read_setting)
    if unavailable:
        raise HTTPException(422, unavailable)
    started = time.monotonic()
    result = {
        "provider": "ssh_mcp",
        "tool": body.tool,
        "zabbix_hostid": body.zabbix_hostid,
    }
    outcome = "error"
    limit = asyncio.timeout(PROBE_SECONDS)
    try:
        async with limit:
            result.update(await _probe(body, who, started + PROBE_SECONDS))
        outcome = result["status"]
    except BaseException as exc:
        root = _root(exc)
        if isinstance(root, HTTPException):
            outcome = "forbidden"
            raise root from None
        if isinstance(root, ProbeRejected):
            outcome = "rejected"
            raise HTTPException(422, str(root)) from None
        if limit.expired() or isinstance(root, TimeoutError):
            outcome = "timeout"
            result.update(
                status="failed",
                error_code="timeout",
                error="诊断测试超过 "
                + str(PROBE_SECONDS)
                + " 秒未完成；远端已开始的采集受 SSH MCP 自身超时控制",
                summary=None,
                findings=[],
                duration_ms=None,
            )
        elif isinstance(root, Exception):
            raise HTTPException(502, "诊断测试未完成：" + _reason(root)) from None
        else:
            raise
    finally:
        audit(
            who["open_id"],
            "tool_probe",
            f"{body.tool} host={body.zabbix_hostid} result={outcome}",
        )
    result["total_ms"] = int((time.monotonic() - started) * 1000)
    result["ok"] = result["status"] in {"success", "partial"}
    result["note"] = "诊断测试只调用一次只读工具；不创建诊断任务，不调用 AI。"
    return result


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
