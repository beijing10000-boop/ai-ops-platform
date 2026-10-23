"""One authenticated management API for assets, tools, tasks and evidence."""

import json
import re
import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from . import inventory
from .main import connection, read_setting
from .security.rbac import require, enforce, permits, ROLES, audit
from .orchestrator import tasks
from .diagnostics.actions import SERVICE
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
        hosts = db.execute(
            "SELECT COUNT(*),SUM(CASE WHEN zabbix_hostid IS NOT NULL THEN 1 ELSE 0 END),SUM(CASE WHEN credential_id IS NOT NULL AND host_key!='' AND address!='' AND enabled=1 THEN 1 ELSE 0 END),SUM(CASE WHEN last_test_status='success' AND enabled=1 THEN 1 ELSE 0 END) FROM assets WHERE device_type='linux'"
        ).fetchone()
        health = [
            dict(zip(("provider", "status", "checked_at", "detail"), r))
            for r in db.execute(
                "SELECT provider,status,checked_at,detail FROM integration_health"
            )
        ]
    with connection() as db:
        ai_counts=dict(db.execute("SELECT status,COUNT(*) FROM diagnostic_tasks WHERE kind='analysis' AND created_at>=datetime('now','-1 day') GROUP BY status"))
    ai_finished=sum(ai_counts.get(k,0) for k in ('success','partial','failed'))
    finished = sum(counts.get(k, 0) for k in ("success", "partial", "failed"))
    return {
        "scope": "平台已接收的告警；任务与用量为最近 24 小时",
        "unrecovered_received_events": active,
        "tasks_24h": sum(counts.values()),
        "ai_runs_24h":sum(ai_counts.values()),
        "ai_success_rate_24h":round(100*ai_counts.get("success",0)/ai_finished,1) if ai_finished else None,
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
        "linux_hosts": hosts[0],
        "linked_linux_hosts": hosts[1] or 0,
        "configured_ssh_hosts": hosts[2] or 0,
        "tested_ssh_hosts": hosts[3] or 0,
        "mcp_configured": bool(read_setting("mcp_url")),
        "linux_adapter": "available",
        "health": health,
    }


@router.get("/assets")
def assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    q: str = Query("", max_length=160),
    device_type: str = "all",
    group_id: int | None = None,
    who=Depends(require("inventory.read")),
):
    return inventory.asset_page(page, page_size, q, device_type, group_id)


@router.post("/assets", status_code=201)
def add_asset(body: inventory.AssetInput, who=Depends(require("inventory.manage"))):
    if body.credential_id or body.proxy_id or body.host_key or body.privileged_approved:
        enforce(who["open_id"], "credentials.manage")
    return write(lambda: inventory.save_asset(body, who["open_id"]))


@router.put("/assets/{asset_id}")
def edit_asset(
    asset_id: int, body: inventory.AssetInput, who=Depends(require("inventory.manage"))
):
    enforce(who["open_id"], "credentials.manage")
    return write(lambda: inventory.save_asset(body, who["open_id"], asset_id))


@router.delete("/assets/{asset_id}")
def disable_asset(asset_id: int, who=Depends(require("inventory.manage"))):
    with connection() as db:
        if not db.execute(
            "UPDATE assets SET enabled=0,revision=revision+1,last_test_status=NULL WHERE id=?",
            (asset_id,),
        ).rowcount:
            raise HTTPException(404, "资产不存在")
    audit(who["open_id"], "asset_disabled", asset_id)
    return {"ok": True}


class ImportAssets(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assets: list[inventory.AssetInput] = Field(min_length=1, max_length=1000)


@router.post("/assets-import")
def import_assets(body: ImportAssets, who=Depends(require("inventory.manage"))):
    enforce(who["open_id"], "credentials.manage")
    # Validate everything before beginning the all-or-nothing transaction.
    checked = write(lambda: [a.checked() for a in body.assets])

    def save():
        ids = []
        with connection() as db:
            for asset in checked:
                values = inventory.asset_values(asset)
                ident = db.execute(
                    "INSERT INTO assets("
                    + ",".join(values)
                    + ") VALUES ("
                    + ",".join("?" for _ in values)
                    + ")",
                    tuple(values.values()),
                ).lastrowid
                ids.append(ident)
                db.executemany(
                    "INSERT INTO asset_group_members VALUES (?,?)",
                    ((ident, g) for g in set(asset.group_ids)),
                )
        return ids

    ids = write(save)
    audit(who["open_id"], "asset_batch_import", len(ids))
    return {"count": len(ids), "ids": ids}


class GroupInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)


@router.get("/groups")
def groups(who=Depends(require("inventory.read"))):
    with connection() as db:
        return [
            dict(zip(("id", "name", "zabbix_groupid"), r))
            for r in db.execute("SELECT * FROM asset_groups ORDER BY name")
        ]


@router.post("/groups")
def add_group(body: GroupInput, who=Depends(require("inventory.manage"))):
    if not body.name.strip(): raise HTTPException(422,"主机组名称不能为空")
    def save():
        with connection() as db:
            return db.execute(
                "INSERT INTO asset_groups(name) VALUES (?)", (body.name.strip(),)
            ).lastrowid

    ident = write(save)
    audit(who["open_id"], "group_created", ident)
    return {"id": ident}


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    private_key: str = Field(min_length=32, max_length=20000)
    passphrase: str = Field(default="", max_length=1024)


@router.get("/credentials")
def credentials(who=Depends(require("credentials.manage"))):
    with connection() as db:
        return [
            dict(zip(("id", "name", "revision", "updated_at"), r))
            for r in db.execute(
                "SELECT id,name,revision,updated_at FROM ssh_credentials ORDER BY name"
            )
        ]


@router.post("/credentials")
def add_credential(body: CredentialInput, who=Depends(require("credentials.manage"))):
    return write(
        lambda: inventory.save_credential(
            body.name, body.private_key, body.passphrase, who["open_id"]
        )
    )


@router.put("/credentials/{credential_id}")
def rotate_credential(
    credential_id: int,
    body: CredentialInput,
    who=Depends(require("credentials.manage")),
):
    result = write(
        lambda: inventory.save_credential(
            body.name, body.private_key, body.passphrase, who["open_id"], credential_id
        )
    )
    return result


class ProxyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    address: str = Field(max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(max_length=32)
    host_key: str = Field(max_length=4096)
    credential_id: int = Field(ge=1)


@router.get("/proxies")
def proxies(who=Depends(require("credentials.manage"))):
    with connection() as db:
        cur = db.execute("SELECT * FROM ssh_proxies ORDER BY name")
        return [inventory.row_dict(r, cur) for r in cur.fetchall()]


def save_proxy(body, who, proxy_id=None):
    if not inventory.USER_RE.fullmatch(body.username):
        raise HTTPException(422, "SSH 用户名无效")
    values = body.model_dump()
    values["address"] = inventory.address(body.address)
    values["host_key"] = inventory.host_key(body.host_key)
    with connection() as db:
        if proxy_id:
            if not db.execute(
                "UPDATE ssh_proxies SET "
                + ",".join(k + "=?" for k in values)
                + " WHERE id=?",
                (*values.values(), proxy_id),
            ).rowcount:
                raise ValueError("跳板不存在")
            db.execute(
                "UPDATE assets SET revision=revision+1,last_test_status=NULL WHERE proxy_id=?",
                (proxy_id,),
            )
        else:
            proxy_id = db.execute(
                "INSERT INTO ssh_proxies("
                + ",".join(values)
                + ") VALUES ("
                + ",".join("?" for _ in values)
                + ")",
                tuple(values.values()),
            ).lastrowid
    audit(who["open_id"], "proxy_saved", proxy_id)
    return {"id": proxy_id}


@router.post("/proxies")
def add_proxy(body: ProxyInput, who=Depends(require("credentials.manage"))):
    return write(lambda: save_proxy(body, who))


@router.put("/proxies/{proxy_id}")
def edit_proxy(
    proxy_id: int, body: ProxyInput, who=Depends(require("credentials.manage"))
):
    return write(lambda: save_proxy(body, who, proxy_id))


@router.post("/assets-sync")
async def sync_assets(who=Depends(require("inventory.manage"))):
    from .integrations import zabbix

    try:
        async with zabbix.connect(read_setting) as session:
            if "host_get" not in zabbix.enabled_names(read_setting):
                raise ValueError("host_get 已被禁用")
            response = await zabbix.call(
                session,
                "host_get",
                {
                    "selectHostGroups": ["groupid", "name"],
                    "selectInventory": ["os", "type"],
                    "selectTags": ["tag", "value"],
                    "limit": 1000,
                },
            )
            if response.isError:
                raise ValueError("MCP 返回错误")
            records = zabbix.records(response)
    except Exception as exc:
        raise HTTPException(502, "资产同步失败：" + type(exc).__name__) from None
    with connection() as db:
        count = 0
        for host in records:
            hid = str(host.get("hostid", ""))
            if not re.fullmatch(r"[0-9]{1,32}", hid):
                continue
            # Never overwrite reviewed SSH routes, credentials, type overrides or public keys.
            db.execute(
                "INSERT INTO assets(name,zabbix_hostid,device_type) VALUES (?,?,?) ON CONFLICT(zabbix_hostid) DO UPDATE SET name=excluded.name",
                (
                    str(host.get("name") or host.get("host") or hid)[:160],
                    hid,
                    inventory.infer_device(host),
                ),
            )
            aid = db.execute(
                "SELECT id FROM assets WHERE zabbix_hostid=?", (hid,)
            ).fetchone()[0]
            for group in host.get("hostgroups") or host.get("groups") or []:
                gid = str(group.get("groupid", ""))
                if not gid.isdigit():
                    continue
                db.execute(
                    "INSERT INTO asset_groups(name,zabbix_groupid) VALUES (?,?) ON CONFLICT(zabbix_groupid) DO UPDATE SET name=excluded.name",
                    (str(group.get("name") or gid)[:160], gid),
                )
                db.execute(
                    "INSERT OR IGNORE INTO asset_group_members VALUES (?,(SELECT id FROM asset_groups WHERE zabbix_groupid=?))",
                    (aid, gid),
                )
            count += 1
    audit(who["open_id"], "zabbix_assets_synced", count)
    return {
        "count": count,
        "at_limit": len(records) >= 1000,
        "note": "仅以 Host ID 关联；SSH 地址与密钥须人工核验。单次最多同步 1000 台。",
    }


class TaskInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: int | None = Field(default=None, ge=1)
    event_id: str | None = Field(default=None, pattern=r"^[0-9]{1,32}$")
    diagnostic_type: str = "auto"
    profile: str = "standard"
    question: str = Field(default="请根据实际证据诊断故障并给出建议", max_length=3000)
    service: str | None = Field(default=None, max_length=64)
    time_window: int = Field(default=30, ge=1, le=120)


@router.post("/tasks", status_code=202)
def submit(body: TaskInput, who=Depends(require("diagnostics.run"))):
    if body.diagnostic_type not in set(PLAYBOOKS) | {"auto"} or body.profile not in (
        "quick",
        "standard",
        "deep",
    ):
        raise HTTPException(422, "诊断类型或模式无效")
    if body.service and not SERVICE.fullmatch(body.service):
        raise HTTPException(422, "服务名称无效")
    asset = inventory.get_asset(body.asset_id) if body.asset_id else None
    if body.asset_id and (not asset or not asset["enabled"]):
        raise HTTPException(422, "资产不存在或已禁用")
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
        bound = inventory.get_asset(zabbix_hostid=str(event.get("host_id")))
        if asset and asset["zabbix_hostid"] != str(event.get("host_id")):
            raise HTTPException(422, "资产与事件 Host ID 不匹配")
        asset = bound
    elif asset:
        event = {
            "host_id": asset["zabbix_hostid"] or "",
            "host_name": asset["name"],
            "event_name": body.question,
        }
    if body.diagnostic_type == "auto":
        body.diagnostic_type = classify(event.get("event_name") or body.question)
    request = {**body.model_dump(), "event": event}
    task, created = tasks.create(
        request,
        source="web",
        actor=who["open_id"],
        event_id=body.event_id,
        asset_id=asset["id"] if asset else None,
        diagnostic_type=body.diagnostic_type,
        profile=body.profile,
    )
    if created:
        write(lambda: tasks.enqueue(task["task_id"]))
    audit(who["open_id"], "analysis_submitted", task["task_id"], task["trace_id"])
    return {
        "task_id": task["task_id"],
        "trace_id": task["trace_id"],
        "duplicate": not created,
    }


@router.post("/assets/{asset_id}/test", status_code=202)
def test_ssh(asset_id: int, who=Depends(require("diagnostics.run"))):
    asset = inventory.get_asset(asset_id)
    if not asset or asset["device_type"] != "linux" or not asset["enabled"]:
        raise HTTPException(422, "需要已启用的 Linux 资产")
    task, _ = tasks.create(
        {"asset_revision": asset["revision"]},
        actor=who["open_id"],
        kind="connection",
        asset_id=asset_id,
        diagnostic_type="connection",
    )
    write(lambda: tasks.enqueue(task["task_id"]))
    return {"task_id": task["task_id"], "trace_id": task["trace_id"]}


@router.get("/tasks")
def task_page(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: str = "all",
    who=Depends(require("reports.read")),
):
    return tasks.page(page, page_size, status)


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
    asset = inventory.get_asset(task["asset_id"]) if task["asset_id"] else None
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
            "UPDATE diagnostic_tasks SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END WHERE task_id=? AND status IN ('queued','running')",
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
    request = {k: v for k, v in old["request"].items() if k != "limits"}
    task, created = tasks.create(
        request,
        source=old["source"],
        actor=who["open_id"],
        kind=old["kind"],
        event_id=old["event_id"],
        asset_id=old["asset_id"],
        diagnostic_type=old["diagnostic_type"],
        profile=old["profile"],
    )
    if created:
        write(lambda: tasks.enqueue(task["task_id"]))
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
            "provider": "linux_ssh",
            "device_types": ["linux"],
            "description": "已登记 Linux 资产的固定诊断动作",
            "read_only": True,
            "risk": "bounded_read",
            "timeout": int(read_setting("ssh_timeout") or 15),
            "max_output_chars": 32768,
            "required_scope": "diagnostics.run",
            "enabled": True,
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
        "modes": {
            "standard": "低权限账号，无需 Python/网关；账号本身不保证绝对只读",
            "privileged": "必须管理员授权并安装固定强制命令网关；root 不是真正只读",
        },
    }


@router.post("/tools/discover")
async def discover(who=Depends(require("settings.manage"))):
    from .integrations import zabbix

    try:
        async with zabbix.connect(read_setting) as session:
            listed = await zabbix.discover(session)
            allowed = zabbix.enabled_names(read_setting)
            names = sorted(t.name for t in listed if t.name in allowed)
        status = "success"
        detail = json.dumps({"authorized_tools": names}, ensure_ascii=False)
    except Exception as exc:
        status = "failed"
        detail = type(exc).__name__
        names = []
    with connection() as db:
        db.execute(
            "INSERT INTO integration_health(provider,status,detail) VALUES (?,?,?) ON CONFLICT(provider) DO UPDATE SET status=excluded.status,checked_at=CURRENT_TIMESTAMP,detail=excluded.detail",
            ("zabbix_mcp", status, detail),
        )
    return {
        "ok": status == "success",
        "authorized_tools": names,
        "detail": detail,
        "note": "工具发现成功不代表远端 Zabbix API 账号已被核验为只读",
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
            "items": [inventory.row_dict(r, cur) for r in cur.fetchall()],
            "total": total,
            "page": page,
            "page_size": page_size,
        }


@router.put('/groups/{group_id}')
def edit_group(group_id:int,body:GroupInput,who=Depends(require('inventory.manage'))):
    if not body.name.strip(): raise HTTPException(422,'主机组名称不能为空')
    def save():
        with connection() as db:
            row=db.execute('SELECT zabbix_groupid FROM asset_groups WHERE id=?',(group_id,)).fetchone()
            if not row: raise HTTPException(404,'主机组不存在')
            if row[0]: raise HTTPException(409,'同步组由 Zabbix 维护，本地只编辑手工组')
            db.execute('UPDATE asset_groups SET name=? WHERE id=?',(body.name.strip(),group_id))
    write(save); audit(who['open_id'],'group_updated',group_id); return {'ok':True}


@router.delete('/groups/{group_id}')
def delete_group(group_id:int,who=Depends(require('inventory.manage'))):
    with connection() as db:
        row=db.execute('SELECT zabbix_groupid FROM asset_groups WHERE id=?',(group_id,)).fetchone()
        if not row: raise HTTPException(404,'主机组不存在')
        if row[0]: raise HTTPException(409,'同步组由 Zabbix 维护，本地只删除手工组')
        db.execute('DELETE FROM asset_groups WHERE id=?',(group_id,))
    audit(who['open_id'],'group_deleted',group_id); return {'ok':True}
