"""Durable batch host-key discovery and explicit, revision-checked confirmation."""

import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException
from redis import Redis
from rq import Queue

from ..main import connection, REDIS_URL
from ..security.rbac import audit, permits
from ..security.redact import redact
from ..diagnostics.host_keys import fetch_key
from . import address, fingerprint, get_asset, host_key, row_dict

MAX_BATCH = 1000
PARALLELISM = 4


def targets(query="", device_type="all", group_id=None):
    clauses = ["enabled=1", "device_type='linux'", "address!=''"]
    args = []
    if device_type not in ("all", "linux"):
        return []
    if query:
        clauses.append("(instr(lower(name),lower(?))>0 OR instr(address,?)>0 OR zabbix_hostid=?)")
        args.extend((query, query, query))
    if group_id:
        clauses.append("id IN (SELECT asset_id FROM asset_group_members WHERE group_id=?)")
        args.append(group_id)
    with connection() as db:
        ids = [r[0] for r in db.execute(
            "SELECT id FROM assets WHERE " + " AND ".join(clauses)
            + " ORDER BY id DESC LIMIT ?", (*args, MAX_BATCH + 1),
        )]
    if len(ids) > MAX_BATCH:
        raise HTTPException(422, "匹配超过 1000 台，请按主机组或名称分批选择")
    return ids


def enqueue(scan_id, total):
    Queue(
        "ai-host-keys",
        connection=Redis.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=3),
    ).enqueue(
        "app.inventory.host_keys.collect", scan_id,
        job_id="host-keys-" + scan_id, job_timeout=max(300, total * 20),
        result_ttl=86400,
    )


def create(asset_ids, actor):
    ids = list(dict.fromkeys(asset_ids))
    if not ids or len(ids) > MAX_BATCH or any(type(i) is not int or i < 1 for i in ids):
        raise HTTPException(422, "请选择 1–1000 台已登记主机")
    scan_id = uuid.uuid4().hex
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        rows = []
        for ident in ids:
            cur = db.execute("SELECT * FROM assets WHERE id=?", (ident,))
            asset = row_dict(cur.fetchone(), cur)
            if not asset or not asset["enabled"] or asset["device_type"] != "linux" or not asset["address"]:
                raise HTTPException(422, f"资产 {ident} 需要是已启用且已配置内网 IP 的 Linux 主机")
            try:
                address(asset["address"])
                previous_fingerprint = fingerprint(asset["host_key"])
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
            rows.append((
                scan_id, ident, asset["name"], asset["address"], asset["ssh_port"],
                asset["revision"], asset["host_key"],
                previous_fingerprint,
            ))
        db.execute(
            "INSERT INTO host_key_scans(scan_id,actor,total) VALUES (?,?,?)",
            (scan_id, actor, len(rows)),
        )
        db.executemany(
            "INSERT INTO host_key_scan_items(scan_id,asset_id,name,address,port,asset_revision,previous_key,previous_fingerprint) VALUES (?,?,?,?,?,?,?,?)",
            rows,
        )
    audit(actor, "host_keys_requested", len(ids), scan_id)
    try:
        enqueue(scan_id, len(ids))
    except Exception:
        fail_pending(scan_id, "获取队列不可用，请检查 Redis 和 host-key-worker 后重试")
    return {"scan_id": scan_id, "total": len(ids)}


def fail_pending(scan_id, message):
    with connection() as db:
        db.execute(
            "UPDATE host_key_scan_items SET status='failed',error=? WHERE scan_id=? AND status='pending'",
            (message, scan_id),
        )
        db.execute(
            "UPDATE host_key_scans SET status='failed',error=?,updated_at=CURRENT_TIMESTAMP WHERE scan_id=?",
            (message, scan_id),
        )


def _collect_one(scan_id, item, actor):
    status, candidate, error = "failed", "", ""
    try:
        if not permits(actor, "credentials.manage"):
            raise ValueError("提交者的凭据管理权限已撤销")
        asset = get_asset(item["asset_id"])
        if not asset or asset["revision"] != item["asset_revision"] or not asset["enabled"]:
            raise ValueError("资产配置已变更，请重新获取")
        candidate = fetch_key(asset)
        current = get_asset(item["asset_id"])
        if not current or current["revision"] != item["asset_revision"]:
            raise ValueError("获取期间资产配置已变更，请重新获取")
        candidate = host_key(candidate)
        status = (
            "unchanged" if candidate == item["previous_key"]
            else "changed" if item["previous_key"] else "new"
        )
    except Exception as exc:
        candidate = ""
        error = redact(str(exc), 240)
    with connection() as db:
        db.execute(
            "UPDATE host_key_scan_items SET status=?,host_key=?,fingerprint=?,error=?,collected_at=CURRENT_TIMESTAMP WHERE scan_id=? AND asset_id=? AND status='pending' AND EXISTS(SELECT 1 FROM host_key_scans WHERE scan_id=? AND status='running')",
            (status, candidate, fingerprint(candidate), error, scan_id, item["asset_id"], scan_id),
        )
        db.execute(
            "UPDATE host_key_scans SET updated_at=CURRENT_TIMESTAMP WHERE scan_id=? AND status='running'",
            (scan_id,),
        )


def collect(scan_id):
    with connection() as db:
        if not db.execute(
            "UPDATE host_key_scans SET status='running',updated_at=CURRENT_TIMESTAMP WHERE scan_id=? AND status='queued'",
            (scan_id,),
        ).rowcount:
            return
        actor = db.execute(
            "SELECT actor FROM host_key_scans WHERE scan_id=?", (scan_id,)
        ).fetchone()[0]
        cur = db.execute(
            "SELECT * FROM host_key_scan_items WHERE scan_id=? AND status='pending'",
            (scan_id,),
        )
        items = [row_dict(row, cur) for row in cur.fetchall()]
    try:
        with ThreadPoolExecutor(max_workers=PARALLELISM) as pool:
            list(pool.map(lambda item: _collect_one(scan_id, item, actor), items))
        with connection() as db:
            db.execute(
                "UPDATE host_key_scans SET status='completed',updated_at=CURRENT_TIMESTAMP WHERE scan_id=? AND status='running'",
                (scan_id,),
            )
    except Exception:
        fail_pending(scan_id, "获取任务中断，请重试未完成主机")


def recent():
    with connection() as db:
        cur = db.execute("SELECT * FROM host_key_scans ORDER BY created_at DESC,rowid DESC LIMIT 10")
        return [row_dict(row, cur) for row in cur.fetchall()]


def detail(scan_id, page=1, page_size=50):
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        stale = db.execute(
            "SELECT 1 FROM host_key_scans WHERE scan_id=? AND status='running' AND updated_at<datetime('now','-2 minutes')",
            (scan_id,),
        ).fetchone()
        if stale:
            db.execute(
                "UPDATE host_key_scan_items SET status='failed',error='Worker 中断，请重试未完成主机' WHERE scan_id=? AND status='pending'",
                (scan_id,),
            )
            db.execute(
                "UPDATE host_key_scans SET status='failed',error='Worker 中断',updated_at=CURRENT_TIMESTAMP WHERE scan_id=?",
                (scan_id,),
            )
        cur = db.execute("SELECT * FROM host_key_scans WHERE scan_id=?", (scan_id,))
        scan = row_dict(cur.fetchone(), cur)
        if not scan:
            raise HTTPException(404, "获取批次不存在")
        cur = db.execute(
            "SELECT asset_id,name,address,port,status,host_key,fingerprint,previous_fingerprint,error,collected_at FROM host_key_scan_items WHERE scan_id=? ORDER BY asset_id LIMIT ? OFFSET ?",
            (scan_id, page_size, (page - 1) * page_size),
        )
        scan["items"] = [row_dict(row, cur) for row in cur.fetchall()]
        scan["counts"] = dict(db.execute(
            "SELECT status,COUNT(*) FROM host_key_scan_items WHERE scan_id=? GROUP BY status",
            (scan_id,),
        ))
        scan["new_ids"] = [r[0] for r in db.execute(
            "SELECT asset_id FROM host_key_scan_items WHERE scan_id=? AND status='new'", (scan_id,),
        )]
        scan["changed_ids"] = [r[0] for r in db.execute(
            "SELECT asset_id FROM host_key_scan_items WHERE scan_id=? AND status='changed'", (scan_id,),
        )]
        scan["page"], scan["page_size"] = page, page_size
        return scan


def retry(scan_id, actor):
    scan = detail(scan_id)
    if scan["status"] not in ("completed", "failed"):
        raise HTTPException(409, "获取尚未结束，请等待")
    with connection() as db:
        ids = [r[0] for r in db.execute(
            "SELECT asset_id FROM host_key_scan_items WHERE scan_id=? AND status='failed'",
            (scan_id,),
        )]
    if not ids:
        raise HTTPException(409, "没有失败主机需要重试")
    return create(ids, actor)


def confirm(scan_id, asset_ids, actor, verified, replace_changed=False):
    if not verified:
        raise HTTPException(422, "请先通过可信渠道核对所选 SHA256 指纹")
    ids = list(dict.fromkeys(asset_ids))
    if not ids or len(ids) > MAX_BATCH or any(type(i) is not int or i < 1 for i in ids):
        raise HTTPException(422, "请选择需要确认的主机")
    saved = 0
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        scan = db.execute("SELECT status FROM host_key_scans WHERE scan_id=?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(404, "获取批次不存在")
        if scan[0] not in ("completed", "failed"):
            raise HTTPException(409, "获取尚未结束，请等待")
        for ident in ids:
            cur = db.execute(
                "SELECT * FROM host_key_scan_items WHERE scan_id=? AND asset_id=?",
                (scan_id, ident),
            )
            item = row_dict(cur.fetchone(), cur)
            cur = db.execute("SELECT * FROM assets WHERE id=?", (ident,))
            asset = row_dict(cur.fetchone(), cur)
            if not item or item["status"] not in ("new", "changed", "saved"):
                raise HTTPException(409, f"资产 {ident} 没有可确认的候选公钥")
            if item["status"] == "saved" and asset and asset["host_key"] == item["host_key"]:
                continue
            if not asset or not asset["enabled"] or asset["device_type"] != "linux" or asset["revision"] != item["asset_revision"]:
                raise HTTPException(409, f"资产 {ident} 配置已变更，请重新获取；所选公钥均未保存")
            if item["status"] == "changed" and not replace_changed:
                raise HTTPException(409, f"资产 {ident} 公钥有变化，需要明确确认替换")
            candidate = host_key(item["host_key"])
            db.execute(
                "UPDATE assets SET host_key=?,revision=revision+1,last_test_status=NULL,last_test_at=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (candidate, ident),
            )
            db.execute(
                "UPDATE host_key_scan_items SET status='saved',saved_at=CURRENT_TIMESTAMP WHERE scan_id=? AND asset_id=?",
                (scan_id, ident),
            )
            db.execute(
                "INSERT INTO audit(action,key,actor,trace_id) VALUES ('host_key_confirmed',?,?,?)",
                (str(ident), actor, scan_id),
            )
            saved += 1
    return {"saved": saved, "already_saved": len(ids) - saved, "scan_id": scan_id}
