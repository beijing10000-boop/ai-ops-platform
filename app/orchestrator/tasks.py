"""Durable task state and encrypted reports. RQ is the execution transport."""

import hashlib
import json
import logging
import sqlite3
import uuid
from ..platform_db import row_dict

log = logging.getLogger(__name__)


class Cancelled(RuntimeError):
    pass


class AlreadyRunning(RuntimeError):
    pass


class QueueUnavailable(RuntimeError):
    pass


def recover_stalled(db):
    # Long configured budgets must not be mistaken for lost workers after ten minutes.
    rows = db.execute(
        "SELECT task_id,request,strftime('%s','now')-strftime('%s',started_at) FROM diagnostic_tasks WHERE status='running' AND started_at<datetime('now','-10 minutes')"
    ).fetchall()
    for task_id, raw, elapsed in rows:
        seconds = (decode(raw) or {}).get("limits", {}).get("seconds", 240)
        if elapsed > max(600, seconds + 120):
            db.execute(
                "UPDATE diagnostic_tasks SET status='failed',stage='failed',error_type='WorkerLost',completed_at=CURRENT_TIMESTAMP WHERE task_id=? AND status='running'",
                (task_id,),
            )


def progress(task_id):
    from ..main import connection

    with connection() as db:
        recover_stalled(db)
        cur = db.execute(
            "SELECT task_id,status,stage,tools,cancel_requested,error_type,completed_at FROM diagnostic_tasks WHERE task_id=?",
            (task_id,),
        )
        return row_dict(cur.fetchone(), cur)


def encode(value):
    from ..main import cipher

    return cipher().encrypt(json.dumps(value, ensure_ascii=False).encode()).decode()


def decode(value):
    from ..main import cipher

    return json.loads(cipher().decrypt(value.encode()).decode()) if value else None


def store_blob(db, kind, value):
    """Keep one encrypted copy of repeated content; rows store the digest."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(text.encode()).hexdigest()
    db.execute(
        "INSERT OR IGNORE INTO shared_blobs(digest,kind,payload) VALUES (?,?,?)",
        (digest, kind, encode(value)),
    )
    return digest


def load_blob(db, digest):
    row = db.execute(
        "SELECT payload FROM shared_blobs WHERE digest=?", (digest,)
    ).fetchone()
    return decode(row[0]) if row else None


def _hydrate_request(db, request):
    """Expand Skill references; requests saved before v1.0 are inline already."""
    skills = (request or {}).get("skills")
    if not isinstance(skills, list):
        return request
    return {
        **request,
        "skills": [
            (load_blob(db, row["blob"]) or row)
            if isinstance(row, dict) and "blob" in row
            else row
            for row in skills
        ],
    }


def hydrate_interaction(db, payload):
    """Expand the shared system instructions of one stored model round."""
    instructions = ((payload or {}).get("request") or {}).get("instructions")
    if not isinstance(instructions, dict) or "blob" not in instructions:
        return payload
    text = load_blob(db, instructions["blob"])
    return {
        **payload,
        "request": {
            **payload["request"],
            "instructions": {**instructions, "text": text if text is not None else ""},
        },
    }


def create(
    request,
    *,
    source="web",
    actor="system",
    kind="analysis",
    asset_id=None,
    event_id=None,
    diagnostic_type="bottleneck",
    profile="standard",
):
    from ..main import connection, read_setting
    from .budgets import profile as profile_limits
    from ..skill_store import snapshot

    task_id = uuid.uuid4().hex
    trace_id = uuid.uuid4().hex
    limits = profile_limits(profile, read_setting)
    skills = snapshot(request, source)
    duplicate_id = None
    with connection() as db:
        # Every task keeps its exact Skill versions, stored once per content.
        request = {
            **request,
            "limits": limits,
            "skills": [{"blob": store_blob(db, "skill", row)} for row in skills],
        }
        try:
            db.execute(
                "INSERT INTO diagnostic_tasks(task_id,trace_id,kind,source,actor,event_id,asset_id,diagnostic_type,profile,request) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    task_id,
                    trace_id,
                    kind,
                    source,
                    actor,
                    event_id or None,
                    asset_id,
                    diagnostic_type,
                    profile,
                    encode(request),
                ),
            )
        except sqlite3.IntegrityError:
            if event_id:
                row = db.execute(
                    "SELECT task_id FROM diagnostic_tasks WHERE event_id=? AND kind='analysis' AND status IN ('queued','running')",
                    (event_id,),
                ).fetchone()
                if row:
                    duplicate_id = row[0]
            if not duplicate_id:
                raise
    if duplicate_id:
        return get(duplicate_id), False
    return get(task_id), True


def get(task_id, private=False):
    from ..main import connection

    with connection() as db:
        recover_stalled(db)
        cur = db.execute("SELECT * FROM diagnostic_tasks WHERE task_id=?", (task_id,))
        result = row_dict(cur.fetchone(), cur)
        if result:
            result["report"] = decode(result["report"])
            raw = result.pop("request")
            if private:
                result["request"] = _hydrate_request(db, decode(raw))
    return result


def start(task_id):
    from ..main import connection

    with connection() as db:
        cur = db.execute(
            "UPDATE diagnostic_tasks SET status='running',stage='collecting',started_at=CURRENT_TIMESTAMP,attempt=attempt+1 WHERE task_id=? AND status='queued' AND cancel_requested=0",
            (task_id,),
        )
        if not cur.rowcount:
            raise AlreadyRunning("任务已在执行或已结束")


def cancelled(task_id):
    from ..main import connection

    with connection() as db:
        row = db.execute(
            "SELECT cancel_requested FROM diagnostic_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
    return not row or bool(row[0])


def stage(task_id, value):
    from ..main import connection

    if cancelled(task_id):
        raise Cancelled("任务已取消")
    with connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET stage=? WHERE task_id=?", (value[:80], task_id)
        )


def evidence(task_id, provider, tool, payload, duration_ms=0):
    from ..main import connection

    task = get(task_id)
    status = (
        "failed"
        if payload.get("error") or payload.get("is_error")
        else payload.get("status", "success")
    )
    with connection() as db:
        db.execute(
            "INSERT INTO diagnostic_evidence(task_id,trace_id,provider,tool,status,duration_ms,payload) VALUES (?,?,?,?,?,?,?)",
            (
                task_id,
                task["trace_id"],
                provider,
                tool,
                status,
                duration_ms,
                encode(payload),
            ),
        )
        db.execute(
            "UPDATE diagnostic_tasks SET tools=tools+1 WHERE task_id=?", (task_id,)
        )


def evidence_page(task_id, include_logs=False):
    from ..main import connection

    with connection() as db:
        cur = db.execute(
            "SELECT * FROM diagnostic_evidence WHERE task_id=? ORDER BY id LIMIT 200",
            (task_id,),
        )
        rows = [row_dict(row, cur) for row in cur.fetchall()]
    for row in rows:
        row["payload"] = decode(row["payload"])
        if (
            row["tool"]
            in {
                "logs",
                "kernel",
                "ssh_diagnose_logs",
                "ssh_diagnose_kernel",
                "ssh_diagnose_system_errors",
                "ssh_diagnose_oom",
                "ssh_triage",
            }
            and not include_logs
        ):
            payload = row["payload"]
            error = str(payload.get("error") or "").casefold()
            reason = None
            if "预算" in error or "budget" in error:
                reason = "采集预算不足，工具未调用；可提高对应模式的采集次数或时间上限"
            elif any(
                word in error
                for word in ("权限", "拒绝", "permission", "denied", "forbidden")
            ):
                reason = "SSH MCP 拒绝采集，请检查客户端动作授权及目标主机日志读取权限"
            elif row["status"] == "failed":
                reason = "日志工具调用失败；有权限的用户可读取原始错误详情"
            row["payload"] = {
                "restricted": True,
                "status": row["status"],
                "message": "日志正文默认隐藏；具有 logs.read 权限可点击“读取日志证据”查看。此提示不代表工具调用被拒绝。",
                **({"failure_reason": reason} if reason else {}),
            }
    return rows


def model_interaction_page(task_id, *, include_content=False):
    """Read per-round model metadata; body requires separate logs.read permission."""
    from ..main import connection

    with connection() as db:
        cur = db.execute(
            "SELECT id,round_number,model,status,created_at,duration_ms,"
            "token_input,token_output,token_total,payload "
            "FROM model_interactions WHERE task_id=? ORDER BY id LIMIT 100",
            (task_id,),
        )
        rows = [row_dict(row, cur) for row in cur.fetchall()]
        for row in rows:
            encrypted = row.pop("payload")
            if include_content:
                row["payload"] = hydrate_interaction(db, decode(encrypted))
    return rows


def finish(
    task_id, report, usage=None, status="success", error_type=None, duration_ms=None
):
    from ..main import connection

    usage = usage or {}
    with connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET status=?,stage=?,report=?,error_type=?,completed_at=CURRENT_TIMESTAMP,duration_ms=?,token_input=?,token_output=?,token_total=? WHERE task_id=?",
            (
                status,
                status,
                encode(report),
                error_type,
                duration_ms,
                usage.get("input") if usage.get("available") else None,
                usage.get("output") if usage.get("available") else None,
                usage.get("total") if usage.get("available") else None,
                task_id,
            ),
        )
    try:
        purge_expired()
    except Exception:
        # Retention is housekeeping; it must never fail the task being finished.
        log.exception("DATA_RETENTION_PURGE_FAILED")


def purge_expired():
    """Delete evidence and model-round details of tasks finished more than
    `data_retention_days` ago. Task rows, conclusions and Token totals stay.
    Runs at most once a day across all workers; 0 days keeps everything."""
    from ..main import connection, read_setting

    try:
        days = int(read_setting("data_retention_days") or "0")
    except ValueError:
        return None
    if days <= 0:
        return None
    with connection() as db:
        claimed = db.execute(
            "INSERT INTO maintenance(key,value) VALUES ('retention_last_run',datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value "
            "WHERE maintenance.value <= datetime('now','-1 day')"
        ).rowcount
        if not claimed:
            return None
        expired = (
            "SELECT task_id FROM diagnostic_tasks WHERE status NOT IN ('queued','running') "
            "AND completed_at < datetime('now', ?)"
        )
        cutoff = "-" + str(days) + " days"
        counts = {
            "evidence": db.execute(
                "DELETE FROM diagnostic_evidence WHERE task_id IN (" + expired + ")",
                (cutoff,),
            ).rowcount,
            "interactions": db.execute(
                "DELETE FROM model_interactions WHERE task_id IN (" + expired + ")",
                (cutoff,),
            ).rowcount,
        }
        db.execute(
            "INSERT INTO audit(action,key) VALUES (?,?)",
            (
                "data_retention_purge",
                f"days={days} evidence={counts['evidence']} interactions={counts['interactions']}",
            ),
        )
    return counts


def page(page=1, page_size=25, status="all", query=""):
    from ..main import connection
    from ..operations import literal_search

    clauses = [] if status == "all" else ["status=?"]
    args = [] if status == "all" else [status]
    if query.strip():
        clauses.append(
            "(task_id LIKE ? ESCAPE '\\' OR event_id LIKE ? ESCAPE '\\' OR trace_id LIKE ? ESCAPE '\\')"
        )
        args.extend([literal_search(query.strip())] * 3)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connection() as db:
        recover_stalled(db)
        total = db.execute(
            "SELECT COUNT(*) FROM diagnostic_tasks" + where, args
        ).fetchone()[0]
        cur = db.execute(
            "SELECT task_id,trace_id,kind,source,actor,event_id,asset_id,diagnostic_type,profile,status,stage,error_type,created_at,started_at,completed_at,duration_ms,token_input,token_output,token_total,tools FROM diagnostic_tasks"
            + where
            + " ORDER BY created_at DESC,rowid DESC LIMIT ? OFFSET ?",
            (*args, page_size, (page - 1) * page_size),
        )
        rows = [row_dict(row, cur) for row in cur.fetchall()]
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


def enqueue(task_id):
    from redis import Redis
    from rq import Queue
    from ..main import REDIS_URL

    try:
        Queue(
            "ai-diagnostics",
            connection=Redis.from_url(
                REDIS_URL, socket_connect_timeout=2, socket_timeout=3
            ),
        ).enqueue(
            "app.diagnostic_worker.process",
            task_id,
            job_id=task_id,
            # The runtime enforces the Web-configured deadline; no second fixed cap.
            job_timeout=-1,
            result_ttl=86400,
        )
    except Exception:
        finish(
            task_id,
            {"message": "任务入队失败，请检查 Redis 后重试"},
            status="failed",
            error_type="QueueUnavailable",
        )
        raise QueueUnavailable("诊断队列暂不可用") from None
