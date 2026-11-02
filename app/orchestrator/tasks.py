"""Durable task state and encrypted reports. RQ is the execution transport."""

import hashlib
import json
import logging
import re
import sqlite3
import uuid

try:
    from rq.exceptions import StopRequested
except ImportError:  # RQ 1.x (requirements allow >=1.16) keeps it in rq.worker
    from rq.worker import StopRequested
from ..platform_db import row_dict
from . import queues

log = logging.getLogger(__name__)
# Log-like tool names: the sensitivity of a tool whose catalog entry does not
# say, and of evidence saved without _meta (records before v1.2). Sensitive
# evidence is hidden without logs.read.
SENSITIVE_TOOL = re.compile(
    r"(logs?|journal|syslog|kernel|errors|oom|nginx|java|jvm|service_detail|triage|collect)"
)


class Cancelled(RuntimeError):
    pass


class AlreadyRunning(RuntimeError):
    pass


class QueueUnavailable(RuntimeError):
    pass


# error_type of an alert analysis that failed before it started because the
# enabled Skills could not be loaded (their bodies over the 128 KB limit, or
# reading them failed).
SNAPSHOT_FAILED = "SkillSnapshotFailed"


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


def stall_seconds():
    """What still runs after the longest configured analysis budget (at least
    ten minutes, as recover_stalled) has lost its worker."""
    from ..main import read_setting
    from .budgets import PROFILES, profile

    longest = max(profile(name, read_setting)["seconds"] for name in PROFILES)
    return max(600, longest + 120)


# RQ job states of a job that will still run, or is running.
WAITING = ("queued", "started", "deferred", "scheduled")


def reconcile(job_state=None):
    """Close tasks killed workers left behind; nothing is queued or run again.

    A running task past its deadline lost its worker (recover_stalled, which
    otherwise only runs when a task is read). A task queued for over ten
    minutes whose RQ job (job id = task id) is gone or over will never start:
    the job failed before starting it, its worker died, or Redis lost it.
    `job_state(job_id)` gives the RQ status, None for a missing job; a lookup
    failing any other way counts as waiting. Without it (no Redis) queued
    tasks are left alone.
    """
    from ..main import connection

    with connection() as db:
        recover_stalled(db)
        queued = [
            row[0]
            for row in db.execute(
                "SELECT task_id FROM diagnostic_tasks WHERE status='queued' "
                "AND created_at<datetime('now','-10 minutes')"
            )
        ]
    if job_state is None:
        return
    lost = []
    for task_id in queued:
        try:
            state = job_state(task_id)
        except StopRequested:
            raise  # RQ's SIGTERM while the worker is idle: let it stop
        except Exception as exc:
            # Redis answered something unexpected: the job may still run, and
            # no task is failed on a guess.
            log.warning(
                "RECONCILE_JOB_STATE_UNKNOWN task_id=%s error=%s",
                task_id,
                type(exc).__name__,
            )
            continue
        if state not in WAITING:
            lost.append(task_id)
    if not lost:
        return
    report = encode(
        {"message": "排队中的任务未能执行（Worker 中断或队列数据丢失），请重新发起分析"}
    )
    with connection() as db:
        for task_id in lost:
            db.execute(
                "UPDATE diagnostic_tasks SET status='failed',stage='failed',"
                "error_type='QueueLost',report=?,completed_at=CURRENT_TIMESTAMP "
                "WHERE task_id=? AND status='queued'",
                (report, task_id),
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
    try:
        skills = snapshot(request, source)
    except Exception as exc:
        if source == "alert" and event_id:
            # An alert analysis that cannot load its Skills must not just not
            # happen: the failed task says why where the alert links to.
            unstarted(
                task_id,
                trace_id,
                {**request, "limits": limits, "skills": []},
                snapshot_failure(exc),
                kind=kind,
                source=source,
                actor=actor,
                event_id=event_id,
                asset_id=asset_id,
                diagnostic_type=diagnostic_type,
                profile=profile,
            )
        raise
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


def snapshot_failure(exc):
    """Why the enabled Skills could not be loaded, in words an administrator
    can act on: the platform's own message, else only the error class."""
    detail = getattr(exc, "detail", None)
    if isinstance(detail, dict):
        detail = detail.get("message")
    if isinstance(detail, str) and detail.strip():
        return detail.strip()[:300]
    if isinstance(exc, ValueError) and str(exc).strip():
        return str(exc).strip()[:300]
    return "读取 Skill 时出错（" + type(exc).__name__ + "）"


def unstarted(task_id, trace_id, request, reason, **fields):
    """A failed task for an alert analysis whose Skills could not be loaded:
    the alert's AI status reads failed and its report says why. A task that
    cannot be stored either (the database itself failing) is only logged."""
    from ..main import connection

    message = (
        "AI 分析未执行：加载诊断 Skill 失败（"
        + reason
        + "）。请在 Skill 管理中处理后，在告警卡片上点「🤖 AI分析」重新分析。"
    )
    try:
        with connection() as db:
            db.execute(
                "INSERT INTO diagnostic_tasks(task_id,trace_id,kind,source,actor,event_id,"
                "asset_id,diagnostic_type,profile,request,status,stage,report,error_type,"
                "completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,'failed','failed',?,?,"
                "CURRENT_TIMESTAMP)",
                (
                    task_id,
                    trace_id,
                    fields["kind"],
                    fields["source"],
                    fields["actor"],
                    fields["event_id"],
                    fields["asset_id"],
                    fields["diagnostic_type"],
                    fields["profile"],
                    encode(request),
                    encode(
                        {
                            "answer": message,
                            "message": message,
                            "limitations": [message],
                        }
                    ),
                    SNAPSHOT_FAILED,
                ),
            )
    except Exception:
        log.exception(
            "SKILL_SNAPSHOT_FAILURE_NOT_RECORDED event_id=%s", fields["event_id"]
        )
        return
    log.warning(
        "SKILL_SNAPSHOT_FAILED event_id=%s task_id=%s reason=%s",
        fields["event_id"],
        task_id,
        reason,
    )


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
        row = db.execute(
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
    return row.lastrowid


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
        meta = row["payload"].get("_meta") if isinstance(row["payload"], dict) else None
        meta = meta if isinstance(meta, dict) else {}
        sensitive = meta.get("sensitive") is True or bool(
            SENSITIVE_TOOL.search(str(row["tool"] or ""))
        )
        if sensitive and not include_logs:
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
                # Call metadata (kind, redacted arguments, evidence id) is not log text.
                **({"_meta": meta} if meta else {}),
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
            queues.DIAGNOSTICS,
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
