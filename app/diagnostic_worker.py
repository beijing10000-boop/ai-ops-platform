"""RQ entry point for manual diagnostics and SSH connection checks."""

import asyncio
import logging
import time
from .main import connection, REDIS_URL, read_setting
from .inventory import get_asset
from .orchestrator import tasks
from .security.rbac import permits


def process(task_id):
    task = tasks.get(task_id, private=True)
    if not task or task["status"] != "queued":
        return {"skipped": True}
    if task["actor"] != "system" and not permits(task["actor"], "diagnostics.run"):
        tasks.finish(
            task_id,
            {"message": "提交者权限已撤销"},
            status="failed",
            error_type="PermissionRevoked",
        )
        return
    if task["kind"] == "connection":
        tasks.start(task_id)
        began = time.monotonic()
        asset = get_asset(task["asset_id"])
        try:
            if not asset or asset["revision"] != task["request"].get("asset_revision"):
                raise ValueError("资产配置已变更，请重新测试")
            from .diagnostics.ssh import execute

            result = execute(
                task["asset_id"],
                "connection",
                cancelled=lambda: tasks.cancelled(task_id),
            )
            tasks.evidence(
                task_id, "linux_ssh", "connection", result, result["duration_ms"]
            )
            tasks.finish(
                task_id,
                result,
                status=result["status"],
                duration_ms=int((time.monotonic() - began) * 1000),
            )
            with connection() as db:
                db.execute(
                    "UPDATE assets SET last_test_status=?,last_test_at=CURRENT_TIMESTAMP WHERE id=? AND revision=?",
                    (result["status"], asset["id"], asset["revision"]),
                )
            return result
        except Exception as exc:
            tasks.finish(
                task_id,
                {"message": str(exc)[:200]},
                status="cancelled" if tasks.cancelled(task_id) else "failed",
                error_type=type(exc).__name__,
                duration_ms=int((time.monotonic() - began) * 1000),
            )
            return
    from .mcp_runtime import run

    request = task["request"]
    try:
        return asyncio.run(
            run(
                read_setting("ai_qa_prompt")
                or "根据实际证据用中文输出结论、依据、建议和诊断不足。",
                request.get("question", "请诊断告警"),
                task_id=task_id,
                event=request.get("event"),
            )
        )
    except Exception as exc:
        if tasks.get(task_id)["status"] in ("queued", "running"):
            tasks.finish(
                task_id,
                {"message": "AI 分析未完成，请核对模型与连接配置"},
                status="failed",
                error_type=type(exc).__name__,
            )
        raise


if __name__ == "__main__":
    from redis import Redis
    from rq import Worker, Queue

    logging.basicConfig(level=logging.INFO)
    redis = Redis.from_url(REDIS_URL)
    Worker([Queue("ai-diagnostics", connection=redis)], connection=redis).work()
