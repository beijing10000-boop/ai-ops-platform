"""RQ entry point for AI analysis through the two external MCP connections."""

import asyncio
import logging
from .main import REDIS_URL, read_setting
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
    if task["kind"] != "analysis":
        tasks.finish(
            task_id,
            {"message": "本地 SSH 任务已停用，请在独立 SSH MCP 管理"},
            status="failed",
            error_type="LocalSSHRemoved",
        )
        return
    from .mcp_runtime import run

    request = task["request"]
    try:
        return asyncio.run(
            run(
                read_setting("ai_alert_prompt" if task["event_id"] else "ai_qa_prompt")
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
