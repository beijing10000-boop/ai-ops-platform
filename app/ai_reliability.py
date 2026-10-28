"""Bounded AI request retries and evidence-preserving fallback reports.

Model retries never re-run MCP calls. Evidence remains in the encrypted task store.
"""

import asyncio
import time

from openai import APIConnectionError, APIStatusError, APITimeoutError, RateLimitError


def model_failure_code(exc):
    if isinstance(exc, APITimeoutError):
        return "ModelTimeout"
    if isinstance(exc, RateLimitError):
        return "ModelRateLimited"
    if isinstance(exc, APIStatusError):
        return "ModelServiceError" if exc.status_code >= 500 else "ModelRequestError"
    if isinstance(exc, APIConnectionError):
        return "ModelConnectionError"
    return type(exc).__name__


def model_failure_message(exc):
    return {
        "ModelTimeout": "AI 模型请求超时",
        "ModelRateLimited": "AI 模型请求受到限流",
        "ModelServiceError": "AI 模型服务暂时不可用",
        "ModelRequestError": "AI 模型请求被拒绝",
        "ModelConnectionError": "AI 模型连接失败",
    }.get(model_failure_code(exc), "AI 模型请求失败")


async def request_response(client, *, deadline, timeout_seconds, reserve_seconds=12, **kwargs):
    """Up to one bounded retry, only for transient model errors and sufficient time."""
    for attempt in range(2):
        remaining = deadline - time.monotonic() - reserve_seconds
        if remaining <= 1:
            raise TimeoutError("任务剩余时间不足，无法继续请求 AI 模型")
        timeout = min(timeout_seconds, remaining)
        try:
            return await client.responses.create(timeout=timeout, **kwargs)
        except (APITimeoutError, APIConnectionError, APIStatusError) as exc:
            transient = isinstance(exc, APIConnectionError) or (
                isinstance(exc, APIStatusError)
                and (exc.status_code == 429 or exc.status_code >= 500)
            )
            if not transient or attempt or deadline - time.monotonic() - reserve_seconds < 25:
                raise
            # Do not retry cancelled tasks, non-transient 4xx errors, or without time.
            await asyncio.sleep(1)
    raise RuntimeError("unreachable")


def evidence_fallback(task_id, reason):
    """Build a factual partial report without pretending the model made a diagnosis."""
    from .orchestrator import tasks

    rows = tasks.evidence_page(task_id, include_logs=False)
    useful = [
        row for row in rows
        if row["status"] in ("success", "partial")
        and row["tool"] not in ("list_tools", "list_mcp_tools")
        and isinstance(row.get("payload"), dict)
        and not row["payload"].get("error")
        and not row["payload"].get("is_error")
    ]
    lines = [
        reason + "；模型未完成最终诊断。",
        "下列仅为已执行的工具及采集状态，不代表故障根因已经确认：",
    ]
    for row in useful[-12:]:
        payload = row["payload"]
        count = len(payload["records"]) if isinstance(payload.get("records"), list) else None
        suffix = f"（返回 {count} 条记录）" if count is not None else ""
        lines.append(f"- {row['provider']} / {row['tool']}: {row['status']}{suffix}")
    lines.append("请在下方“证据与工具执行记录”核验具体数值、时间和错误；未采集到的指标不能推断为正常。")
    return "\n".join(lines), bool(useful)
