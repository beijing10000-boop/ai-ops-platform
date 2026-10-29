"""Encrypted, bounded, redacted diagnostics of OpenAI Responses API exchanges.

Store request/response previews for authorized operators, never raw reasoning,
credentials, SDK objects, or complete potentially huge multi-round contexts.
"""

import json
import logging
import time

from .security.redact import redact, redact_data

log = logging.getLogger(__name__)
_PREVIEW_LIMIT = 16000


def _strip_internal_reasoning(value):
    """Never persist model reasoning or opaque encrypted reasoning from prior rounds."""
    if isinstance(value, list):
        return [_strip_internal_reasoning(item) for item in value]
    if isinstance(value, dict):
        if value.get("type") == "reasoning":
            return {"type": "reasoning", "omitted": True}
        return {
            key: _strip_internal_reasoning(item)
            for key, item in value.items()
            if key not in ("encrypted_content", "reasoning")
        }
    return value


def _preview(value, secret_values=()):
    if isinstance(value, (dict, list)):
        value = json.dumps(
            redact_data(_strip_internal_reasoning(value)),
            ensure_ascii=False,
            default=str,
        )
    else:
        value = str(value if value is not None else "")
    value = redact(value, None)
    for secret in secret_values:
        if not isinstance(secret, str) or len(secret) < 8:
            continue
        value = value.replace(secret, "[REDACTED]")
        value = value.replace(
            json.dumps(secret, ensure_ascii=False)[1:-1], "[REDACTED]"
        )
    size = len(value)
    if size > _PREVIEW_LIMIT:
        # Retain the latest conversation entries as well as the beginning.
        value = (
            value[:8000]
            + "\n[…中间省略，详情请查看已授权的原始工具证据…]\n"
            + value[-7500:]
        )
    return {"text": value, "original_chars": size, "truncated": size > _PREVIEW_LIMIT}


def _response_payload(response, secrets):
    output = []
    for item in getattr(response, "output", []) or []:
        kind = getattr(item, "type", "")
        if kind == "function_call":
            output.append(
                {
                    "type": "function_call",
                    "name": getattr(item, "name", ""),
                    "arguments": _preview(getattr(item, "arguments", ""), secrets),
                }
            )
        elif kind == "message":
            # Response text is captured below, not duplicated in output entries.
            output.append({"type": "message"})
        else:
            # Do not persist hidden reasoning or internal model reasoning content.
            output.append({"type": str(kind)[:40]})
    return {
        "text": _preview(getattr(response, "output_text", "") or "", secrets),
        "items": output[:32],
        "status": str(getattr(response, "status", "completed"))[:40],
    }


def _record(task_id, round_number, model, status, duration_ms, usage, payload):
    """A missing/misconfigured trace store must not abort the real diagnosis."""
    from .main import connection
    from .orchestrator.tasks import encode

    try:
        with connection() as db:
            db.execute(
                """INSERT INTO model_interactions(
                    task_id, round_number, model, status, duration_ms,
                    token_input, token_output, token_total, payload
                ) VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    task_id,
                    round_number,
                    str(model)[:120],
                    status,
                    duration_ms,
                    (usage or {}).get("input"),
                    (usage or {}).get("output"),
                    (usage or {}).get("total"),
                    encode(payload),
                ),
            )
    except Exception:
        log.exception("MODEL_INTERACTION_RECORD_FAILED task=%s", task_id)


async def traced_response(
    client,
    *,
    task_id,
    round_number,
    secret_values=(),
    **kwargs,
):
    """Record one logical model request; bounded transient retries are internal."""
    from .ai_reliability import request_response
    from .mcp_runtime import usage_counts

    model = kwargs.get("model", "")
    request = {
        "instructions": _preview(kwargs.get("instructions", ""), secret_values),
        "input": _preview(kwargs.get("input", []), secret_values),
        "tools": [
            str(item.get("name", ""))[:100]
            for item in kwargs.get("tools", []) or []
            if isinstance(item, dict)
        ],
        "tool_choice": kwargs.get("tool_choice", "auto"),
        "max_output_tokens": kwargs.get("max_output_tokens"),
    }
    started = time.monotonic()
    try:
        response = await request_response(client, **kwargs)
    except Exception as exc:
        from .ai_reliability import model_failure_code

        _record(
            task_id,
            round_number,
            model,
            "failed",
            int((time.monotonic() - started) * 1000),
            None,
            {
                "request": request,
                "error": model_failure_code(exc),
                "error_class": type(exc).__name__,
                "note": "仅记录异常类别，不保存上游原始错误或密钥",
            },
        )
        raise
    usage = usage_counts(response)
    _record(
        task_id,
        round_number,
        model,
        "completed",
        int((time.monotonic() - started) * 1000),
        usage,
        {
            "request": request,
            "response": _response_payload(response, secret_values),
            "note": "脱敏、限长预览；工具证据原文另行授权；模型内部推理不公开",
        },
    )
    return response
