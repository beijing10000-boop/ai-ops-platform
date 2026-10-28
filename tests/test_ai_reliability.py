"""Regression tests for model timeouts, retry budgets and safe evidence fallback."""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from openai import APITimeoutError, APIStatusError

from app import ai_reliability
from app.orchestrator import budgets


def test_model_timeout_setting_is_bounded():
    for value in ("15", "90", "180"):
        budgets.validate_settings({"ai_request_timeout_seconds": value})
    for value in ("", "0", "181", "-1", "abc", "90.5"):
        with pytest.raises(Exception):
            budgets.validate_settings({"ai_request_timeout_seconds": value})


def test_transient_model_error_retries_once_without_new_tool_calls():
    error = APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))
    create = AsyncMock(side_effect=[error, "final answer"])
    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    answer = asyncio.run(
        ai_reliability.request_response(
            client, deadline=time.monotonic() + 120,
            timeout_seconds=90, model="fixture", input=[]
        )
    )
    assert answer == "final answer"
    assert create.await_count == 2
    assert all(call.kwargs["timeout"] <= 90 for call in create.call_args_list)


def test_bad_model_request_is_not_retried():
    request = httpx.Request("POST", "https://example.invalid")
    error = APIStatusError(
        "bad request", response=httpx.Response(400, request=request), body={}
    )
    create = AsyncMock(side_effect=error)
    with pytest.raises(APIStatusError):
        asyncio.run(
            ai_reliability.request_response(
                SimpleNamespace(responses=SimpleNamespace(create=create)),
                deadline=time.monotonic() + 120, timeout_seconds=90
            )
        )
    assert create.await_count == 1


def test_evidence_fallback_states_no_unproven_root_cause(monkeypatch):
    from app.orchestrator import tasks

    monkeypatch.setattr(
        tasks, "evidence_page", lambda *args, **kwargs: [
            {
                "status": "success", "provider": "zabbix_mcp",
                "tool": "history_get", "payload": {"records": [{"value": "75"}]}
            },
            {
                "status": "failed", "provider": "zabbix_mcp",
                "tool": "problem_get", "payload": {"error": "invalid sort"}
            },
        ]
    )
    text, useful = ai_reliability.evidence_fallback("any-task", "AI 模型请求超时")
    assert useful
    assert "history_get" in text and "1 条记录" in text
    assert "根因已经确认" not in text and "problem_get" not in text
    assert ai_reliability.model_failure_code(
        APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))
    ) == "ModelTimeout"
