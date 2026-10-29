"""Diagnostic entry point for alerts, Web and Feishu Q&A.

Every task runs through the Skill runtime (skill_runtime.run). The platform keeps
a managed base Skill enabled, so a scope only has no Skill when an administrator
disabled all of them; such tasks fail explicitly instead of using a fixed flow.
"""

import json

from .main import read_setting
from .diagnostics.playbooks import classify
from .diagnostics.targets import directory_request
from .orchestrator import tasks

NO_SKILL = (
    "本场景没有启用的诊断 Skill（平台基础 Skill 也已停用），请在 Skill 管理中启用后重试"
)


def compact_result(value, max_chars):
    text = str(value)
    if len(text) <= max_chars:
        return text
    head = int(max_chars * 0.75)
    return text[:head] + "\n...[truncated]...\n" + text[-(max_chars - head) :]


def usage_counts(response):
    usage = getattr(response, "usage", None)
    if usage is None:
        return None

    def field(source, name):
        return (
            source.get(name)
            if isinstance(source, dict)
            else getattr(source, name, None)
        )

    def count(name, source=usage):
        value = field(source, name)
        return value if type(value) is int and value >= 0 else None

    return {
        "input": count("input_tokens"),
        "output": count("output_tokens"),
        "total": count("total_tokens"),
        # Prompt-cache hits are part of `input`; None when the gateway omits it.
        "cached": count("cached_tokens", field(usage, "input_tokens_details")),
    }


def incomplete_output_reason(response):
    if getattr(response, "status", None) != "incomplete":
        return None
    details = getattr(response, "incomplete_details", None)
    reason = (
        details.get("reason")
        if isinstance(details, dict)
        else getattr(details, "reason", None)
    )
    return {
        "max_output_tokens": "模型输出达到单次 Token 上限，报告未完整生成；已保留返回内容，请缩小问题范围或调整模型输出限制",
        "content_filter": "模型服务限制了本轮输出，报告未完整生成；已保留返回内容",
    }.get(reason, "模型未完整返回本轮输出；已保留返回内容，不能视为完整报告")


def numbered(value):
    """Structured outputs give suggestions as a list; cards and reports show text."""
    if not isinstance(value, list):
        return value
    items = [str(item).strip() for item in value if str(item or "").strip()]
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, 1))


def readable_report_answer(raw):
    """Format JSON model output for the Web report without changing card payload.

    Worker callers still receive the original JSON text for Feishu card fields.
    All generated strings remain escaped by the browser renderer.
    """
    from .report_presentation import human_metrics

    text = str(raw or "").strip()
    if text.startswith("```"):
        import re

        text = re.sub(r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$", "", text).strip()
    try:
        result = json.loads(text)
    except (TypeError, ValueError):
        return human_metrics(raw)
    if not isinstance(result, dict) or not any(
        isinstance(result.get(key), (str, list))
        for key in ("cause", "action", "analysis")
    ):
        return human_metrics(raw)
    parts = []
    for name, key in (
        ("诊断结论", "cause"),
        ("处理建议", "action"),
        ("分析与依据", "analysis"),
    ):
        content = numbered(result.get(key))
        if isinstance(content, str) and content.strip():
            parts.append(name + "\n" + human_metrics(content.strip()))
    return "\n\n".join(parts) if parts else human_metrics(raw)


def format_usage(usage, *, duration_ms=None, timing=None):
    profile_labels = {"quick": "快速分析", "standard": "标准分析", "deep": "深度分析"}
    profile = (usage or {}).get("profile")
    suffix = (
        (" · 分析模式：" + profile_labels[profile]) if profile in profile_labels else ""
    )
    duration = ""
    if type(duration_ms) in (float, int) and duration_ms >= 0:
        duration = f" · 执行耗时：{duration_ms / 1000:.1f} 秒"
        if isinstance(timing, dict) and isinstance(timing.get("rounds"), list):
            # Where the time went, so a slow model round is visible at a glance.
            duration += (
                f"（预采集 {timing.get('prefetch', 0)} 秒 · "
                f"模型 {len(timing['rounds'])} 轮 {timing.get('model', 0)} 秒 · "
                f"工具 {timing.get('tools', 0)} 秒）"
            )
    if not usage or usage.get("available") is not True:
        return "本轮 Token 消耗：模型未返回用量" + suffix + duration
    cached = usage.get("cached")
    hit = f"，其中缓存命中 {cached:,}" if type(cached) is int and cached > 0 else ""
    return "本轮 Token 消耗：{:,}（输入 {:,}{} / 输出 {:,}）{}{}".format(
        usage["total"], usage["input"], hit, usage["output"], suffix, duration
    )


def create_task(question, event=None, profile_name=None, actor="system"):
    """Create the queued task run() would create, so a queue can hold it first."""
    event = event or {}
    try:
        directory = directory_request(question)
    except ValueError:
        directory = None
    return tasks.create(
        {"event": event, "question": question[:4000]},
        source="alert" if event else "qa",
        actor=actor,
        event_id=str(event["event_id"]) if event.get("event_id") else None,
        diagnostic_type="disk"
        if directory
        else classify(event.get("event_name") or question),
        profile=profile_name or read_setting("ai_analysis_profile") or "standard",
    )


async def run(
    prompt,
    question,
    *,
    client=None,
    model=None,
    context="",
    return_usage=False,
    task_id=None,
    event=None,
    profile_name=None,
):
    # Accept structured alert metadata only from the trusted caller, never from question text.
    event = event or {}
    key = read_setting("openai_api_key")
    model = model or read_setting("openai_model")
    base = read_setting("openai_base_url")
    if not model or (client is None and not (key and base)):
        raise RuntimeError("AI 模型未配置")
    if task_id:
        task = tasks.get(task_id, private=True)
        if not task:
            raise ValueError("任务不存在")
    else:
        task, created = create_task(question, event, profile_name)
        if not created:
            raise tasks.AlreadyRunning("此事件已有分析任务，请查看现有任务")
        task = tasks.get(task["task_id"], private=True)
    task_id = task["task_id"]
    tasks.start(task_id)
    if not task["request"].get("skills"):
        tasks.finish(
            task_id,
            {"answer": NO_SKILL, "limitations": [NO_SKILL]},
            status="failed",
            error_type="NoSkillEnabled",
        )
        usage = {
            "input": 0,
            "output": 0,
            "total": 0,
            "available": False,
            "task_id": task_id,
            "trace_id": task["trace_id"],
            "profile": task["profile"],
        }
        return (NO_SKILL, usage) if return_usage else NO_SKILL
    from .skill_runtime import run as run_with_skills

    return await run_with_skills(
        prompt,
        question,
        task=task,
        client=client,
        model=model,
        context=context,
        return_usage=return_usage,
        read_setting=read_setting,
    )
