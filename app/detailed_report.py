"""Authorized full-detail Markdown export for a diagnostic task.

Do not pass this export through the public report API: original tool evidence and
model exchange previews require logs.read and are scrubbed again at export time.
"""

import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .security.redact import redact, redact_data

SHANGHAI = ZoneInfo("Asia/Shanghai")
SECRET_SETTING_KEYS = (
    "openai_api_key",
    "mcp_token",
    "ssh_mcp_token",
    "lark_app_secret",
    "zabbix_webhook_secret",
)


def _scrub(value, secrets):
    """Preserve the original record structure except credentials and key material."""
    value = redact_data(value)
    if isinstance(value, dict):
        return {key: _scrub(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub(item, secrets) for item in value]
    if isinstance(value, str):
        value = redact(value, None)
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value
    return value


def _beijing(value):
    if not value:
        return "未记录"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(SHANGHAI).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(value)


def _json_block(value):
    """Four-space indented Markdown is safe even if a log contains code fences."""
    data = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return "\n".join("    " + line for line in data.splitlines())


def build_detailed_report(task_id, *, task=None):
    """Export *all stored* task, evidence and model records, not page-limited UI views."""
    from .main import connection, read_setting
    from .orchestrator import tasks
    from .orchestrator.tasks import decode
    from .mcp_runtime import readable_report_answer

    task = task or tasks.get(task_id, private=True)
    if task is None:
        raise ValueError("任务不存在")
    if "request" not in task:
        task = tasks.get(task_id, private=True)

    secrets = tuple(
        value
        for key in SECRET_SETTING_KEYS
        if isinstance(value := read_setting(key), str) and len(value) >= 8
    )
    with connection() as db:
        evidence = [
            dict(
                zip(
                    (
                        "id",
                        "task_id",
                        "trace_id",
                        "provider",
                        "tool",
                        "status",
                        "collected_at",
                        "duration_ms",
                        "payload",
                    ),
                    row,
                )
            )
            for row in db.execute(
                "SELECT id,task_id,trace_id,provider,tool,status,"
                "collected_at,duration_ms,payload "
                "FROM diagnostic_evidence WHERE task_id=? ORDER BY id",
                (task_id,),
            ).fetchall()
        ]
        interactions = [
            dict(
                zip(
                    (
                        "id",
                        "round_number",
                        "model",
                        "status",
                        "created_at",
                        "duration_ms",
                        "token_input",
                        "token_output",
                        "token_total",
                        "payload",
                    ),
                    row,
                )
            )
            for row in db.execute(
                "SELECT id,round_number,model,status,created_at,duration_ms,"
                "token_input,token_output,token_total,payload "
                "FROM model_interactions WHERE task_id=? ORDER BY id",
                (task_id,),
            ).fetchall()
        ]
        for row in evidence:
            row["payload"] = decode(row["payload"])
        # Rounds reference shared system instructions; print each text once.
        instructions = {}
        for row in interactions:
            row["payload"] = decode(row["payload"])
            shared = ((row["payload"] or {}).get("request") or {}).get("instructions")
            if isinstance(shared, dict) and shared.get("blob") not in (
                None,
                *instructions,
            ):
                instructions[shared["blob"]] = tasks.load_blob(db, shared["blob"])

    task = _scrub(task, secrets)
    evidence = _scrub(evidence, secrets)
    interactions = _scrub(interactions, secrets)
    instructions = _scrub(instructions, secrets)

    report = task.get("report") or {}
    request = task.get("request") or {}
    event = request.get("event") or {}
    skills = request.get("skills") or []
    budget = report.get("budget") or {
        "limits": request.get("limits") or {},
        "used": {"calls": task.get("tools")},
    }
    target = report.get("target") or {}
    answer = readable_report_answer(report.get("answer") or report.get("message") or "")
    if not answer:
        answer = "此任务未生成可显示的 AI 诊断结论。"

    parts = [
        "# AI 运维详细诊断报告",
        "",
        "> 包含任务中已保存的全部诊断数据；模型交互仅为系统已记录的脱敏限长预览，"
        "模型隐藏推理、未采集或历史上未保存的内容无法补全。",
        "> 导出内容仍会进行凭据脱敏；请按内部运维资料保密管理。",
        "",
        "## 1. 任务总览",
        "",
        f"- 任务 ID：{task.get('task_id', '')}",
        f"- Trace ID：{task.get('trace_id', '')}",
        f"- 任务来源：{task.get('source') or '未记录'}",
        f"- 任务类型：{task.get('diagnostic_type') or '未记录'}",
        f"- 分析模式：{task.get('profile') or '未记录'}",
        f"- 状态：{task.get('status') or '未记录'}",
        f"- 错误类型：{task.get('error_type') or '无'}",
        f"- 任务创建（北京时间）：{_beijing(task.get('created_at'))}",
        f"- 开始执行（北京时间）：{_beijing(task.get('started_at'))}",
        f"- 执行结束（北京时间）：{_beijing(task.get('completed_at'))}",
        f"- 执行耗时：{task['duration_ms'] / 1000:.2f} 秒"
        if isinstance(task.get("duration_ms"), (int, float))
        else "- 执行耗时：未记录",
        f"- Token 输入：{task.get('token_input') if task.get('token_input') is not None else '未返回'}",
        f"- Token 输出：{task.get('token_output') if task.get('token_output') is not None else '未返回'}",
        f"- Token 合计：{task.get('token_total') if task.get('token_total') is not None else '未返回'}",
        f"- MCP 执行次数：{task.get('tools')}",
        f"- 已保存证据记录：{len(evidence)}",
        f"- 已保存模型交互记录：{len(interactions)}",
        "",
        "## 2. 告警、主机与诊断目标",
        "",
        _json_block({"event": event, "target": target}),
        "",
        "## 3. AI 诊断结论与处理建议",
        "",
        answer,
        "",
        "## 4. 诊断不足和预算",
        "",
        _json_block(
            {
                "limitations": report.get("limitations") or [],
                "budget": budget,
            }
        ),
        "",
        "## 5. 本次加载的 Skill",
        "",
    ]
    if skills:
        for index, skill in enumerate(skills, start=1):
            # `instructions` is the SKILL.md body already present under `files`.
            shown = (
                {k: v for k, v in skill.items() if k != "instructions"}
                if isinstance(skill, dict) and "SKILL.md" in (skill.get("files") or {})
                else skill
            )
            parts.extend(
                [
                    f"### Skill {index}",
                    "",
                    _json_block(shown),
                    "",
                ]
            )
    else:
        parts.extend(["本任务未保存 Skill 快照，可能使用兼容诊断流程。", ""])
    snapshot = {
        **task,
        "request": {
            **request,
            "skills": [
                {
                    key: skill.get(key)
                    for key in ("name", "revision", "digest")
                    if isinstance(skill, dict)
                }
                | {"note": "完整内容见第 5 节"}
                for skill in skills
            ],
        },
    }

    parts.extend(
        [
            "## 6. 原始任务元数据和请求快照",
            "",
            _json_block(snapshot),
            "",
            "## 7. 诊断时间线",
            "",
            f"- {_beijing(task.get('created_at'))} · 创建任务",
        ]
    )
    if task.get("started_at"):
        parts.append(f"- {_beijing(task['started_at'])} · 开始分析")
    for item in evidence:
        parts.append(
            f"- {_beijing(item['collected_at'])} · MCP {item['provider']}/"
            f"{item['tool']} · {item['status']} · {item['duration_ms']} ms"
        )
    for item in interactions:
        parts.append(
            f"- {_beijing(item['created_at'])} · 模型第 {item['round_number']} 轮 · "
            f"{item['model']} · {item['status']} · {item['duration_ms']} ms"
        )
    if task.get("completed_at"):
        parts.append(f"- {_beijing(task['completed_at'])} · 任务结束")

    parts.extend(["", "## 8. 逐轮与大模型交互记录", ""])
    if not interactions:
        parts.extend(
            [
                "未保存交互记录。v0.9.6 以前的任务不会补录，本任务未发起模型请求，"
                "或交互明细已按保留天数清理。",
                "",
            ]
        )
    for number, (digest, text) in enumerate(instructions.items(), start=1):
        parts.extend(
            [
                f"### 系统指令 {number}（各轮引用 blob {digest[:12]}，只列一次）",
                "",
                _json_block({"blob": digest, "text": text}),
                "",
            ]
        )
    for item in interactions:
        parts.extend(
            [
                f"### 第 {item['round_number']} 轮 · {item['model']} · {item['status']}",
                "",
                f"调用时间（北京时间）：{_beijing(item['created_at'])}；"
                f"耗时：{item['duration_ms']} ms；"
                f"Token：输入 {item['token_input']} / 输出 {item['token_output']} / 合计 {item['token_total']}",
                "",
                _json_block(item),
                "",
            ]
        )
    parts.extend(["## 9. MCP 工具执行记录和完整已保存证据", ""])
    if not evidence:
        parts.extend(
            [
                "证据明细已按保留天数清理；任务结论与统计仍保留。"
                if task.get("tools")
                else "未采集到 MCP 证据。",
                "",
            ]
        )
    for item in evidence:
        parts.extend(
            [
                f"### {item['provider']} / {item['tool']}（记录 {item['id']}）",
                "",
                f"时间（北京时间）：{_beijing(item['collected_at'])}；"
                f"状态：{item['status']}；耗时：{item['duration_ms']} ms",
                "",
                _json_block(item),
                "",
            ]
        )
    parts.extend(
        [
            "## 10. 数据完整性说明",
            "",
            "- 本文件包括数据库中当前任务已保存的所有 MCP 证据记录，不受网页分页条数限制。",
            "- 模型交互保留的是 v0.9.6 起系统已存的脱敏限长预览；早期任务无记录，"
            "标记为 truncated 的输入或响应无法恢复省略部分。",
            "- 来自 MCP 的原始采集结果如在采集时已经按预算截断，导出无法还原不存在的数据。",
            "- 已去除已知 API Key、访问令牌及敏感字段；导出仍可能包含运维系统日志、"
            "主机信息和内部业务数据，请妥善保存。",
            "",
        ]
    )
    return "\n".join(parts)
