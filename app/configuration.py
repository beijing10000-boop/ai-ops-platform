"""Local validation of Web settings forms. No credentials are returned by validation."""

import re
from urllib.parse import urlsplit
from fastapi import HTTPException

INTEGER_SETTINGS = {
    "data_retention_days": (
        0,
        3650,
        "诊断明细保留天数须为 0–3650 的整数，0 表示永久保留",
    ),
    "ai_alert_reuse_hours": (0, 72, "复用近期分析的时长须为 0–72 小时，0 表示关闭"),
    "ai_daily_token_limit": (
        0,
        1_000_000_000,
        "自动分析每日 Token 上限须为非负整数，0 表示不限",
    ),
}


def validate_form(values, read):
    def value(key):
        val = values.get(key)
        return read(key) if val is None or val == "********" else val

    if "web_protocol" in values and values["web_protocol"] not in {"http", "https"}:
        raise HTTPException(422, "Web 协议必须为 HTTP 或 HTTPS")
    if "web_public_host" in values and values["web_public_host"]:
        try:
            host = urlsplit("http://" + values["web_public_host"])
            valid = (
                host.hostname
                and not host.username
                and not host.password
                and not host.query
                and not host.fragment
                and host.path in {"", "/"}
                and (host.port is None or 1 <= host.port <= 65535)
                and not any(c.isspace() for c in values["web_public_host"])
            )
        except ValueError:
            valid = False
        if not valid:
            raise HTTPException(422, "Web 外部地址只能填写主机名/IP及可选端口")
    for key in ("openai_base_url", "zabbix_frontend_url"):
        if values.get(key):
            try:
                parts = urlsplit(values[key])
                valid = (
                    parts.scheme in {"http", "https"}
                    and parts.hostname
                    and not parts.username
                    and not parts.password
                    and not parts.query
                    and not parts.fragment
                    and not any(c.isspace() for c in values[key])
                    and (parts.port is None or 1 <= parts.port <= 65535)
                )
            except ValueError:
                valid = False
            if not valid:
                raise HTTPException(
                    422, "服务地址必须为不含账号、密码或查询参数的 HTTP(S) 地址"
                )
    if (
        "lark_app_id" in values
        and values["lark_app_id"]
        and not re.fullmatch(r"cli_[A-Za-z0-9]{8,64}", values["lark_app_id"])
    ):
        raise HTTPException(422, "飞书 App ID 格式错误")
    if (
        "lark_app_secret" in values
        and values["lark_app_secret"] not in {"", "********"}
        and not 8 <= len(values["lark_app_secret"]) <= 512
    ):
        raise HTTPException(422, "飞书 App Secret 长度应为 8–512 字符")
    if "feishu_enabled" in values and values["feishu_enabled"] not in {"true", "false"}:
        raise HTTPException(422, "飞书开关无效")
    if "ai_min_severity" in values and values["ai_min_severity"] not in {
        str(i) for i in range(6)
    }:
        raise HTTPException(422, "告警最低级别必须为 0–5")
    if values.get("ai_quick_severity_max") not in (None, "", "1", "2", "3", "4"):
        raise HTTPException(422, "快速分析的告警级别上限无效")
    if values.get("ai_quick_host_groups"):
        words = [w.strip() for w in values["ai_quick_host_groups"].split(",")]
        if len(words) > 20 or any(not w or len(w) > 64 for w in words):
            raise HTTPException(
                422, "主机组关键字最多 20 个，每个 1–64 字，以英文逗号分隔"
            )
    for key, (low, high, message) in INTEGER_SETTINGS.items():
        raw = values.get(key)
        if raw is not None and not (
            raw.isdecimal() and str(int(raw)) == raw and low <= int(raw) <= high
        ):
            raise HTTPException(422, message)
    for key in ("allowed_chat_ids", "feishu_alert_chat_ids"):
        if key in values:
            ids = [s.strip() for s in values[key].split(",") if s.strip()]
            if len(ids) > 100 or any(
                not re.fullmatch(r"oc_[A-Za-z0-9_-]{2,128}", s) for s in ids
            ):
                raise HTTPException(
                    422, "飞书群 ID 必须以 oc_ 开头，多个以英文逗号分隔"
                )
    if value("ssh_mcp_enabled") == "true" and not all(
        value(k) for k in ("ssh_mcp_url", "ssh_mcp_token")
    ):
        raise HTTPException(422, "启用 SSH MCP 前请填写地址和专用令牌")
    return {
        "ok": True,
        "message": "填写内容校验通过；此检查不会保存配置或发起诊断。连接可用性请使用对应验证连接按钮。",
    }
