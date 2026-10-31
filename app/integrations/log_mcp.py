"""Third MCP connection: the log analysis platform's read-only log tools.

URL and token are administrator settings, never model or tool arguments. The
log platform scopes every call by its own token (tools, log types, source
groups); the platform additionally keeps only `log_` tools the server marks
read-only that take no command, SQL, script or URL. Same transport rules as
the SSH MCP connection: no redirects, no environment proxy, TLS verified.
"""

from contextlib import asynccontextmanager
from datetime import timedelta
import asyncio

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .ssh_mcp import IntegrationError, client_factory, validate_endpoint

# One tool call; the log platform bounds its own windows and row counts.
TIMEOUT = 30
TOKEN_PREFIX = "logmcp_"
# Tools every log MCP token may run: catalog, source list, target lookup.
META = frozenset({"log_list_tool_catalog", "log_list_sources", "log_resolve_target"})
# Parameters that would hand the server code to run or an address to fetch.
FORBIDDEN_PARAMS = frozenset(
    {"command", "commands", "sql", "script", "scripts", "shell", "url", "urls"}
)


def configured(read_setting):
    return bool(read_setting("log_mcp_url") and read_setting("log_mcp_token"))


def allowed(tool):
    annotations = getattr(tool, "annotations", None)
    schema = tool.inputSchema if isinstance(tool.inputSchema, dict) else {}
    properties = schema.get("properties")
    names = properties if isinstance(properties, dict) else {}
    return bool(
        tool.name.startswith("log_")
        and annotations
        and annotations.readOnlyHint is True
        and annotations.destructiveHint is not True
        and not {str(name).casefold() for name in names} & FORBIDDEN_PARAMS
    )


def authorized_tools(catalog):
    """Tool names this token may run, from log_list_tool_catalog; None when the
    reply does not say (a failed call or an unexpected shape)."""
    if not isinstance(catalog, dict) or catalog.get("status") == "failed":
        return None
    entries = catalog.get("tools")
    if not isinstance(entries, list):
        return None
    return {
        entry["name"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }


def reason(exc):
    """A bounded failure text for reports and the console; never the token."""
    if isinstance(exc, (ValueError, IntegrationError)):
        return str(exc)[:250]
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return (
                f"日志 MCP 拒绝令牌（HTTP {code}）：令牌无效、已过期或已撤销，"
                "请在日志分析平台「MCP 接入」重新签发"
            )
        return f"日志 MCP 返回 HTTP {code}"
    if isinstance(exc, TimeoutError):
        return "日志 MCP 响应超时"
    if isinstance(exc, httpx.TransportError):
        return "日志 MCP 无法连接：" + type(exc).__name__
    return "日志 MCP 连接失败：" + type(exc).__name__


@asynccontextmanager
async def connect(read_setting, *, timeout=TIMEOUT):
    """Plain HTTP is accepted: the log platform runs on the user's trusted LAN."""
    url, token = read_setting("log_mcp_url"), read_setting("log_mcp_token")
    if not url or not token:
        raise IntegrationError("日志 MCP 未配置：请在连接管理填写地址和令牌")
    validate_endpoint(url, mcp_path=True)
    if not token.isascii() or any(c.isspace() for c in token):
        raise IntegrationError("日志 MCP 令牌配置无效")
    async with streamablehttp_client(
        url,
        headers={"Authorization": "Bearer " + token},
        timeout=timeout,
        sse_read_timeout=timeout,
        httpx_client_factory=client_factory,
    ) as (read, write, _):
        async with ClientSession(
            read, write, read_timeout_seconds=timedelta(seconds=timeout)
        ) as session:
            async with asyncio.timeout(min(timeout, 15)):
                await session.initialize()
            yield session
