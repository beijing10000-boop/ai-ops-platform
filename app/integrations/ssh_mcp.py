"""Second MCP connection for AI Ops Platform; no SSH credentials or arbitrary tools.

Use from the platform's server, keeping this connection separate from Zabbix MCP.
The caller owns the overall task deadline, evidence storage and action budget.
"""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
import asyncio
import json
import re
from urllib.parse import urlsplit

from fastapi import HTTPException

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

SERVICE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")


class IntegrationError(RuntimeError):
    """Safe to surface in an evidence-gap record; never embeds a bearer token."""


@dataclass(frozen=True)
class HostBinding:
    zabbix_hostid: str
    host_id: int
    revision: int


class SSHMCPAdapter:
    """Preflight host-binding checks; Skills run diagnostics via app.skill_mcp."""

    def __init__(self, session: ClientSession, timeout: float = 90):
        self.session = session
        self.timeout = timeout

    async def _call(self, name, arguments):
        try:
            async with asyncio.timeout(self.timeout):
                result = await self.session.call_tool(name, arguments)
        except Exception as exc:
            raise IntegrationError(
                "SSH MCP 调用未完成：" + type(exc).__name__
            ) from None
        if result.isError:
            raise IntegrationError(
                "SSH MCP 拒绝工具调用；请检查专用客户端令牌的动作授权、主机组范围及有效期（工具 "
                + name
                + "）"
            )
        payload = result.structuredContent
        if payload is None:
            texts = [item.text for item in result.content if item.type == "text"]
            if len(texts) != 1 or len(texts[0]) > 1_000_000:
                raise IntegrationError("SSH MCP 返回格式或长度无效")
            try:
                payload = json.loads(texts[0])
            except ValueError:
                raise IntegrationError("SSH MCP 返回非 JSON 内容") from None
        if not isinstance(payload, dict) or len(json.dumps(payload)) > 1_000_000:
            raise IntegrationError("SSH MCP 返回格式或长度无效")
        return payload

    async def resolve(self, zabbix_hostid: str) -> HostBinding:
        if not isinstance(zabbix_hostid, str) or not re.fullmatch(
            r"[0-9]{1,32}", zabbix_hostid
        ):
            raise IntegrationError("必须使用任务绑定的数字 Zabbix Host ID")
        data = await self._call("ssh_resolve_host", {"zabbix_hostid": zabbix_hostid})
        if (
            data.get("status") != "success"
            or data.get("zabbix_hostid") != zabbix_hostid
            or type(data.get("host_id")) is not int
            or data["host_id"] < 1
            or type(data.get("revision")) is not int
            or data["revision"] < 1
        ):
            raise IntegrationError("SSH 主机映射缺失、重复、未就绪或不在授权范围内")
        return HostBinding(zabbix_hostid, data["host_id"], data["revision"])


@asynccontextmanager
async def connect(
    url: str, token: str, *, allow_http: bool = False, timeout: float = 90
):
    """URL/token are administrator configuration, never model/tool arguments.

    HTTP must be explicitly enabled for isolated testing. No redirects, automatic
    retries, environment proxy, or fallback to local SSH. TLS verification stays on.
    """
    validate_endpoint(url, ssh=True)
    if (
        (urlsplit(url).scheme == "http" and not allow_http)
        or not token
        or not token.isascii()
        or any(c.isspace() for c in token)
    ):
        raise IntegrationError("SSH MCP 地址或令牌配置无效")
    if not 1 <= timeout <= 120:
        raise IntegrationError("调用超时必须为 1–120 秒")

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
            yield SSHMCPAdapter(session, timeout)


def validate_endpoint(url, *, ssh=False):
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and not any(c.isspace() for c in url)
            and (parsed.port is None or 1 <= parsed.port <= 65535)
            and (not ssh or parsed.path.rstrip("/") == "/mcp")
        )
    except ValueError:
        valid = False
    if not valid:
        raise IntegrationError(
            "MCP 地址无效：请填写不含用户名、密码、查询参数的 HTTP(S) 地址；SSH MCP 路径为 /mcp"
        )


def validate_settings(values):
    try:
        for key in ("mcp_url", "ssh_mcp_url"):
            if values.get(key):
                validate_endpoint(values[key], ssh=key == "ssh_mcp_url")
        for key in ("mcp_token", "ssh_mcp_token"):
            value = values.get(key, "")
            if (
                value
                and value != "********"
                and (not value.isascii() or any(c.isspace() for c in value))
            ):
                raise IntegrationError("MCP Token 不能包含空白或非 ASCII 字符")
        if "ssh_mcp_enabled" in values and values["ssh_mcp_enabled"] not in {
            "true",
            "false",
        }:
            raise IntegrationError("SSH MCP 开关必须为 true 或 false")
        if (
            "ssh_mcp_timeout_seconds" in values
            and not 1 <= int(values["ssh_mcp_timeout_seconds"]) <= 120
        ):
            raise IntegrationError("SSH MCP 超时必须为 1–120 秒")
    except (ValueError, IntegrationError) as exc:
        raise HTTPException(
            422,
            str(exc)
            if isinstance(exc, IntegrationError)
            else "SSH MCP 超时必须为 1–120 秒",
        ) from None


@asynccontextmanager
async def configured(read_setting, *, timeout=None):
    if read_setting("ssh_mcp_enabled") != "true":
        raise IntegrationError("SSH MCP 未启用")
    seconds = int(read_setting("ssh_mcp_timeout_seconds") or 90)
    if timeout is not None:
        seconds = min(seconds, timeout)
    # Explicit administrator-supplied HTTP is supported for the user's trusted LAN.
    async with connect(
        read_setting("ssh_mcp_url"),
        read_setting("ssh_mcp_token"),
        allow_http=True,
        timeout=seconds,
    ) as adapter:
        yield adapter


def client_factory(headers=None, timeout=None, auth=None):
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=False,
        trust_env=False,
    )
