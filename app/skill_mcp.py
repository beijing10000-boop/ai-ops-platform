"""Lazy, read-only MCP transport for Skills; no diagnostic query order lives here."""

import asyncio
from contextlib import AsyncExitStack
import json
import time

from .integrations import ssh_mcp, zabbix

SSH_META = {
    "ssh_list_hosts",
    "ssh_list_groups",
    "ssh_list_tool_catalog",
    "ssh_resolve_host",
    "ssh_resolve_target",
}
# SSH MCP action ids whose tool name is not ssh_diagnose_<id> (servers before
# v0.5.0 do not return the `tool` field in ssh_list_tool_catalog).
ACTION_TOOLS = {
    "connection": "ssh_test_connection",
    "triage": "ssh_triage",
    "directory": "ssh_diagnose_directory_usage",
    "mount_health": "ssh_diagnose_mounts",
    "log_errors": "ssh_diagnose_system_errors",
}


def authorized_ssh_tools(entries):
    """Tool names this client token may run, from ssh_list_tool_catalog."""
    names = set()
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            tool = entry.get("tool")
            names.add(
                tool
                if isinstance(tool, str)
                else ACTION_TOOLS.get(entry["id"], "ssh_diagnose_" + entry["id"])
            )
    return names


def ssh_allowed(tool):
    annotations = getattr(tool, "annotations", None)
    return bool(
        annotations
        and annotations.readOnlyHint is True
        and annotations.destructiveHint is False
        and (
            tool.name in SSH_META | {"ssh_test_connection", "ssh_triage"}
            or tool.name.startswith("ssh_diagnose_")
        )
        and not set(tool.inputSchema.get("properties", {}))
        & {"command", "commands", "script", "shell", "url", "address"}
        - ({"address"} if tool.name == "ssh_resolve_target" else set())
    )


def payload(response):
    data = getattr(response, "structuredContent", None)
    if data is None:
        texts = [part.text for part in response.content if part.type == "text"]
        if len(texts) != 1 or len(texts[0]) > 1_000_000:
            raise ValueError("SSH MCP 返回格式或长度无效")
        try:
            data = json.loads(texts[0])
        except ValueError:
            raise ValueError("SSH MCP 返回非 JSON 内容") from None
    # FastMCP wraps list return values in structuredContent.result.
    if isinstance(data, dict) and set(data) == {"result"}:
        data = data["result"]
    if not isinstance(data, (dict, list)) or len(json.dumps(data)) > 1_000_000:
        raise ValueError("SSH MCP 返回格式或长度无效")
    return data


class SkillMCP:
    def __init__(self, read_setting, providers, *, deadline, target=None):
        self.read_setting = read_setting
        self.providers = set(providers)
        self.deadline = deadline
        self.target = target
        self.stack = AsyncExitStack()
        self.sessions, self.tools, self.bindings = {}, {}, {}
        self.item_scope = set()
        self.monitoring_hostids = set()
        self.target_metadata = {}
        self.configuration = {p: self.config(p) for p in self.providers}

    def config(self, provider):
        keys = (
            ("ssh_mcp_enabled", "ssh_mcp_url", "ssh_mcp_token")
            if provider == "ssh_mcp"
            else ("mcp_url", "mcp_token")
        )
        return tuple(self.read_setting(key) for key in keys)

    def check(self, provider):
        if provider not in self.providers:
            raise ValueError("该 Skill 未获准使用此 MCP 服务")
        if self.config(provider) != self.configuration[provider]:
            raise ValueError("MCP 配置已变更，请创建新任务")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("任务达到时间预算")

    async def __aenter__(self):
        await self.stack.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.stack.__aexit__(*args)

    async def catalog(self, provider):
        self.check(provider)
        if provider not in self.sessions:
            async with asyncio.timeout(
                min(20, max(0.1, self.deadline - time.monotonic()))
            ):
                if provider == "ssh_mcp":
                    adapter = await self.stack.enter_async_context(
                        ssh_mcp.configured(self.read_setting)
                    )
                    session = adapter.session
                else:
                    session = await self.stack.enter_async_context(
                        zabbix.connect(self.read_setting)
                    )
                self.sessions[provider] = session
                tools, cursor, seen = {}, None, set()
                for _ in range(20):
                    result = (
                        await session.list_tools(cursor=cursor)
                        if cursor
                        else await session.list_tools()
                    )
                    for tool in result.tools:
                        if (
                            ssh_allowed(tool)
                            if provider == "ssh_mcp"
                            else tool.name in zabbix.enabled_names(self.read_setting)
                        ):
                            tools[tool.name] = tool
                    cursor = getattr(result, "nextCursor", None)
                    if not cursor:
                        break
                    if cursor in seen:
                        raise ValueError("MCP 工具分页重复")
                    seen.add(cursor)
                else:
                    raise ValueError("MCP 工具分页超过限制")
                if provider == "ssh_mcp" and "ssh_list_tool_catalog" in tools:
                    tools = await self.authorized(session, tools)
                self.tools[provider] = tools
        if provider not in self.tools:
            raise ValueError("MCP 工具发现失败，请创建新任务重试")
        return self.tools[provider]

    async def authorized(self, session, tools):
        """Hide diagnostics this token may not run, so the model never plans them.

        A visible-but-forbidden tool only fails at call time and marks the task
        partial; resolve/list tools stay. On any catalog error keep the full list
        (the server still refuses unauthorized calls).
        """
        try:
            response = await session.call_tool("ssh_list_tool_catalog", {})
            allowed = (
                None if response.isError else authorized_ssh_tools(payload(response))
            )
        except Exception:
            allowed = None
        if not allowed:
            return tools
        return {
            name: tool
            for name, tool in tools.items()
            if name in SSH_META or name in allowed
        }

    async def definitions(self, provider, query=""):
        if not isinstance(query, str):
            raise ValueError("工具查询须为字符串")
        tools = await self.catalog(provider)
        if not query:
            return [{"name": tool.name} for tool in tools.values()]
        if query in tools:
            tools = {query: tools[query]}
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "parameters": zabbix.input_schema(t.name)
                if provider == "zabbix_mcp"
                else t.inputSchema,
            }
            for t in tools.values()
            if not query
            or query.casefold() in (t.name + " " + (t.description or "")).casefold()
        ]

    def bind(self, name, args, data):
        if name not in {"ssh_list_hosts", "ssh_resolve_host", "ssh_resolve_target"}:
            return
        rows = (
            data
            if isinstance(data, list)
            else [data]
            if data.get("status") == "success"
            else []
        )
        matching = []
        for row in rows:
            ident = row.get("host_id", row.get("id"))
            revision = row.get("revision")
            if (
                type(ident) is not int
                or ident < 1
                or type(revision) is not int
                or revision < 1
            ):
                continue
            if name == "ssh_resolve_target" and row.get("address") != args.get(
                "address"
            ):
                continue
            if name == "ssh_resolve_host" and row.get("zabbix_hostid") != args.get(
                "zabbix_hostid"
            ):
                continue
            if self.target:
                kind, value = self.target
                if (
                    str(
                        row.get("address")
                        if kind == "ip"
                        else row.get("zabbix_hostid", "")
                    )
                    != value
                ):
                    continue
            matching.append((ident, row))
        # A single explicit target must not resolve to multiple SSH assets.
        if self.target and len(matching) > 1:
            raise ValueError("SSH MCP 返回重复目标，未建立绑定")
        for ident, row in matching:
            self.bindings[ident] = row

    def observe_monitoring_target(self, name, args, records):
        """Record returned identity for the report without issuing any extra queries."""
        if name == "hostinterface_get" and self.target and self.target[0] == "ip":
            ids = {
                str(row.get("hostid", ""))
                for row in records
                if row.get("ip") == self.target[1]
                and str(row.get("hostid", "")).isdigit()
            }
            self.monitoring_hostids = ids if len(ids) == 1 else set()
            return
        if name != "host_get" or len(records) != 1:
            return
        expected = (
            {self.target[1]}
            if self.target and self.target[0] == "hostid"
            else self.monitoring_hostids
            if self.target
            else {str(value) for value in args.get("hostids", [])}
        )
        row = records[0]
        host_id = str(row.get("hostid", ""))
        if len(expected) != 1 or host_id not in expected or not host_id.isdigit():
            return
        if self.target_metadata.get("host_id") not in (None, "", host_id):
            return
        device_type = zabbix.infer_device(row)
        self.target_metadata = {
            **self.target_metadata,
            "host_id": host_id,
            "host_name": row.get("name")
            or row.get("host")
            or self.target_metadata.get("host_name")
            or host_id,
            "device_type": self.target_metadata.get("device_type", device_type)
            if self.target_metadata.get("ssh_host_id") or device_type == "unknown"
            else device_type,
        }

    async def call(self, provider, name, arguments):
        self.check(provider)
        tools = await self.catalog(provider)
        if (
            name not in tools
            or provider == "zabbix_mcp"
            and name not in zabbix.enabled_names(self.read_setting)
        ):
            raise ValueError("工具不在当前授权的只读目录中；请检查服务版本与工具授权")
        if not isinstance(arguments, dict) or len(json.dumps(arguments)) > 12000:
            raise ValueError("工具参数无效")
        args = dict(arguments)
        session, tool = self.sessions[provider], tools[name]
        async with asyncio.timeout(max(0.1, self.deadline - time.monotonic())):
            if provider == "zabbix_mcp":
                if name in {"history_get", "trend_get"} and (
                    not args.get("itemids")
                    or any(str(x) not in self.item_scope for x in args["itemids"])
                ):
                    raise ValueError("历史查询须先通过 item_get 核验监控项 ID")
                response = await zabbix.call(
                    session,
                    name,
                    args,
                    schema=tool.inputSchema,
                    host_id=self.target[1]
                    if self.target and self.target[0] == "hostid"
                    else None,
                )
                result = zabbix.safe_result(response, 100000)
                if not result["is_error"]:
                    self.observe_monitoring_target(name, args, result["records"])
                if not result["is_error"] and name == "item_get":
                    self.item_scope.update(
                        str(r["itemid"])
                        for r in result["records"]
                        if str(r.get("itemid", "")).isdigit()
                    )
                return result
            if name not in SSH_META:
                ident = args.get("host_id")
                binding = self.bindings.get(ident) if type(ident) is int else None
                if not binding:
                    raise ValueError(
                        "先从 SSH MCP 精确解析授权资产及 revision；当前目标未核验（旧版 SSH 服务请升级）"
                    )
                if (
                    args.get("expected_revision", binding["revision"])
                    != binding["revision"]
                ):
                    raise ValueError("SSH 资产 revision 不匹配")
                args["expected_revision"] = binding["revision"]
                self.target_metadata = {
                    "ssh_host_id": ident,
                    "address": binding.get("address"),
                    "host_name": binding.get("name"),
                    "host_id": binding.get("zabbix_hostid"),
                    "device_type": "linux",
                }
            if set(args) - set(tool.inputSchema.get("properties", {})):
                raise ValueError("SSH 工具参数不在实际 Schema 中")
            zabbix.validate_remote_schema(name, args, tool.inputSchema)
            response = await asyncio.wait_for(
                session.call_tool(name, args),
                timeout=min(
                    120, int(self.read_setting("ssh_mcp_timeout_seconds") or 90)
                ),
            )
            if response.isError:
                return {
                    "error": "SSH MCP 拒绝调用："
                    + "\n".join(
                        str(getattr(part, "text", "")) for part in response.content
                    )[:2000],
                    "is_error": True,
                }
            data = payload(response)
            if name not in SSH_META and (
                not isinstance(data, dict) or data.get("host_id") != args["host_id"]
            ):
                raise ValueError("SSH MCP 返回的主机与任务绑定不匹配")
            failed = (
                bool(response.isError)
                or isinstance(data, dict)
                and data.get("status") in {"failed", "cancelled"}
            )
            if not failed:
                self.bind(name, args, data)
            return {
                "is_error": failed,
                "data": data,
                **(
                    {"error": str(data.get("error") or "SSH MCP 返回失败")}
                    if failed and isinstance(data, dict)
                    else {}
                ),
                "status": "failed"
                if failed
                else data.get("status", "success")
                if isinstance(data, dict)
                else "success",
            }
