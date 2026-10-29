"""The model only sees SSH diagnostics the platform's token may actually run."""

import asyncio
from contextlib import asynccontextmanager
import time
from types import SimpleNamespace

import pytest
from mcp.types import Tool, ToolAnnotations

from app.integrations import ssh_mcp
from app.skill_mcp import SkillMCP, authorized_ssh_tools

CONFIG = {
    "ssh_mcp_enabled": "true",
    "ssh_mcp_url": "http://ssh.invalid/mcp",
    "ssh_mcp_token": "never-expose-token",
}


def tool(name):
    return Tool(
        name=name,
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    )


class Session:
    def __init__(self, catalog):
        self.catalog = catalog

    async def list_tools(self):
        names = (
            "ssh_resolve_target",
            "ssh_list_tool_catalog",
            "ssh_diagnose_cpu",
            "ssh_diagnose_pressure",
            "ssh_diagnose_mounts",
        )
        return SimpleNamespace(tools=[tool(n) for n in names], nextCursor=None)

    async def call_tool(self, name, args):
        assert name == "ssh_list_tool_catalog"
        if isinstance(self.catalog, Exception):
            raise self.catalog
        # FastMCP wraps list results in structuredContent.result.
        return SimpleNamespace(
            structuredContent={"result": self.catalog}, content=[], isError=False
        )


def visible(monkeypatch, catalog):
    session = Session(catalog)

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield SimpleNamespace(session=session)

    monkeypatch.setattr(ssh_mcp, "configured", connect)

    async def run():
        async with SkillMCP(
            lambda key: CONFIG.get(key, ""),
            ["ssh_mcp"],
            deadline=time.monotonic() + 20,
        ) as bridge:
            return set(await bridge.catalog("ssh_mcp"))

    return asyncio.run(run())


def test_catalog_entries_map_to_tool_names_with_or_without_tool_field():
    assert authorized_ssh_tools(
        [
            {"id": "cpu", "tool": "ssh_diagnose_cpu"},
            {"id": "mount_health"},  # SSH MCP before v0.5.0
            {"id": "log_errors"},
            {"id": "pressure"},
            "not-an-entry",
        ]
    ) == {
        "ssh_diagnose_cpu",
        "ssh_diagnose_mounts",
        "ssh_diagnose_system_errors",
        "ssh_diagnose_pressure",
    }


def test_unauthorized_diagnostics_are_hidden_but_resolvers_stay(monkeypatch):
    assert visible(monkeypatch, [{"id": "cpu", "tool": "ssh_diagnose_cpu"}]) == {
        "ssh_resolve_target",
        "ssh_list_tool_catalog",
        "ssh_diagnose_cpu",
    }
    # Older servers return only action ids.
    assert "ssh_diagnose_mounts" in visible(monkeypatch, [{"id": "mount_health"}])


@pytest.mark.parametrize("catalog", [RuntimeError("down"), []])
def test_catalog_failure_keeps_the_full_list(monkeypatch, catalog):
    # The SSH server still refuses unauthorized calls; we only lose the hint.
    assert "ssh_diagnose_pressure" in visible(monkeypatch, catalog)
