"""Joint: the platform's SkillMCP bridge against the real log MCP service."""

import asyncio
import time

import joint_providers as jp
import pytest

from app.integrations import log_mcp, ssh_mcp
from app.skill_mcp import SkillMCP

# Words in the Skills that start with log_ but name a field or a setting.
NOT_TOOLS = {"log_target", "log_mcp", "log_mcp_url", "log_mcp_token"}


def bridge(env, token):
    values = {"log_mcp_url": env.provider.mcp_url, "log_mcp_token": token}
    return SkillMCP(
        lambda key: values.get(key, ""), ["logs"], deadline=time.monotonic() + 120
    )


def test_catalog_is_read_only_and_follows_the_token_grant(log_env):
    async def run():
        async with bridge(log_env, log_env.full["token"]) as full:
            offered = set(await full.catalog("logs"))
            assert full.unauthorized_log_tools() == []
        async with bridge(log_env, log_env.overview_only["token"]) as narrow:
            narrowed = set(await narrow.catalog("logs"))
            hidden = set(narrow.unauthorized_log_tools())
        return offered, narrowed, hidden

    offered, narrowed, hidden = asyncio.run(run())
    # Every grantable tool passed the platform's read-only filter.
    assert set(log_env.grantable) <= offered
    assert narrowed == set(log_mcp.META) | {"log_overview"}
    assert hidden == set(log_env.grantable) - {"log_overview"}


def test_every_log_tool_the_managed_skills_name_exists(log_env):
    async def run():
        async with bridge(log_env, log_env.full["token"]) as full:
            return set(await full.catalog("logs"))

    offered = asyncio.run(run())
    used = jp.skill_tools("log_", NOT_TOOLS)
    missing = {
        name: sorted(files) for name, files in used.items() if name not in offered
    }
    assert not missing, f"Skill 引用了日志 MCP 不提供的工具：{missing}"


def test_a_down_log_store_is_a_failure_never_an_empty_result(log_env):
    if log_env.store:
        pytest.skip("配置了真实 ClickHouse")

    async def run():
        async with bridge(log_env, log_env.full["token"]) as full:
            overview = await full.call(
                "logs", "log_overview", {"target": "10.20.30.40", "minutes": 30}
            )
            search = await full.call(
                "logs", "log_search", {"target": "10.20.30.40", "limit": 5}
            )
            return overview, search

    for result in asyncio.run(run()):
        assert result["is_error"] and result["status"] == "failed", result
        assert result["data"]["error_code"] == "query_failed", result


def test_rejected_token_fails_the_connection_with_a_reason(log_env):
    async def run():
        async with bridge(log_env, "logmcp_" + "x" * 32) as rejected:
            await rejected.catalog("logs")

    with pytest.raises(ssh_mcp.IntegrationError) as caught:
        asyncio.run(run())
    assert "401" in str(caught.value) and "重新签发" in str(caught.value)
