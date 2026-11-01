"""Joint: the platform's SkillMCP bridge against the real SSH MCP service."""

import asyncio
import re
import time
from pathlib import Path

import joint_providers as jp
import pytest
from joint_providers import NOT_READY, READY, UNKNOWN, WINDOWS

from app.integrations import ssh_mcp
from app.skill_mcp import SkillMCP

# Words in the Skills that start with ssh_ but name a field or a provider.
NOT_TOOLS = {"ssh_mcp", "ssh_target", "ssh_host_id"}


def settings(env, token):
    values = {
        "ssh_mcp_enabled": "true",
        "ssh_mcp_url": env.provider.mcp_url,
        "ssh_mcp_token": token,
        "ssh_mcp_timeout_seconds": "60",
    }
    return lambda key: values.get(key, "")


def bridge(env, token, target=None):
    return SkillMCP(
        settings(env, token),
        ["ssh_mcp"],
        deadline=time.monotonic() + 180,
        target=target,
    )


def test_catalog_follows_the_token_grant(ssh_env):
    async def run():
        async with bridge(ssh_env, ssh_env.full["token"]) as full:
            tools = await full.catalog("ssh_mcp")
            assert full.unauthorized_tools() == []
            # Everything the server offers the platform passes its read-only filter.
            assert {"ssh_resolve_host", "ssh_collect", "ssh_diagnose_cpu"} <= set(tools)
        async with bridge(ssh_env, ssh_env.limited["token"]) as limited:
            tools = await limited.catalog("ssh_mcp")
            assert "ssh_diagnose_cpu" in tools
            assert "ssh_diagnose_memory" not in tools
            assert "ssh_diagnose_memory" in limited.unauthorized_tools()
            # Lookup tools stay: the platform must still resolve its target.
            assert {"ssh_resolve_host", "ssh_resolve_target"} <= set(tools)

    asyncio.run(run())


def test_every_ssh_tool_the_managed_skills_name_exists_and_is_read_only(ssh_env):
    async def run():
        async with bridge(ssh_env, ssh_env.full["token"]) as full:
            return set(await full.catalog("ssh_mcp"))

    offered = asyncio.run(run())
    used = jp.skill_tools("ssh_", NOT_TOOLS)
    missing = {
        name: sorted(files) for name, files in used.items() if name not in offered
    }
    assert not missing, f"Skill 引用了 SSH MCP 不提供（或非只读）的工具：{missing}"


# Costly or intrusive actions an administrator grants deliberately: the Skills
# mention them as optional steps, the recommended grant leaves them out.
OPT_IN = {"jvm", "triage", "directory", "peer_connections", "peer_traffic"}


def recommended_actions(env):
    """The console's 「按 AI Ops Platform 推荐勾选」 scope: the service's own
    `recommended` flags (v0.9+), else the list older consoles kept in app.js."""
    entries = jp.created(env.provider.admin.get("/tools"))
    if any("recommended" in entry for entry in entries):
        return {entry["id"] for entry in entries if entry.get("recommended")}
    app_js = (Path(env.repo) / "web" / "app.js").read_text(encoding="utf-8")
    block = re.search(r"recommendedClientActions\s*=\s*\[(.*?)\]", app_js, re.DOTALL)
    assert block, "SSH MCP 控制台不再提供推荐授权"
    return set(re.findall(r'"([a-z_]+)"', block.group(1)))


def test_console_recommended_grant_covers_the_managed_skills(ssh_env):
    """「按 AI Ops Platform 推荐勾选」 must grant what the platform's Skills use;
    a tool outside it is silently hidden from every recommended token."""

    async def run():
        async with bridge(ssh_env, ssh_env.full["token"]) as full:
            await full.catalog("ssh_mcp")
            return full

    full = asyncio.run(run())
    recommended = recommended_actions(ssh_env)
    used = {
        name: full.ssh_action(name)
        for name in jp.skill_tools("ssh_", NOT_TOOLS)
        if name.startswith("ssh_diagnose_") or name == "ssh_collect"
    }
    outside = {
        name: action
        for name, action in used.items()
        if action not in recommended | OPT_IN | {"collect"}
    }
    assert not outside, f"平台 Skill 使用但推荐授权未勾选的动作：{outside}"
    assert not recommended & OPT_IN, "推荐授权不应包含需人工决定的高开销动作"


def test_resolution_outcomes_reach_the_platform_classified(ssh_env):
    async def run():
        async with bridge(ssh_env, ssh_env.full["token"]) as full:

            async def resolve(zabbix_hostid):
                return await full.call(
                    "ssh_mcp", "ssh_resolve_host", {"zabbix_hostid": zabbix_hostid}
                )

            ready = await resolve(READY)
            assert ready["status"] == "success", ready
            assert ready["data"]["host_id"] == ssh_env.hosts[READY]
            assert ready["data"]["asset_type"] == "linux"
            assert ssh_env.hosts[READY] in full.bindings
            codes = {}
            for zabbix_hostid in (WINDOWS, NOT_READY, UNKNOWN):
                result = await resolve(zabbix_hostid)
                assert result["is_error"] and result["status"] == "failed", result
                codes[zabbix_hostid] = result["data"].get("error_code")
            # No failed resolution may leave a binding behind.
            assert set(full.bindings) == {ssh_env.hosts[READY]}
            direct = await full.call(
                "ssh_mcp", "ssh_resolve_target", {"address": ssh_env.address}
            )
            assert direct["status"] == "success", direct
            return codes

    codes = asyncio.run(run())
    assert codes == {
        WINDOWS: "not_linux",
        NOT_READY: "not_ready",
        UNKNOWN: "mapping_unresolved",
    }


def test_unreachable_host_is_a_structured_failure_not_an_exception(ssh_env):
    async def run():
        async with bridge(ssh_env, ssh_env.full["token"], ("hostid", READY)) as full:
            await full.call("ssh_mcp", "ssh_resolve_host", {"zabbix_hostid": READY})
            host_id = ssh_env.hosts[READY]
            started = time.monotonic()
            single = await full.call(
                "ssh_mcp", "ssh_diagnose_cpu", {"host_id": host_id}
            )
            bundled = await full.call(
                "ssh_mcp",
                "ssh_collect",
                {"host_id": host_id, "actions": ["cpu", "memory", "processes"]},
            )
            return single, bundled, time.monotonic() - started, full.target_metadata

    single, bundled, took, metadata = asyncio.run(run())
    for result in (single, bundled):
        assert result["is_error"] and result["status"] == "failed", result
        assert result["data"].get("error_code"), result
        assert result["data"].get("job_id"), "失败的执行也要留下可在 SSH MCP 查看的任务"
    # Refused at connect: the platform's budget is not burnt on a dead host.
    assert took < 60
    assert metadata["ssh_host_id"] == single["data"]["host_id"]


def test_forbidden_tools_are_hidden_and_refused_by_the_server(ssh_env):
    async def run():
        async with bridge(ssh_env, ssh_env.limited["token"]) as limited:
            await limited.call("ssh_mcp", "ssh_resolve_host", {"zabbix_hostid": READY})
            with pytest.raises(ValueError, match="授权"):
                await limited.call(
                    "ssh_mcp", "ssh_diagnose_memory", {"host_id": ssh_env.hosts[READY]}
                )
        # Past the platform's filter, the server itself refuses.
        async with ssh_mcp.connect(
            ssh_env.provider.mcp_url,
            ssh_env.limited["token"],
            allow_http=True,
            timeout=30,
        ) as adapter:
            refused = await adapter.session.call_tool(
                "ssh_diagnose_memory", {"host_id": ssh_env.hosts[READY]}
            )
            return refused

    refused = asyncio.run(run())
    text = " ".join(getattr(part, "text", "") for part in refused.content)
    assert refused.isError or '"forbidden"' in text, text


def test_revoked_token_fails_the_connection_with_a_reason(ssh_env):
    created = ssh_env.client("joint-revoked", ["cpu"])
    jp.created(ssh_env.provider.admin.post(f"/mcp/clients/{created['id']}/revoke"))

    async def run():
        async with bridge(ssh_env, created["token"]) as revoked:
            await revoked.catalog("ssh_mcp")

    with pytest.raises(ssh_mcp.IntegrationError) as caught:
        asyncio.run(run())
    assert "SSH MCP" in str(caught.value)
    assert created["token"] not in str(caught.value)
