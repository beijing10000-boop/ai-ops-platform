"""Real Streamable HTTP SDK and independently authenticated MCP connections."""

import asyncio
import socket
import threading
import time
from contextlib import ExitStack, contextmanager

import httpx
import pytest
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.responses import PlainTextResponse

from app.integrations import ssh_mcp, zabbix


@contextmanager
def server(provider):
    mcp = FastMCP(provider, stateless_http=True, json_response=True)

    annotations = ToolAnnotations(readOnlyHint=True, destructiveHint=False)

    @mcp.tool(annotations=annotations)
    def ssh_resolve_target(address: str) -> dict:
        return {
            "status": "success",
            "host_id": 92,
            "revision": 3,
            "address": address,
            "name": "direct-native",
        }

    @mcp.tool(annotations=annotations)
    def ssh_resolve_host(zabbix_hostid: str) -> dict:
        if zabbix_hostid != "10":
            return {"status": "failed"}
        return {
            "status": "success",
            "zabbix_hostid": "10",
            "host_id": 92,
            "revision": 3,
        }

    @mcp.tool(annotations=annotations)
    def ssh_diagnose_cpu(host_id: int, expected_revision: int) -> dict:
        if expected_revision != 3:
            return {"host_id": host_id, "action": "cpu", "status": "failed"}
        return {
            "host_id": host_id,
            "action": "cpu",
            "status": "success",
            "job_id": "fixture-job",
            "output": "current CPU evidence",
        }

    @mcp.tool(annotations=annotations)
    def ssh_diagnose_directory_usage(
        host_id: int, root: str = "/data", expected_revision: int | None = None
    ) -> dict:
        assert expected_revision == 3
        return {
            "host_id": host_id,
            "action": "directory",
            "status": "success",
            "data": {
                "root": root,
                "top_directories": [{"directory": root + "/app", "bytes": 1024}],
            },
        }

    @mcp.tool()
    def host_get(
        hostids: list[str] | None = None,
        output: list[str] | None = None,
        limit: int = 100,
    ) -> list[dict]:
        return [{"hostid": "10", "name": "fixture-monitoring"}]

    inner = mcp.streamable_http_app()
    token = provider + "-fixture-token"
    requests = []

    async def app(scope, receive, send):
        if scope["type"] == "http":
            header = dict(scope["headers"]).get(b"authorization", b"").decode()
            requests.append(header)
            if header != "Bearer " + token:
                await PlainTextResponse("unauthorized", status_code=401)(
                    scope, receive, send
                )
                return
        await inner(scope, receive, send)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    service = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
    thread = threading.Thread(
        target=service.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    try:
        for _ in range(100):
            if service.started:
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("fixture MCP failed to start")
        yield "http://127.0.0.1:" + str(port) + "/mcp", token, requests
    finally:
        service.should_exit = True
        thread.join(timeout=5)
        sock.close()


def test_two_real_mcp_connections_keep_tokens_bindings_and_failures_separate():
    with ExitStack() as stack:
        ssh_url, ssh_token, ssh_requests = stack.enter_context(server("ssh"))
        z_url, z_token, z_requests = stack.enter_context(server("zabbix"))

        async def run():
            async with zabbix.connect(
                {"mcp_url": z_url, "mcp_token": z_token}.get
            ) as session:
                assert "host_get" in {t.name for t in await zabbix.discover(session)}
                response = await zabbix.call(session, "host_get", {"hostids": ["10"]})
                assert zabbix.records(response)[0]["hostid"] == "10"
                async with ssh_mcp.connect(
                    ssh_url, ssh_token, allow_http=True, timeout=5
                ) as adapter:
                    binding = await adapter.resolve("10")
                    assert binding.host_id == 92 and binding.revision == 3
                    result = await adapter.diagnose(binding, "cpu")
                    assert (
                        result["provider"] == "ssh_mcp"
                        and result["job_id"] == "fixture-job"
                    )
                    directory = await adapter.diagnose(
                        binding, "directory", directory_root="/data"
                    )
                    assert directory["data"]["root"] == "/data"
                    assert (
                        directory["data"]["top_directories"][0]["directory"]
                        == "/data/app"
                    )
                    stale = await adapter.diagnose(
                        ssh_mcp.HostBinding("10", 92, 2), "cpu"
                    )
                    assert stale["status"] == "failed"
                    with pytest.raises(ssh_mcp.IntegrationError, match="映射"):
                        await adapter.resolve("999")
            with pytest.raises(Exception):
                async with ssh_mcp.connect(
                    ssh_url, z_token, allow_http=True, timeout=3
                ):
                    pytest.fail("wrong MCP token must not authenticate")

        asyncio.run(run())
        assert set(z_requests) == {"Bearer " + z_token}
        assert "Bearer " + ssh_token in ssh_requests


def test_http_client_never_forwards_tokens_through_redirects_or_environment_proxies(
    monkeypatch,
):
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:1")

    async def run():
        async with ssh_mcp.client_factory(
            headers={"Authorization": "Bearer fixture"}, timeout=1
        ) as client:
            assert client.follow_redirects is False
            assert isinstance(client, httpx.AsyncClient)

    asyncio.run(run())


def test_skill_bridge_uses_native_ssh_schema_over_real_transport():
    from app.skill_mcp import SkillMCP

    with server("ssh") as (url, token, requests):
        settings = {
            "ssh_mcp_enabled": "true",
            "ssh_mcp_url": url,
            "ssh_mcp_token": token,
        }

        async def run():
            async with SkillMCP(
                lambda key: settings.get(key, ""),
                ["ssh_mcp"],
                deadline=time.monotonic() + 20,
                target=("ip", "198.51.100.21"),
            ) as bridge:
                found = await bridge.definitions("ssh_mcp", "ssh_resolve_target")
                assert "address" in found[0]["parameters"]["properties"]
                await bridge.call(
                    "ssh_mcp", "ssh_resolve_target", {"address": "198.51.100.21"}
                )
                result = await bridge.call(
                    "ssh_mcp", "ssh_diagnose_cpu", {"host_id": 92}
                )
                assert result["data"]["job_id"] == "fixture-job"
                assert bridge.target_metadata["ssh_host_id"] == 92

        asyncio.run(run())
        assert set(requests) == {"Bearer " + token}
