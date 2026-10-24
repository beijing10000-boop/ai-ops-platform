import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_real_stdio_mcp_exposes_only_registered_asset_diagnostics(tmp_path):
    async def run():
        env = {**os.environ, "DATA_DIR": str(tmp_path)}
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "app.mcp_server"], env=env
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                assert {t.name for t in listing.tools} == {
                    "list_linux_hosts",
                    "diagnose_linux_host",
                }
                assert not (await session.call_tool("list_linux_hosts", {})).isError
                result = await session.call_tool(
                    "diagnose_linux_host", {"host_id": 999, "diagnostic_type": "cpu"}
                )
                assert result.isError

    asyncio.run(run())
