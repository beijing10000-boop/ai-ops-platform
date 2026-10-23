from types import SimpleNamespace
from app.mcp_runtime import search_tool_catalog, DISCOVERY_TOOL, LOAD_TOOL

def test_dynamic_catalog_finds_any_mcp_tool():
    tools=[SimpleNamespace(name="host_get", description="Get hosts"),
           SimpleNamespace(name="custom_diagnostics", description="Diagnose custom switches")]
    assert search_tool_catalog(tools,"custom")[0]["name"]=="custom_diagnostics"
    assert search_tool_catalog(tools,"host")[0]["name"]=="host_get"

def test_both_meta_tools_are_bounded():
    assert DISCOVERY_TOOL["name"]=="search_mcp_tools"
    assert LOAD_TOOL["name"]=="load_mcp_tools"
