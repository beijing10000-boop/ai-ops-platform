from app.mcp_runtime import PROFILES, compact_result, native_tools
from types import SimpleNamespace

def test_default_standard_profile():
    assert PROFILES["standard"]["rounds"] == 4
    assert PROFILES["standard"]["calls"] == 8
    assert PROFILES["quick"]["calls"] < PROFILES["standard"]["calls"] < PROFILES["deep"]["calls"]

def test_compact_tool_result_bounded_and_preserves_tail():
    raw = "START:" + "a"*10000 + ":END"
    result = compact_result(raw, 4000)
    assert len(result) < 4100
    assert result.startswith("START:")
    assert result.endswith(":END")
    assert "truncated" in result
    assert compact_result("normal", 4000) == "normal"

def test_native_tools_keeps_every_discovered_tool():
    tools = [SimpleNamespace(name=name, description=name, inputSchema={"type":"object","properties":{}}) for name in ("host_get", "item_get", "custom_tool")]
    assert {t["name"] for t in native_tools(tools)} == {"host_get", "item_get", "custom_tool"}
