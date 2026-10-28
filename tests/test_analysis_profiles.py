from app.mcp_runtime import compact_result, native_tools
from app.orchestrator.budgets import PROFILES
from types import SimpleNamespace


def test_default_standard_profile():
    assert PROFILES["standard"]["rounds"] == 4
    assert PROFILES["standard"]["calls"] == 12
    assert (
        PROFILES["quick"]["calls"]
        < PROFILES["standard"]["calls"]
        < PROFILES["deep"]["calls"]
    )


def test_compact_tool_result_bounded_and_preserves_tail():
    raw = "START:" + "a" * 10000 + ":END"
    result = compact_result(raw, 4000)
    assert len(result) < 4100
    assert result.startswith("START:")
    assert result.endswith(":END")
    assert "truncated" in result
    assert compact_result("normal", 4000) == "normal"


def test_native_tools_keeps_only_authorized_discovered_tools():
    tools = [
        SimpleNamespace(
            name=name,
            description=name,
            inputSchema={"type": "object", "properties": {}},
        )
        for name in ("host_get", "item_get", "custom_tool")
    ]
    assert {t["name"] for t in native_tools(tools)} == {"host_get", "item_get"}


def test_usage_footer_profiles_and_missing_usage():
    from app.mcp_runtime import format_usage

    for profile, label in (
        ("quick", "快速分析"),
        ("standard", "标准分析"),
        ("deep", "深度分析"),
    ):
        value = format_usage(
            {
                "available": True,
                "total": 1200,
                "input": 1000,
                "output": 200,
                "profile": profile,
            }
        )
        assert "1,200" in value and "分析模式：" + label in value
    assert "分析模式：深度分析" in format_usage({"profile": "deep", "available": False})
    assert "分析模式" not in format_usage({"available": False})
