from app.mcp_runtime import compact_result
from app.orchestrator.budgets import PROFILES


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


def test_token_usage_aggregation_helpers():
    from types import SimpleNamespace

    from app import mcp_runtime

    first = SimpleNamespace(
        usage=SimpleNamespace(input_tokens=120, output_tokens=30, total_tokens=150)
    )
    second = SimpleNamespace(
        usage={"input_tokens": 80, "output_tokens": 20, "total_tokens": 100}
    )
    assert mcp_runtime.usage_counts(first) == {"input": 120, "output": 30, "total": 150}
    assert mcp_runtime.usage_counts(second) == {"input": 80, "output": 20, "total": 100}
    assert mcp_runtime.usage_counts(SimpleNamespace(usage=None)) is None
    assert "250" in mcp_runtime.format_usage(
        {"input": 200, "output": 50, "total": 250, "available": True}
    )
    assert "未返回用量" in mcp_runtime.format_usage({"available": False})


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


def test_duration_is_part_of_usage_footer():
    from app.mcp_runtime import format_usage

    text = format_usage(
        {
            "available": True,
            "total": 1250,
            "input": 1000,
            "output": 250,
            "profile": "standard",
        },
        duration_ms=57100,
    )
    assert "分析模式：标准分析 · 执行耗时：57.1 秒" in text
    assert "1,250" in text
    assert "执行耗时" not in format_usage({"available": False})
