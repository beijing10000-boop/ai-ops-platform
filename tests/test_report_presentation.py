from app.mcp_runtime import readable_report_answer
from app.report_presentation import human_metrics


def test_human_metrics_convert_iec_values_and_percentage_precision():
    value = "内存 8173636 KiB，可用 800340 KiB；利用率 90.201081%，空闲 9.792%。"
    out = human_metrics(value)
    assert "7.79 GiB" in out
    assert "0.76 GiB" in out
    assert "90.20%" in out
    assert "9.79%" in out
    assert "KiB" not in out
    assert human_metrics("50.00 MiB / 1.00 GiB") == "0.05 GiB / 1.00 GiB"
    # Under 0.01 GiB a size stays in MiB rather than reading 0.00 GiB.
    assert human_metrics("RSS 5120 KiB") == "RSS 5.00 MiB"


def test_byte_sizes_read_in_gib_without_repeating_the_models_own_conversion():
    # Production (v1.4.1, memory alert): byte counts on the Feishu card.
    text = (
        "总内存 16825073664 B 中可用仅 1587232768 B（约 1.48 GiB，9.44%），"
        "Swap（0 B），读取 1,048,576 bytes，页 512 B"
    )
    assert human_metrics(text) == (
        "总内存 15.67 GiB 中可用仅 1.48 GiB（9.44%），"
        "Swap（0 GiB），读取 1.00 MiB，页 512 B"
    )
    # Rates and identifiers are not sizes.
    for kept in ("120 MiB/s", "800 B/s", "E5-2680", "dsp-api_445", "-Xmx 4096m"):
        assert human_metrics(kept) == kept


def test_json_report_does_not_expose_human_required_or_convert_raw_identifiers():
    raw = '{"cause":"内存达到90.201081%","action":"调查Java","analysis":"PID 31272 RSS 2232168 KiB","human_required":true}'
    report = readable_report_answer(raw)
    assert "诊断结论" in report
    assert "90.20%" in report
    assert "2.13 GiB" in report
    assert "PID 31272" in report
    assert "需人工核验" not in report


def test_text_report_is_normalized_without_changing_precise_ip():
    text = "198.51.100.35 90.12345%，RSS 1000 KiB"
    result = readable_report_answer(text)
    assert "198.51.100.35" in result
    assert "90.12%" in result
    assert "0.98 MiB" in result
