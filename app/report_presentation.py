"""Presentation-only normalizations for human-facing diagnostic reports.

Keep original MCP evidence, model output and stored metrics untouched.
"""
import re

_PERCENT = re.compile(r"(?<![A-Za-z0-9_.])(?P<number>\d+(?:\.\d+)?)\s*%")
_KIB = re.compile(r"(?<![\w.])(?P<number>\d[\d,]*(?:\.\d+)?)\s*KiB\b", re.I)


def human_metrics(text):
    """Use two decimals for percentages and IEC MiB/GiB for KiB literals."""
    if not isinstance(text, str):
        return text

    def kib(match):
        value = float(match["number"].replace(",", ""))
        mib = value / 1024
        return f"{mib / 1024:.2f} GiB" if mib >= 1024 else f"{mib:.2f} MiB"

    text = _KIB.sub(kib, text)
    text = _PERCENT.sub(lambda m: f"{float(m['number']):.2f}%", text)
    # Avoid repeating model-provided approximate binary equivalents.
    text = re.sub(r"(\d+\.\d{2}\s+(?:MiB|GiB))（约\s*\1）", r"\1", text)
    return text
