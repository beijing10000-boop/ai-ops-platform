"""Presentation-only normalizations for human-facing diagnostic reports.

Keep original MCP evidence, model output and stored metrics untouched.
"""

import re

_PERCENT = re.compile(r"(?<![A-Za-z0-9_.])(?P<number>\d+(?:\.\d+)?)\s*%")
# Sizes written in bytes, KiB or MiB; rates such as MiB/s are left as written.
_SIZE = re.compile(
    r"(?<![\w.])(?P<number>\d[\d,]*(?:\.\d+)?)\s*"
    r"(?P<unit>(?i:KiB|MiB)|B|[Bb]ytes?|字节)(?![\w/])"
)
_UNIT_BYTES = {"kib": 1024, "mib": 1024**2}


def _gib(match):
    """A size in GiB with two decimals; under 0.01 GiB in MiB, so nothing
    reads 0.00 GiB, and byte counts under 1 KiB as written."""
    value = float(match["number"].replace(",", ""))
    unit = match["unit"].lower()
    if unit not in _UNIT_BYTES and 0 < value < 1024:
        return match[0]
    size = value * _UNIT_BYTES.get(unit, 1)
    if not size:
        return "0 GiB"
    gib = size / 1024**3
    return f"{gib:.2f} GiB" if gib >= 0.01 else f"{size / 1024**2:.2f} MiB"


def human_metrics(text):
    """Use two decimals for percentages and GiB for sizes in bytes, KiB or MiB."""
    if not isinstance(text, str):
        return text
    text = _SIZE.sub(_gib, text)
    text = _PERCENT.sub(lambda m: f"{float(m['number']):.2f}%", text)
    # Avoid repeating model-provided approximate binary equivalents:
    # "1.48 GiB（约 1.48 GiB）" and "1.48 GiB（约 1.48 GiB，9.44%）".
    text = re.sub(r"(\d+\.\d{2}\s+(?:MiB|GiB))（约\s*\1）", r"\1", text)
    return re.sub(r"(\d+\.\d{2}\s+(?:MiB|GiB))（约\s*\1\s*[，,]\s*", r"\1（", text)
