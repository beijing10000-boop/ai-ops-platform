import re

PATTERNS = (
    (
        re.compile(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
            re.S,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (
        re.compile(r'(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)[^\s,;"\']+'),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r'(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?token|token)["\']?\s*[:=]\s*["\']?)[^\s,;"\']+'
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"), r"\1[REDACTED]@"),
)


def redact(value, limit=32768):
    text = str(value)
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:limit]
