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


def redact_data(value):
    """Redact parsed report values without truncating or invalidating JSON."""
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if re.search(
                    r"(?i)(?:^|[_-])(?:password|passwd|passphrase|secret|"
                    r"(?:access[_-]?)?token|api[_-]?key|private[_-]?key|authorization)$",
                    key,
                )
                else redact_data(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact(value, None)
    return value


def redact(value, limit=32768):
    text = str(value)
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:limit]
