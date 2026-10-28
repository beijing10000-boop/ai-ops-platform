import json
from fastapi import HTTPException

PROFILES = {
    "quick": {
        "rounds": 2,
        "calls": 4,
        "per_round": 3,
        "result_chars": 2000,
        "seconds": 65,
        "tokens": 12000,
    },
    "standard": {
        "rounds": 4,
        "calls": 12,
        "per_round": 4,
        "result_chars": 4000,
        "seconds": 110,
        "tokens": 24000,
    },
    "deep": {
        "rounds": 6,
        "calls": 16,
        "per_round": 8,
        "result_chars": 6000,
        "seconds": 150,
        "tokens": 48000,
    },
}
RANGES = {
    "rounds": (1, None),
    "calls": (1, None),
    "per_round": (1, None),
    "result_chars": (500, None),
    "seconds": (20, None),
    "tokens": (2000, None),
}


def validate_settings(values):
    try:
        if "ai_request_timeout_seconds" in values:
            raw = values["ai_request_timeout_seconds"]
            if not isinstance(raw, str) or not raw.isdecimal() or not 15 <= int(raw) <= 180:
                raise ValueError()
        if "ai_profile_budgets" in values:
            obj = json.loads(values["ai_profile_budgets"] or "{}")
            if not isinstance(obj, dict) or set(obj) - set(PROFILES):
                raise ValueError()
            for name, limits in obj.items():
                if not isinstance(limits, dict) or set(limits) - set(RANGES):
                    raise ValueError()
                for key, val in limits.items():
                    lo, hi = RANGES[key]
                    if (
                        type(val) is not int
                        or val < lo
                        or (hi is not None and val > hi)
                    ):
                        raise ValueError()
        if "disabled_tools" in values:
            from ..integrations.zabbix import READ_TOOLS

            names = json.loads(values["disabled_tools"] or "[]")
            if not isinstance(names, list) or any(n not in READ_TOOLS for n in names):
                raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(422, "预算或工具禁用配置无效") from None


def profile(name, read_setting):
    name = name if name in PROFILES else "standard"
    limits = dict(PROFILES[name])
    raw = read_setting("ai_profile_budgets") or "{}"
    validate_settings({"ai_profile_budgets": raw})
    limits.update(json.loads(raw).get(name, {}))
    return limits
