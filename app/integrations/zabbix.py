"""Platform-enforced exact read allowlist, independent of MCP annotations."""

import json
import re
import time
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from jsonschema import Draft202012Validator
from ..security.redact import redact

READ_TOOLS = frozenset(
    {
        "host_get",
        "hostgroup_get",
        "hostinterface_get",
        "event_get",
        "problem_get",
        "trigger_get",
        "item_get",
        "history_get",
        "trend_get",
    }
)
FIELDS = {
    "host_get": ["hostid", "host", "name", "status"],
    "hostgroup_get": ["groupid", "name"],
    "hostinterface_get": [
        "interfaceid",
        "hostid",
        "type",
        "ip",
        "dns",
        "useip",
        "port",
        "available",
    ],
    "event_get": [
        "eventid",
        "objectid",
        "clock",
        "value",
        "severity",
        "name",
        "r_eventid",
    ],
    "problem_get": ["eventid", "objectid", "clock", "severity", "name", "r_eventid"],
    "trigger_get": ["triggerid", "description", "priority", "value", "lastchange"],
    "item_get": [
        "itemid",
        "hostid",
        "name",
        "key_",
        "lastvalue",
        "lastclock",
        "value_type",
        "units",
    ],
    "history_get": ["itemid", "clock", "value", "ns"],
    "trend_get": ["itemid", "clock", "num", "value_min", "value_avg", "value_max"],
}
COMMON = {
    "output",
    "limit",
    "sortfield",
    "sortorder",
    "filter",
    "search",
    "searchByAny",
    "searchWildcardsEnabled",
    "countOutput",
}
PARAMS = {
    "host_get": {
        "hostids",
        "groupids",
        "selectInterfaces",
        "selectHostGroups",
        "selectInventory",
        "selectTags",
    },
    "hostgroup_get": {"groupids"},
    "hostinterface_get": {"hostids", "interfaceids"},
    "event_get": {
        "eventids",
        "hostids",
        "objectids",
        "source",
        "object",
        "time_from",
        "time_till",
        "value",
        "severities",
    },
    "problem_get": {"eventids", "hostids", "objectids", "recent", "severities"},
    "trigger_get": {"triggerids", "hostids", "selectHosts", "selectItems"},
    "item_get": {"itemids", "hostids", "triggerids", "value_type"},
    "history_get": {"itemids", "hostids", "history", "time_from", "time_till"},
    "trend_get": {"itemids", "time_from", "time_till"},
}
SELECTS = {
    "selectInterfaces": ["interfaceid", "type", "ip", "dns", "main", "useip", "port"],
    "selectHostGroups": ["groupid", "name"],
    "selectInventory": ["os", "type"],
    "selectTags": ["tag", "value"],
    "selectHosts": ["hostid", "host", "name"],
    "selectItems": FIELDS["item_get"],
}


def input_schema(name):
    """Curated schemas describe only arguments accepted by our local policy."""
    properties = {}
    for key in COMMON | PARAMS[name]:
        if key.endswith("ids"):
            value = {
                "type": "array",
                "items": {"type": "string", "pattern": "^[0-9]{1,32}$"},
                "minItems": 1,
                "maxItems": 8 if name in {"history_get", "trend_get"} else 100,
            }
        elif key in SELECTS:
            value = {"type": "array", "items": {"type": "string", "enum": SELECTS[key]}}
        elif key == "output":
            value = {"type": "array", "items": {"type": "string", "enum": FIELDS[name]}}
        elif key == "limit":
            value = {
                "type": "integer",
                "minimum": 1,
                "maximum": 120 if name in {"history_get", "trend_get"} else 100,
            }
        elif key in {"time_from", "time_till"}:
            value = {"type": "integer", "minimum": 0}
        elif key == "history":
            value = {"type": "integer", "enum": [0, 1, 2, 3, 4, 5, 6]}
        elif key in {"search", "filter"}:
            value = {
                "type": "object",
                "properties": {
                    field: {
                        "anyOf": [
                            {"type": "string", "maxLength": 160},
                            {"type": "integer"},
                            {
                                "type": "array",
                                "maxItems": 8,
                                "items": {"type": "string", "maxLength": 80},
                            },
                        ]
                    }
                    for field in (
                        "name",
                        "host",
                        "key_",
                        "status",
                        "value_type",
                        "value",
                    )
                },
                "additionalProperties": False,
            }
        elif key in {"searchByAny", "searchWildcardsEnabled", "countOutput", "recent"}:
            value = {"type": "boolean"}
        elif key == "sortorder":
            value = {"type": "string", "enum": ["ASC", "DESC"]}
        elif key == "sortfield":
            value = {
                "anyOf": [
                    {"type": "string", "enum": FIELDS[name]},
                    {
                        "type": "array",
                        "items": {"type": "string", "enum": FIELDS[name]},
                    },
                ]
            }
        elif key == "severities":
            value = {
                "type": "array",
                "maxItems": 6,
                "items": {"type": "integer", "minimum": 0, "maximum": 5},
            }
        else:
            value = {
                "anyOf": [{"type": "string", "maxLength": 80}, {"type": "integer"}]
            }
        properties[key] = value
    required = (
        ["itemids", "history", "time_from", "time_till"]
        if name == "history_get"
        else ["itemids", "time_from", "time_till"]
        if name == "trend_get"
        else []
    )
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


async def discover(session):
    """Inspect paginated catalogs, retaining only our nine authorized tool types."""
    tools = []
    cursor = None
    seen = set()
    for _ in range(20):
        result = (
            await session.list_tools(cursor=cursor)
            if cursor
            else await session.list_tools()
        )
        tools.extend(t for t in result.tools if t.name in READ_TOOLS)
        cursor = getattr(result, "nextCursor", None)
        if not cursor:
            return list({t.name: t for t in tools}.values())
        if cursor in seen:
            raise ValueError("MCP tool pagination repeated a cursor")
        seen.add(cursor)
    raise ValueError("MCP tool pagination exceeded its budget")


def enabled_names(read_setting):
    try:
        disabled = set(json.loads(read_setting("disabled_tools") or "[]"))
    except (TypeError, ValueError):
        disabled = set(READ_TOOLS)  # fail closed
    return READ_TOOLS - disabled


def validate_args(name, arguments, *, host_id=None):
    if name not in READ_TOOLS or not isinstance(arguments, dict):
        raise ValueError("tool not authorized")
    if set(arguments) - (COMMON | PARAMS[name]):
        raise ValueError("parameter not authorized")
    if len(json.dumps(arguments)) > 12000:
        raise ValueError("arguments too large")
    args = dict(arguments)
    # Always request a minimal explicit field set; never retrieve host secrets or item credentials.
    output = args.get("output")
    if output not in (None, "extend") and (
        not isinstance(output, list) or any(f not in FIELDS[name] for f in output)
    ):
        raise ValueError("output fields not authorized")
    args["output"] = FIELDS[name] if output in (None, "extend") else output
    for key in set(args) & set(SELECTS):
        if args[key] == "extend":
            args[key] = SELECTS[key]
        if not isinstance(args[key], list) or any(
            x not in SELECTS[key] for x in args[key]
        ):
            raise ValueError("select fields not authorized")
    for key, val in list(args.items()):
        if key.endswith("ids"):
            if (
                not isinstance(val, list)
                or not 1 <= len(val) <= 100
                or any(not re.fullmatch(r"[0-9]{1,32}", str(x)) for x in val)
            ):
                raise ValueError("invalid ID scope")
            args[key] = [str(x) for x in val]
        elif key in {"filter", "search"}:
            if (
                not isinstance(val, dict)
                or len(val) > 5
                or set(val) - {"name", "host", "key_", "status", "value_type", "value"}
            ):
                raise ValueError("invalid search fields")
            if any(len(str(v)) > 160 for v in val.values()):
                raise ValueError("search too large")
    if (
        type(args.get("limit", 100)) is not int
        or not 1 <= args.get("limit", 100) <= 1000
    ):
        raise ValueError("invalid result limit")
    args["limit"] = min(
        args.get("limit", 100),
        120
        if name in {"history_get", "trend_get"}
        else 1000
        if name == "host_get"
        else 100,
    )
    if host_id and name in {
        "host_get",
        "hostinterface_get",
        "item_get",
        "trigger_get",
        "event_get",
        "problem_get",
        "history_get",
    }:
        if args.get("hostids") and args["hostids"] != [str(host_id)]:
            raise ValueError("host outside task scope")
        args["hostids"] = [str(host_id)]
    if name in {"history_get", "trend_get"}:
        if not args.get("itemids") or len(args["itemids"]) > 8:
            raise ValueError("bounded item IDs required")
        end = args.get("time_till", int(time.time()))
        start = args.get("time_from", end - 1800 if type(end) is int else None)
        if (
            type(start) is not int
            or type(end) is not int
            or not 0 < end - start <= 86400
        ):
            raise ValueError("history window must be 1–86400 seconds")
        args.update(time_from=start, time_till=end)
        if name == "history_get" and (
            type(args.get("history")) is not int
            or args["history"] not in (0, 1, 2, 3, 4, 5, 6)
        ):
            raise ValueError("history value type required")
    return args


def records(response):
    structured = getattr(response, "structuredContent", None)
    if isinstance(structured, list):
        return [r for r in structured if isinstance(r, dict)][:1000]
    if isinstance(structured, dict):
        for key in ("result", "data", "items"):
            if isinstance(structured.get(key), list):
                return [r for r in structured[key] if isinstance(r, dict)][:1000]
    decoder = json.JSONDecoder()
    for part in getattr(response, "content", [])[:2]:
        raw = str(getattr(part, "text", ""))[:1500000]
        # Skip the upstream [System: ...] disclaimer without treating it as instructions.
        for match in re.finditer(r"(?m)^\s*([\[{])", raw):
            try:
                obj, _ = decoder.raw_decode(raw[match.start(1) :])
            except ValueError:
                continue
            if isinstance(obj, dict):
                obj = obj.get("result", obj.get("data", obj))
            if isinstance(obj, dict):
                return [obj]
            if isinstance(obj, list):
                return [r for r in obj if isinstance(r, dict)][:1000]
    return []


def safe_result(response, max_chars=6000):
    rows = records(response)
    if rows:
        # No remote result is allowed to smuggle known credential fields into the model.
        forbidden = {
            "password",
            "passwd",
            "private_key",
            "token",
            "secret",
            "auth",
            "tls_psk",
            "tls_psk_identity",
            "macros",
        }

        def clean(v):
            if isinstance(v, dict):
                return {k: clean(x) for k, x in v.items() if k.lower() not in forbidden}
            if isinstance(v, list):
                return [clean(x) for x in v[:1000]]
            return redact(v, 2000) if isinstance(v, str) else v

        cleaned = clean(rows)
        text = json.dumps(cleaned, ensure_ascii=False)
    else:
        text = redact(
            "\n".join(
                str(getattr(p, "text", ""))
                for p in getattr(response, "content", [])[:2]
            ),
            max_chars,
        )
        cleaned = []
    return {
        "is_error": bool(getattr(response, "isError", False)),
        "data": redact(text, max_chars),
        "records": cleaned,
        "truncated": len(text) > max_chars,
    }


@asynccontextmanager
async def connect(read_setting):
    endpoint = read_setting("mcp_url")
    if not endpoint:
        raise RuntimeError("MCP 未配置")
    token = read_setting("mcp_token")
    async with streamablehttp_client(
        endpoint,
        headers={"Authorization": "Bearer " + token} if token else {},
        timeout=15,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def call(session, name, args, *, schema=None, host_id=None):
    import asyncio

    checked = validate_args(name, args, host_id=host_id)
    if schema:
        # Never resolve remote $ref URLs; the discovered schema is untrusted.
        if re.search(r'"\$ref"\s*:\s*"(?!#)', json.dumps(schema)):
            raise ValueError("external schema refs forbidden")
        Draft202012Validator(schema).validate(checked)
    return await asyncio.wait_for(session.call_tool(name, checked), timeout=18)
