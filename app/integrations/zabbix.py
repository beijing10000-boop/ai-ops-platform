"""Platform-enforced exact read allowlist, independent of MCP annotations."""

import json
import re
import time
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from jsonschema import Draft202012Validator
from ..security.redact import redact
from .ssh_mcp import client_factory, validate_endpoint

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
SORT_FIELDS = {"problem_get": ["eventid"]}

SELECTS = {
    "selectInterfaces": ["interfaceid", "type", "ip", "dns", "main", "useip", "port"],
    "selectHostGroups": ["groupid", "name"],
    "selectInventory": ["os", "type"],
    "selectTags": ["tag", "value"],
    "selectHosts": ["hostid", "host", "name"],
    "selectItems": FIELDS["item_get"],
}


def search_fields(name):
    fields = {"name", "host", "key_", "status", "value_type", "value"}
    return fields | {"ip"} if name == "hostinterface_get" else fields


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
            # The model sees this schema in every later round; name the fields
            # once instead of repeating the same value schema per field.
            # validate_args() still enforces fields and sizes.
            value = {
                "type": "object",
                "propertyNames": {"enum": sorted(search_fields(name))},
                "additionalProperties": {
                    "type": ["string", "integer", "array"],
                    "maxLength": 160,
                    "maxItems": 8,
                    "items": {"type": "string", "maxLength": 80},
                },
            }
        elif key in {"searchByAny", "searchWildcardsEnabled", "countOutput", "recent"}:
            value = {"type": "boolean"}
        elif key == "sortorder":
            value = {"type": "string", "enum": ["ASC", "DESC"]}
        elif key == "sortfield":
            value = {
                "anyOf": [
                    {"type": "string", "enum": SORT_FIELDS.get(name, FIELDS[name])},
                    {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": SORT_FIELDS.get(name, FIELDS[name]),
                        },
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
    if "sortfield" in args:
        value = args["sortfield"]
        fields = [value] if isinstance(value, str) else value
        if (
            not isinstance(fields, list)
            or not fields
            or any(field not in SORT_FIELDS.get(name, FIELDS[name]) for field in fields)
        ):
            raise ValueError(f"{name} 不支持该排序字段；请使用允许的 sortfield")
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
                or set(val) - search_fields(name)
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
    validate_endpoint(endpoint)
    token = read_setting("mcp_token")
    async with streamablehttp_client(
        endpoint,
        headers={"Authorization": "Bearer " + token} if token else {},
        timeout=15,
        httpx_client_factory=client_factory,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


class ToolSchemaMismatch(ValueError):
    """The locally allowed read query cannot satisfy the remote MCP schema."""


def _schema_accepts(property_schema, expected):
    if not isinstance(property_schema, dict):
        return False
    declared = property_schema.get("type")
    if declared == expected or isinstance(declared, list) and expected in declared:
        return True
    return any(
        _schema_accepts(option, expected)
        for field in ("anyOf", "oneOf", "allOf")
        for option in property_schema.get(field, [])
    )


def adapt_read_args(name, checked, schema):
    """Convert allowlisted read arguments to the remote MCP transport shape.

    Must be called only after validate_args. Some initMAX MCP versions require
    comma-separated output fields and carry selectXxx via extra_params.
    """
    if name not in READ_TOOLS:
        raise ValueError("tool not authorized")
    if re.search(r'"\\$ref"\\s*:\\s*"(?!#)', json.dumps(schema)):
        raise ValueError("external schema refs forbidden")
    if not isinstance(schema, dict) or not isinstance(
        schema.get("properties", {}), dict
    ):
        raise ToolSchemaMismatch("远端未提供可验证的参数结构")
    props = schema.get("properties", {})
    args, extra = {}, {}
    for key, value in checked.items():
        if key == "output" and _schema_accepts(props.get("output", {}), "string"):
            value = ",".join(value) if isinstance(value, list) else value
        if key in props:
            args[key] = value
        elif "extra_params" in props and _schema_accepts(
            props["extra_params"], "object"
        ):
            # Local policy already validated each key, value and host scope.
            extra[key] = value
        elif schema.get("additionalProperties") is not False:
            # An open/unspecified JSON Schema permits locally authorized keys.
            args[key] = value
        else:
            # Do not silently drop host/ID scope or any parameter.
            raise ToolSchemaMismatch(f"远端 {name} 不支持必需的只读参数 {key}")
    if extra:
        args["extra_params"] = extra
    return args


def validate_remote_schema(name, args, schema):
    # Do not resolve remote schema URLs.
    if re.search(r'"\$ref"\s*:\s*"(?!#)', json.dumps(schema)):
        raise ValueError("external schema refs forbidden")
    from jsonschema.exceptions import ValidationError

    try:
        Draft202012Validator(schema).validate(args)
    except ValidationError as exc:
        # Never reflect untrusted schema messages or argument values.
        location = ".".join(str(bit) for bit in exc.absolute_path) or "root"
        raise ToolSchemaMismatch(
            f"远端 {name} 参数 {location} 不兼容（{exc.validator}）"
        ) from None


async def call(session, name, args, *, schema=None, host_id=None):
    import asyncio

    checked = validate_args(name, args, host_id=host_id)
    if schema is not None:
        checked = adapt_read_args(name, checked, schema)
        validate_remote_schema(name, checked, schema)
    return await asyncio.wait_for(session.call_tool(name, checked), timeout=18)


DEVICE_TYPES = {"linux", "windows", "vmware", "network", "other", "unknown"}


def infer_device(host):
    """Identify a verified Zabbix host using explicit tags, inventory or groups.

    Group memberships must come from host.get/selectHostGroups, never from
    untrusted alert text. In ambiguous cases fail closed to "unknown".
    """
    tags = {
        str(t.get("tag", "")).strip().lower(): str(t.get("value", "")).strip().lower()
        for t in host.get("tags", [])
        if isinstance(t, dict)
    }
    declared = tags.get("aiops.device_type")
    if declared in DEVICE_TYPES - {"unknown"}:
        return declared

    inventory = host.get("inventory")
    inventory = inventory if isinstance(inventory, dict) else {}
    os_name = str(inventory.get("os") or "").lower()
    for kind, words in [
        ("windows", ("windows",)),
        ("vmware", ("vmware", "esxi", "vcenter")),
        ("network", ("huawei", "vrp", "cisco", "comware")),
        (
            "linux",
            (
                "linux",
                "ubuntu",
                "debian",
                "rocky",
                "centos",
                "rhel",
                "red hat",
                "almalinux",
                "suse",
                "fedora",
                "openeuler",
                "euleros",
            ),
        ),
    ]:
        if any(w in os_name for w in words):
            return kind

    # Zabbix host.get exposes the selected host groups as "hostgroups".
    # Accept older/alternative "groups" only if it is structured group data.
    groups = host.get("hostgroups")
    if not isinstance(groups, list):
        groups = host.get("groups")
    if not isinstance(groups, list):
        return "unknown"
    names = {
        " ".join(str(group.get("name") or "").strip().casefold().split())
        for group in groups
        if isinstance(group, dict)
    }
    # Exact names only: an arbitrary group such as "Not Linux" does not
    # establish a safe SSH device classification.
    known_groups = {
        "linux": {"linux", "linux servers", "linux hosts", "linux server"},
        "windows": {"windows", "windows servers", "windows hosts"},
        "vmware": {"vmware", "vmware hosts", "vmware servers", "esxi", "vcenter"},
    }
    matches = {kind for kind, aliases in known_groups.items() if names & aliases}
    return next(iter(matches)) if len(matches) == 1 else "unknown"


async def monitoring_hosts(read_setting, query="", host_id=None):
    """Read current authorized hosts directly from Zabbix; never persist an inventory."""
    import asyncio

    if "host_get" not in enabled_names(read_setting):
        raise ValueError("host_get 已被禁用，无法查询监控主机")
    args = {
        "selectInventory": ["os", "type"],
        "selectTags": ["tag", "value"],
        "selectHostGroups": ["groupid", "name"],
        "limit": 100,
    }
    if host_id:
        if not re.fullmatch(r"[0-9]{1,32}", host_id):
            raise ValueError("Zabbix Host ID 无效")
        args["hostids"] = [host_id]
    elif query:
        if query.isdigit():
            args["hostids"] = [query]
        else:
            args["search"] = {"name": query, "host": query}
            args["searchByAny"] = True
    async with asyncio.timeout(20):
        async with connect(read_setting) as session:
            remote = next(
                (t for t in await discover(session) if t.name == "host_get"), None
            )
            if remote is None:
                raise ValueError("Zabbix MCP 没有授权 host_get")
            response = await call(
                session,
                "host_get",
                args,
                schema=remote.inputSchema,
                host_id=host_id if host_id else None,
            )
    if response.isError:
        raise ValueError("Zabbix MCP 拒绝查询主机")
    rows = records(response)
    result, seen = [], set()
    for host in rows[:100]:
        hid = str(host.get("hostid", ""))
        if host_id and hid in seen:
            raise ValueError("Zabbix MCP 返回重复 Host ID，无法唯一确认所选主机")
        if not re.fullmatch(r"[0-9]{1,32}", hid) or hid in seen:
            continue
        if host_id and hid != host_id:
            raise ValueError("Zabbix MCP 返回的主机与所选 Host ID 不匹配")
        seen.add(hid)
        result.append(
            {
                "zabbix_hostid": hid,
                "name": str(host.get("name") or host.get("host") or hid)[:160],
                "device_type": infer_device(host),
                "monitored": str(host.get("status", "0")) == "0",
            }
        )
    if host_id and len(result) != 1:
        raise ValueError("所选主机不存在或不在当前 Zabbix MCP 读取范围内")
    return result
