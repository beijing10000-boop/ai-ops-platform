import asyncio
from types import SimpleNamespace
import pytest
from app.integrations import zabbix
from app.security.redact import redact


@pytest.mark.parametrize(
    "name,args",
    [
        ("host_delete", {"hostids": ["1"]}),
        ("zabbix_raw_api_call", {"method": "script.execute"}),
        ("host_get", {"params": {"output": "extend"}}),
        ("host_get", {"selectMacros": "extend"}),
        ("host_get", {"output": ["tls_psk"]}),
        ("item_get", {"output": ["password"]}),
        ("event_get", {"raw_json": True}),
        (
            "history_get",
            {"itemids": ["1"], "history": 0, "time_from": 1, "time_till": 999999},
        ),
        ("item_get", {"hostids": ["99"]}),
        ("host_get", {"server": "unapproved"}),
        ("host_get", {"filter": {"ip": "172.20.2.101"}}),
    ],
)
def test_write_secret_and_scope_bypasses_rejected(name, args):
    with pytest.raises(ValueError):
        zabbix.validate_args(name, args, host_id="1")


def test_read_fields_are_reduced_and_host_scope_is_forced():
    args = zabbix.validate_args("host_get", {"output": "extend"}, host_id="42")
    assert args["hostids"] == ["42"]
    assert args["output"] == ["hostid", "host", "name", "status"]
    assert "tls_psk" not in args["output"]


def test_disclaimer_parser_and_sensitive_field_removal():
    response = SimpleNamespace(
        isError=False,
        content=[
            SimpleNamespace(
                text='[System: raw untrusted data]\n[{"hostid":"42","password":"never-show","name":"host"}]'
            )
        ],
    )
    assert zabbix.records(response)[0]["hostid"] == "42"
    assert "never-show" not in zabbix.safe_result(response)["data"]


def test_remote_schema_cannot_fetch_external_reference():
    async def run():
        with pytest.raises(ValueError, match="external schema"):
            await zabbix.call(
                None,
                "host_get",
                {},
                schema={"$ref": "https://example.invalid/schema.json"},
            )

    asyncio.run(run())


def test_redaction_removes_credentials_before_model_submission():
    text = "Authorization: Bearer xyzsecret password=hunter2 api_key=secret123 https://u:p@example.org\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
    result = redact(text)
    for secret in ("xyzsecret", "hunter2", "secret123", "u:p@", "\nsecret\n"):
        assert secret not in result


def test_initmax_mcp_schema_translates_output_and_inventory_tags_without_writes():
    schema = {
        "type": "object",
        "properties": {
            "hostids": {"type": "array", "items": {"type": "string"}},
            "output": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "limit": {"type": "integer"},
            "extra_params": {"anyOf": [{"type": "object"}, {"type": "null"}]},
        },
        "additionalProperties": False,
    }
    checked = zabbix.validate_args(
        "host_get",
        {
            "hostids": ["11848"],
            "selectInventory": ["os", "type"],
            "selectTags": ["tag", "value"],
            "selectHostGroups": ["groupid", "name"],
        },
        host_id="11848",
    )
    wire = zabbix.adapt_read_args("host_get", checked, schema)
    zabbix.validate_remote_schema("host_get", wire, schema)
    assert wire["output"] == "hostid,host,name,status"
    assert wire["hostids"] == ["11848"]
    assert wire["extra_params"] == {
        "selectInventory": ["os", "type"],
        "selectTags": ["tag", "value"],
        "selectHostGroups": ["groupid", "name"],
    }
    assert "server" not in wire and "raw_json" not in wire


def test_extra_params_cannot_bypass_local_write_or_host_scope_policy():
    schema = {
        "type": "object",
        "properties": {
            "output": {"type": "string"},
            "extra_params": {"type": "object"},
        },
        "additionalProperties": False,
    }
    with pytest.raises(ValueError, match="parameter not authorized"):
        zabbix.validate_args("host_get", {"extra_params": {"method": "script.execute"}})
    with pytest.raises(ValueError, match="host outside task scope"):
        zabbix.validate_args("host_get", {"hostids": ["11849"]}, host_id="11848")
    checked = zabbix.validate_args("host_get", {}, host_id="11848")
    wire = zabbix.adapt_read_args("host_get", checked, schema)
    assert wire["extra_params"]["hostids"] == ["11848"]


def test_strict_mcp_schema_unsupported_scoping_fails_closed():
    checked = zabbix.validate_args("host_get", {}, host_id="11848")
    with pytest.raises(zabbix.ToolSchemaMismatch, match="hostids"):
        zabbix.adapt_read_args(
            "host_get",
            checked,
            {
                "type": "object",
                "properties": {
                    "output": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "additionalProperties": False,
            },
        )


def test_readable_ai_json_report_keeps_worker_original_payload():
    import json
    from app.mcp_runtime import readable_report_answer

    info = {
        "cause": "原因尚未确定",
        "action": "先检查 Zabbix agent",
        "analysis": "MCP 校验失败，尚未取得监控证据",
        "human_required": True,
    }
    raw = json.dumps(info, ensure_ascii=False)
    human = readable_report_answer(raw)
    assert "故障原因（AI 推断）\n原因尚未确定" in human
    assert "处理建议\n先检查 Zabbix agent" in human
    assert "分析与依据" in human
    assert "需人工核验：是" in human
    assert readable_report_answer("纯文本结论") == "纯文本结论"


def test_problem_get_rejects_clock_sort_and_advertises_only_eventid():
    schema = zabbix.input_schema("problem_get")["properties"]["sortfield"]
    assert schema["anyOf"][0]["enum"] == ["eventid"]
    with pytest.raises(ValueError, match="sortfield"):
        zabbix.validate_args("problem_get", {"sortfield": "clock"})
    good = zabbix.validate_args("problem_get", {"sortfield": "eventid"})
    assert good["sortfield"] == "eventid"
    assert (
        "clock"
        in zabbix.input_schema("event_get")["properties"]["sortfield"]["anyOf"][0][
            "enum"
        ]
    )
