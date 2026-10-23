import asyncio
from types import SimpleNamespace
import pytest
from app.integrations import zabbix
from app.security.redact import redact
from app.diagnostics.actions import build, gateway_request


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


@pytest.mark.parametrize(
    "unit",
    [
        "nginx;id",
        "$(id)",
        "`id`",
        "--help",
        "nginx\nreboot",
        "a/b",
        "nginx.service && rm -rf /",
        "nginx.service\x00",
    ],
)
def test_service_injections_rejected_before_connection(unit):
    with pytest.raises(ValueError):
        build("logs", unit, 30)


def test_no_arbitrary_file_shell_or_mutation_actions():
    for action in (
        "execute_shell",
        "restart",
        "stop",
        "write_file",
        "upload",
        "download",
        "delete",
        "du_all",
    ):
        with pytest.raises(ValueError):
            build(action)
    assert "sudo" not in build("cpu")
    assert "python" not in build("cpu")
    assert "--since" in build("kernel")
    assert "-n 120" in build("logs", "nginx.service", 30)
    assert gateway_request("cpu") == "aiops-v1 cpu 30"


def test_redaction_removes_credentials_before_model_submission():
    text = "Authorization: Bearer xyzsecret password=hunter2 api_key=secret123 https://u:p@example.org\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
    result = redact(text)
    for secret in ("xyzsecret", "hunter2", "secret123", "u:p@", "\nsecret\n"):
        assert secret not in result
