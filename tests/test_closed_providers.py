"""An MCP service whose session cannot be opened is closed for the task: the
model is not offered it, a call to it is refused before it is made, and the
refusal is a capability note (coverage.skipped), never an evidence gap that
makes the task partial (PC-05). Classification of Chinese text (PC-04)."""

from contextlib import asynccontextmanager

import pytest

from app.diagnostics.playbooks import classify, classify_keys
from app.integrations import ssh_mcp, zabbix
from test_acceptance_scenarios import (
    LINUX_HOST,
    SSH,
    Call,
    Model,
    Zabbix,
    alert_clock,
    answer,
    event_for,
    item,
    output_of,
    rig,
    run_alert,
)


def provider_enums(request):
    return [
        tool["parameters"]["properties"]["provider"]["enum"]
        for tool in request["tools"]
        if "provider" in tool["parameters"]["properties"]
    ]


def test_an_unreachable_ssh_mcp_is_closed_not_a_gap(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST, [item("201", "system.cpu.load[all,avg5]", 9.0)], [], [], {}, {}
    )
    rig(monkeypatch, zbx, SSH({}))

    @asynccontextmanager
    async def refused(read_setting, **kwargs):
        raise ConnectionRefusedError("connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(ssh_mcp, "configured", refused)
    resolve = {
        "provider": "ssh_mcp",
        "name": "ssh_resolve_host",
        "arguments": {"zabbix_hostid": "10101"},
    }
    model = Model(
        lambda request: answer("", [Call("r1", "call_mcp_tool", resolve)]),
        lambda request: answer('{"cause": "仅凭 Zabbix"}'),
    )
    task, _ = run_alert(event_for("Linux: Load high", "71031", clock), model)
    caps = task["report"]["capabilities"]
    assert caps["ssh_mcp"]["status"] == "unreachable"
    assert provider_enums(model.requests[0]) == [["zabbix_mcp"], ["zabbix_mcp"]]
    assert "SSH 实时诊断不可用" in output_of(model.requests[1], "r1")["error"]
    assert task["status"] == "success"
    assert {
        "tool": "ssh_resolve_host",
        "reason": "目标主机的 SSH 实时诊断不可用，未调用",
    } in task["report"]["coverage"]["skipped"]


def test_an_unreachable_zabbix_mcp_is_closed_not_a_gap(monkeypatch):
    clock = alert_clock()
    rig(monkeypatch, None, SSH({}))

    @asynccontextmanager
    async def refused(*args, **kwargs):
        raise ConnectionRefusedError("connection refused")
        yield  # pragma: no cover

    monkeypatch.setattr(zabbix, "connect", refused)
    items = {
        "provider": "zabbix_mcp",
        "name": "item_get",
        "arguments": {"hostids": ["10101"]},
    }
    model = Model(
        lambda request: answer("", [Call("r1", "call_mcp_tool", items)]),
        lambda request: answer('{"cause": "仅凭 SSH"}'),
    )
    task, _ = run_alert(event_for("Linux: Load high", "71032", clock), model)
    caps = task["report"]["capabilities"]
    assert caps["zabbix_mcp"]["status"] == "unreachable"
    assert all("zabbix_mcp" not in enum for enum in provider_enums(model.requests[0]))
    assert "Zabbix MCP 不可用" in output_of(model.requests[1], "r1")["error"]
    assert {"tool": "item_get", "reason": "Zabbix MCP 不可用，未调用"} in task[
        "report"
    ]["coverage"]["skipped"]


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("CPU使用率过高", "cpu"),
        ("10.0.0.5的cpu为什么高", "cpu"),
        ("Nginx进程不存在", "nginx"),
        ("帮我看看nginx为啥502", "nginx"),
        ("tomcat进程挂了", "java"),
        ("JVM内存不足", "java"),
        ("PING不通", "unreachable"),
        ("磁盘空间不足 /data", "disk"),
        # Unchanged: words inside longer words are no match.
        ("upload failed", "bottleneck"),
        ("zoom meeting", "bottleneck"),
        ("High CPU utilization on web-01", "cpu"),
    ],
)
def test_classification_reads_words_next_to_chinese(text, kind):
    assert classify(text) == kind


def test_process_counts_of_nginx_classify_as_nginx():
    assert classify_keys(["proc.num[nginx,,,]"], "service")[0] == "nginx"
    assert classify_keys(["proc.num[,,,openresty]"], "bottleneck")[0] == "nginx"
    assert classify_keys(["proc.num[sshd]"], "bottleneck")[0] == "service"
