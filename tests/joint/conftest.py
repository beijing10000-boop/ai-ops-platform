"""Joint tests: the platform's own MCP clients against the real providers.

They run only when the provider checkouts are given (CI's joint job, or by
hand), each with the Python environment that has its requirements:

  AIOPS_JOINT_SSH_MCP_REPO / AIOPS_JOINT_SSH_MCP_PYTHON   ssh-mcp-server
  AIOPS_JOINT_LOG_MCP_REPO / AIOPS_JOINT_LOG_MCP_PYTHON   log-analysis-platform
  AIOPS_JOINT_CLICKHOUSE_URL (+ _USER, _PASSWORD, _DATABASE)  optional log store

Without a log store every log query fails; the SSH target is a local port
nothing listens on, so every diagnosis is refused at connect. Both are what
the tests then check: how the platform classifies and reports them.
"""

import os
import sys
from types import SimpleNamespace

import joint_providers as jp
import pytest
from joint_providers import NOT_READY, READY, WINDOWS


def _python(name):
    return os.environ.get(name) or sys.executable


@pytest.fixture(scope="session")
def ssh_env():
    repo = os.environ.get("AIOPS_JOINT_SSH_MCP_REPO")
    if not repo:
        pytest.skip("设置 AIOPS_JOINT_SSH_MCP_REPO 后运行 SSH MCP 联合测试")
    provider = jp.start("ssh", repo, _python("AIOPS_JOINT_SSH_MCP_PYTHON"))
    try:
        admin = provider.admin
        group = jp.created(admin.post("/groups", json={"name": "joint"}))["id"]
        credential = jp.created(
            admin.post(
                "/credentials",
                json={"name": "joint-key", "private_key": jp.private_key_pem()},
            )
        )["id"]
        address = jp.local_private_ip()
        port = jp.closed_port()

        def host(name, address, zabbix_hostid, **extra):
            body = {
                "name": name,
                "address": address,
                "port": port,
                "username": "joint",
                "zabbix_hostid": zabbix_hostid,
                "group_ids": [group],
                **extra,
            }
            return jp.created(admin.post("/hosts", json=body))["id"]

        ready = {"host_key": jp.host_public_key(), "credential_id": credential}
        hosts = {
            READY: host("joint-ready", address, READY, **ready),
            WINDOWS: host(
                "joint-windows", "10.255.255.11", WINDOWS, asset_type="windows"
            ),
            NOT_READY: host("joint-no-credential", "10.255.255.12", NOT_READY),
        }
        # The console refuses a second host with the same Zabbix Host ID; only
        # a Zabbix sync could leave duplicates, so they are not built here.
        duplicate = admin.post(
            "/hosts",
            json={"name": "joint-dup", "address": "10.255.255.13", "port": port,
                  "username": "joint", "zabbix_hostid": READY, "group_ids": [group]},
        )  # fmt: skip
        assert duplicate.status_code == 422, duplicate.text
        everything = sorted({entry["id"] for entry in jp.created(admin.get("/tools"))})

        def client(name, actions):
            body = {
                "name": name,
                "group_ids": [group],
                "actions": actions,
                "valid_days": 1,
            }
            return jp.created(admin.post("/mcp/clients", json=body))

        yield SimpleNamespace(
            provider=provider,
            repo=repo,
            address=address,
            hosts=hosts,
            actions=everything,
            full=client("joint-platform", everything),
            limited=client("joint-cpu-only", ["cpu"]),
            client=client,
        )
    finally:
        provider.stop()


@pytest.fixture(scope="session")
def log_env():
    repo = os.environ.get("AIOPS_JOINT_LOG_MCP_REPO")
    if not repo:
        pytest.skip("设置 AIOPS_JOINT_LOG_MCP_REPO 后运行日志 MCP 联合测试")
    store = os.environ.get("AIOPS_JOINT_CLICKHOUSE_URL")
    env = {
        "LOGMCP_MAINTENANCE": "false",
        "INGEST_TOKEN": "joint-ingest-token",
        # Port 9 on loopback refuses at once: "the log store is down".
        "CLICKHOUSE_URL": store or "http://127.0.0.1:9",
        "VECTOR_METRICS_URL": "http://127.0.0.1:9/metrics",
    }
    for name in ("USER", "PASSWORD", "DATABASE"):
        if os.environ.get("AIOPS_JOINT_CLICKHOUSE_" + name):
            env["CLICKHOUSE_" + name] = os.environ["AIOPS_JOINT_CLICKHOUSE_" + name]
    provider = jp.start("log", repo, _python("AIOPS_JOINT_LOG_MCP_PYTHON"), env)
    try:
        admin = provider.admin
        # Catalog, source list and target lookup come with every token.
        grantable = sorted(
            entry["name"]
            for entry in jp.created(admin.get("/mcp/tools"))
            if entry["kind"] != "meta"
        )

        def client(name, tools):
            body = {"name": name, "tools": tools, "valid_days": 1}
            return jp.created(admin.post("/mcp/clients", json=body))

        full = client("joint-platform", grantable)
        jp.warm_up_logs(provider.mcp_url, full["token"])
        yield SimpleNamespace(
            provider=provider,
            repo=repo,
            store=bool(store),
            grantable=grantable,
            full=full,
            overview_only=client("joint-overview-only", ["log_overview"]),
            client=client,
        )
    finally:
        provider.stop()
