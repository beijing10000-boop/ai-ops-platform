"""Regression tests for the remaining P2 findings on the diagnosis path (2026-11 audit).

Citation confidence only from checked quotes (OPS-SKILL-09); dates, times and
small integers no longer ground a quote (OPS-SKILL-10); platform Skills
replaced only by a newer template version (OPS-SKILL-11); a stored Skill that
no longer validates is skipped and shown, not fatal (OPS-SKILL-12); an alert
analysis whose Skills cannot load says why (OPS-SKILL-13); log sources found
by exact, unambiguous identities in turn (OPS-CORE-08); a failed analysis
round still ends in a summary, and prefetch has its own time cap (OPS-CORE-09).
"""

import asyncio
import base64
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

from cryptography.fernet import Fernet
import httpx
from openai import APIStatusError, APITimeoutError
import pytest

from app import evidence_check, main, mcp_runtime, operations, skill_runtime, worker
from app import skill_store as skills
from app.integrations import log_mcp, ssh_mcp, zabbix
from app.orchestrator import tasks
from test_acceptance_scenarios import (
    LINUX_HOST,
    SSH,
    Model,
    Zabbix,
    alert_clock,
    answer,
    event_for,
    item,
    prefetched,
    rig,
    run_alert,
    ssh_calls,
    step,
)
from test_log_mcp import CONFIG as LOG_CONFIG
from test_log_mcp import LogSession, analyze, text_reply, tool
from test_platform import client_for

P = "/api/v1/platform/skills"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


# --- OPS-SKILL-09: confidence only from checked quotes ---------------------------------

INDEX = {
    "E1": {
        "provider": "ssh_mcp",
        "tool": "ssh_diagnose_cpu",
        "text": json.dumps({"evidence_id": "E1", "data": {"load_1": 6.25}}),
    },
    "E2": {
        "provider": "zabbix_mcp",
        "tool": "item_get",
        "text": json.dumps(
            {
                "evidence_id": "E2",
                "records": [{"key_": "system.cpu.num", "lastvalue": "4"}],
            }
        ),
    },
    "E3": {
        "provider": "zabbix_mcp",
        "tool": "history_get",
        "text": json.dumps({"evidence_id": "E3", "records": [{"value": "12.4"}]}),
    },
}


def test_ids_that_exist_never_make_a_plain_text_answer_high():
    """Three existing ids from two sources used to rate 高 with no quote checked."""
    result = evidence_check.check("负载 6.25（E1），核数 4（E2），历史见 E3。", INDEX)
    assert result["method"] == "reference"
    assert [item["id"] for item in result["valid"]] == ["E1", "E2", "E3"]
    assert result["confidence"] == "中"
    assert "回答没有附原文摘录" in result["confidence_note"]
    text = evidence_check.render(result)
    assert text.splitlines()[1] == (
        "依据可信度：中（回答没有附原文摘录；平台只核对了证据编号存在且采集成功，"
        "可信度最高评为中）"
    )
    # Nothing valid stays 低.
    assert evidence_check.check("见 E9。", INDEX)["confidence"] == "低"


def test_a_json_answer_without_an_evidence_array_is_capped():
    answer = json.dumps(
        {"cause": "负载 6.25（E1），核数 4（E2），告警后 12.4（E3）", "action": ["x"]},
        ensure_ascii=False,
    )
    result = evidence_check.check(answer, INDEX)
    assert result["method"] == "reference" and result["confidence"] == "中"
    assert result["confidence_note"].startswith("回答没有 evidence 原文摘录")


def test_a_broken_answer_read_field_by_field_is_capped_and_says_so():
    """A comma lost inside the evidence array: only cause/action are salvaged,
    the quotes are gone, and the ids alone used to give 高."""
    answer = (
        '{"cause": "负载升高（E1），核数 4（E2）", "action": ["核对批处理"], '
        '"evidence": [{"id": "E1", "quote": "load_1 6.25"} {"id": "E3" "quote": "12.4"}]}'
    )
    parsed, how = evidence_check.parse_answer(answer)
    assert how == "salvaged" and "evidence" not in parsed
    result = evidence_check.check(answer, INDEX)
    assert result["method"] == "reference" and result["confidence"] == "中"
    assert result["confidence_note"].startswith("回答的 JSON 不完整")
    assert "JSON 不完整" in evidence_check.render(result)


def test_checked_quotes_still_reach_high():
    answer = json.dumps(
        {
            "cause": "负载高",
            "evidence": [
                {"id": "E1", "quote": "load_1 6.25"},
                {"id": "E2", "quote": "system.cpu.num"},
            ],
        }
    )
    result = evidence_check.check(answer, INDEX)
    assert result["method"] == "quote" and result["confidence"] == "高"
    assert "confidence_note" not in result
    assert evidence_check.parse_answer(answer)[1] == "json"
    assert evidence_check.parse_answer("纯文本") == (None, None)


# --- OPS-SKILL-10: times, dates and small integers do not ground a quote ----------------

HISTORY = {
    "provider": "zabbix_mcp",
    "tool": "history_get",
    "text": json.dumps(
        {
            "evidence_id": "E4",
            "series": [
                {
                    "itemid": "301",
                    "numeric_summary": {"value": {"min": 3.2, "avg": 4.75, "max": 6.3}},
                    "sample_records": [
                        {
                            "clock": "1793272341",
                            "value": "3.2",
                            "local_time": "2026-10-29 19:12:21",
                        },
                        {
                            "clock": "1793274921",
                            "value": "6.3",
                            "local_time": "2026-10-29 19:55:21",
                        },
                    ],
                    "state_counts": {"D": 2, "R": 6},
                }
            ],
        },
        ensure_ascii=False,
    ),
}


def quotes(*pairs, index=None):
    answer = json.dumps(
        {"cause": "x", "evidence": [{"id": i, "quote": q} for i, q in pairs]},
        ensure_ascii=False,
    )
    result = evidence_check.check(answer, index or {"E4": HISTORY})
    return [item["quote"] for item in result["valid"]]


def test_digits_of_a_timestamp_in_the_evidence_ground_nothing():
    # 12 and 55 occur only inside "19:12:21" / "19:55:21".
    assert quotes(("E4", "5xx 12 次"), ("E4", "等待 55 秒")) == []
    # A real measurement still counts.
    assert quotes(("E4", "最大 6.3"), ("E4", "均值 4.75")) == ["最大 6.3", "均值 4.75"]


def test_small_integers_alone_must_be_quoted_as_text():
    """ "D 状态 6 个" passed because some 6 was somewhere in the evidence (here
    the R count); a small number alone now needs the evidence's own text."""
    assert quotes(("E4", "D 状态 6 个")) == []
    assert quotes(("E4", "state_counts D 2")) == ["state_counts D 2"]


def test_a_quote_resting_on_a_time_alone_must_match_as_text():
    # Its digits all occur in the evidence's timestamps, which proved nothing.
    assert quotes(("E4", "19:55 发生告警")) == []
    # A moment copied as the evidence shows it, or a value next to a time,
    # still checks out: the time is not a number to look for.
    assert quotes(
        ("E4", "2026-10-29 19:55:21"),
        ("E4", "2026-10-29 20:01:00"),
        ("E4", "19:55:21 达到 6.3"),
    ) == ["2026-10-29 19:55:21", "19:55:21 达到 6.3"]


def test_derived_signal_numbers_stay_citable_under_the_same_rule():
    index = {"E5": {"provider": "zabbix_mcp", "tool": "history_get", "text": "{}"}}
    evidence_check.attach_signals(
        index,
        [{"evidence_id": "E5", "value": {"ratio": 2.5, "items": 7, "events": 14}}],
    )
    assert quotes(
        ("E5", "是基线的 2.5 倍"),
        ("E5", "触发 14 次"),
        ("E5", "7 个监控项"),
        index=index,
    ) == ["是基线的 2.5 倍", "触发 14 次"]


# --- OPS-SKILL-11: platform Skills only replaced by a newer template ------------------

# (template version, sha256 of the template's files with LF line ends). A
# failure here means a template changed: raise its platform-template-version
# comment, or containers keep the stored copy, then record the new pair.
TEMPLATE_LOCK = {
    "platform-base": (
        1,
        "14b5c28feb0a4e9d74975eb7307b586b63abc82fb352f708c20a087dc1117260",
    ),
    "platform-logs": (
        1,
        "a6a512616f8c73c26637d19a894d9580b3ee4ccd65f56a5a4848cd2242aa766b",
    ),
    "platform-linux": (
        1,
        "b790238d205aa5bec26dfbe966f68bccced25fa49c82bc83fcf9a6ca8887a58e",
    ),
    "platform-windows": (
        1,
        "e2fbb741c8dd44ece6ae17e388f668cfd28be9e925111c003d0a0346640f1738",
    ),
    "platform-network": (
        1,
        "dbef1983a9a494b850528afd7de5ca2ad93b45d55b047e18ac7b505552f7283e",
    ),
    "platform-service": (
        1,
        "45a16a64e09406d2d21b577240df62a78eebf0830e1d0c7a67ef790c89c76672",
    ),
    "platform-syslog": (
        1,
        "525578ff9584b3ec741d3a69425952d007f715e28da80081f658b8c93816681c",
    ),
    "platform-nginx": (
        1,
        "5c6711265e57e0328cfa56f18a14ed8bffdc3076cd60368a8b285cbed8151202",
    ),
    "platform-java": (
        1,
        "b7b116b0aa4a173950562896218ab71ecd1fb441a29881d02146d39d686820ef",
    ),
}


def test_every_platform_template_carries_a_version_raised_with_its_text():
    assert set(TEMPLATE_LOCK) == set(skills.MANAGED)
    for name, locked in TEMPLATE_LOCK.items():
        files = {
            path: text.replace("\r\n", "\n")
            for path, text in skills.template_files(name).items()
        }
        assert (skills.template_version(files), skills.digest(files)) == locked, name
    # The version is the platform's: the model never reads it.
    package = skills.managed_package("platform-base")
    assert "platform-template-version" not in package["instructions"]
    assert "platform-template-version" not in skills.skill_body(
        {"files": package["files"]}
    )


def stored_row(name):
    return next(row for row in skills.rows() if row["name"] == name)


def bundled(name, version, extra=""):
    """The package a container bundling `version` of a template would install."""
    files = dict(skills.managed_package(name)["files"])
    text = skills.TEMPLATE_VERSION.sub("", files["SKILL.md"]).rstrip() + "\n" + extra
    if version:
        text += f"\n<!-- platform-template-version: {version} -->\n"
    files["SKILL.md"] = text
    return {**skills.parse_document(text), "files": files}


def test_a_container_bundling_an_older_template_keeps_the_newer_copy(monkeypatch):
    """A web container still on the release's template and a worker patched
    in place used to overwrite each other on every task, bumping the revision."""
    original = skills.managed_package
    current = skills.template_version(original("platform-base")["files"])
    first = stored_row("platform-base")
    newer = bundled("platform-base", current + 1, "\n新版规则。\n")
    monkeypatch.setattr(
        skills,
        "managed_package",
        lambda name: newer if name == "platform-base" else original(name),
    )
    upgraded = stored_row("platform-base")
    assert upgraded["digest"] == skills.digest(newer["files"])
    assert upgraded["revision"] == first["revision"] + 1
    monkeypatch.setattr(skills, "managed_package", original)
    for _ in range(3):
        again = stored_row("platform-base")
        assert (again["digest"], again["revision"]) == (
            upgraded["digest"],
            upgraded["revision"],
        )
    assert "新版规则" in skills.get(upgraded["id"])["instructions"]


def test_a_copy_saved_before_template_versions_is_upgraded_once(monkeypatch):
    original = skills.managed_package
    legacy = bundled("platform-linux", 0)
    assert skills.template_version(legacy["files"]) == 0
    monkeypatch.setattr(
        skills,
        "managed_package",
        lambda name: legacy if name == "platform-linux" else original(name),
    )
    saved = stored_row("platform-linux")  # as v1.5.0 stored it: no version
    monkeypatch.setattr(skills, "managed_package", original)
    upgraded = stored_row("platform-linux")
    assert upgraded["digest"] == skills.digest(original("platform-linux")["files"])
    assert upgraded["revision"] == saved["revision"] + 1
    assert stored_row("platform-linux")["revision"] == upgraded["revision"]


def test_a_stored_platform_copy_this_version_cannot_read_is_replaced():
    """Even at a higher version: after a rollback the older release repairs a
    copy whose metadata it does not know, instead of losing the Skill."""
    stored_row("platform-java")
    text = (
        "---\nname: platform-java\ndescription: 下一版本\nfuture_key: 1\n---\n\n正文\n"
        "\n<!-- platform-template-version: 99 -->\n"
    )
    with main.connection() as db:
        db.execute(
            "UPDATE platform_skills SET bundle=?,digest='x' WHERE name='platform-java'",
            (skills.encode({"SKILL.md": text}),),
        )
    repaired = stored_row("platform-java")
    assert repaired["digest"] == skills.digest(
        skills.managed_package("platform-java")["files"]
    )
    assert "invalid" not in repaired


# --- OPS-SKILL-12: a stored Skill that no longer validates -----------------------------


def imported(client, name, body="按本环境规则分析。", **choices):
    text = f"---\nname: {name}\ndescription: {name} 的规则\n---\n\n{body}\n"
    response = client.post(
        P,
        json={
            "filename": name + ".md",
            "data": base64.b64encode(text.encode()).decode(),
            "enabled": True,
            "providers": ["zabbix_mcp"],
            "mode": "supplement",
            **choices,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def overwrite(name, bundle):
    with main.connection() as db:
        db.execute("UPDATE platform_skills SET bundle=? WHERE name=?", (bundle, name))


def test_one_skill_that_no_longer_validates_does_not_stop_everyone(caplog):
    """An upgrade that tightens validation used to make every task creation
    and Skill 管理 fail with 500 while the list still looked fine."""
    client = client_for()
    imported(client, "legacy-rules")
    imported(client, "other-key")
    # Stored by an earlier release with metadata this one rejects, and one
    # encrypted with another key.
    overwrite(
        "legacy-rules",
        skills.encode(
            {
                "SKILL.md": "---\nname: legacy-rules\ndescription: 旧\nretired: 1\n---\n\n旧正文\n"
            }
        ),
    )
    other = Fernet(Fernet.generate_key())
    overwrite(
        "other-key",
        other.encrypt(json.dumps({"SKILL.md": "x"}).encode()).decode(),
    )
    listing = {row["name"]: row for row in client.get(P).json()["items"]}
    assert listing["legacy-rules"]["invalid"].startswith("Skill 元数据只支持")
    assert listing["other-key"]["invalid"] == skills.UNREADABLE
    assert "invalid" not in listing["platform-base"]
    # Task snapshots leave them out and say so; the other Skills still load.
    names = [row["name"] for row in skills.snapshot({}, "web")]
    assert "legacy-rules" not in names and "other-key" not in names
    assert "platform-base" in names
    assert "SKILL_SKIPPED_INVALID name=legacy-rules" in caplog.text
    # An administrator sees why and can export or delete it; editing it
    # cannot fix its metadata, so that is refused with the way out.
    legacy = client.get(P + "/" + listing["legacy-rules"]["id"]).json()
    assert legacy["invalid"] and legacy["instructions"] == "旧正文"
    refused = client.put(P + "/" + legacy["id"], json={"enabled": False})
    assert refused.status_code == 409 and "更新同名 Skill" in refused.json()["detail"]
    assert client.get(P + "/" + legacy["id"] + "/export").status_code == 200
    assert (
        client.get(P + "/" + listing["other-key"]["id"] + "/export").status_code == 409
    )
    assert (
        client.delete(
            P + "/" + listing["other-key"]["id"] + "?confirm=true"
        ).status_code
        == 200
    )
    # Re-importing a corrected version replaces it.
    imported(client, "legacy-rules", "新正文", replace_existing=True)
    assert "invalid" not in stored_row("legacy-rules")


# --- OPS-SKILL-13: an alert analysis whose Skills cannot load says why ----------------


def test_an_alert_whose_skills_cannot_load_is_failed_with_the_reason(
    monkeypatch, caplog
):
    client = client_for()
    for n in range(3):  # three 43 KB supplements: over the 128 KB snapshot limit
        imported(client, f"bulky-{n}", "规则。" * 4800, scopes=["alert"])
    event = {
        "event_id": "880900",
        "event_value": "1",
        "severity": "4",
        "event_name": "Linux: Load average is too high",
        "host_id": "10913",
        "trigger_id": "71001",
        "host_name": "app-01",
    }
    with main.connection() as db:
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_name,host_name,"
            "severity,ai_status,event_json) VALUES (?,?,?,?,?,?,?)",
            (
                "880900",
                "1",
                event["event_name"],
                "app-01",
                4,
                "pending",
                json.dumps(event),
            ),
        )

    async def notify(card, event=None, **kwargs):
        return None

    monkeypatch.setattr(worker, "notify", notify)
    monkeypatch.setattr(
        worker, "cfg", lambda key: "4" if key == "ai_min_severity" else ""
    )
    result = asyncio.run(worker.handle_alert(event))
    assert result["ai_failed"] is True
    with main.connection() as db:
        status = db.execute(
            "SELECT ai_status FROM alert_events WHERE event_id='880900'"
        ).fetchone()[0]
    assert status == "failed"
    # The alert links to a failed analysis that says why and what to do.
    [row] = operations.alert_page()["items"]
    task = tasks.get(row["task_id"])
    assert task["status"] == "failed" and task["error_type"] == tasks.SNAPSHOT_FAILED
    answer = task["report"]["answer"]
    assert "128 KB" in answer and "Skill 管理" in answer and "AI分析" in answer
    assert f"SKILL_SNAPSHOT_FAILED event_id=880900 task_id={row['task_id']}" in (
        caplog.text
    )
    # The traceback is logged with the event.
    [record] = [
        r for r in caplog.records if "ALERT_ANALYSIS_ENQUEUE_FAILED" in r.getMessage()
    ]
    assert record.exc_info
    # Web diagnosis of the alert keeps answering 422 with the reason at once.
    web = client.post("/api/v1/platform/tasks", json={"event_id": "880900"})
    assert web.status_code == 422 and "128 KB" in web.json()["detail"]
    assert operations.alert_page()["items"][0]["task_id"] == row["task_id"]
    # Other failures name only their class, never internal detail.
    assert tasks.snapshot_failure(ValueError("Skill 名称无效")) == "Skill 名称无效"
    assert tasks.snapshot_failure(RuntimeError("内部细节")) == (
        "读取 Skill 时出错（RuntimeError）"
    )


# --- OPS-CORE-08: the log source by exact, unambiguous identities -------------------

DEVICE = {
    "hostid": "10500",
    "host": "core-switch-01",
    "name": "核心交换机",
    "parentTemplates": [{"templateid": "1", "name": "Huawei VRP by SNMP"}],
    "interfaces": [
        {"type": "2", "ip": "198.51.100.50", "main": "1"},
        {"type": "2", "ip": "198.51.100.51", "main": "0"},
    ],
}
LINK_DOWN = {
    "event_id": "880700",
    "event_name": "Interface GE0/0/1: Link down",
    "host_id": "10500",
    "trigger_id": "90001",
    "event_date": "2026.10.31",
    "event_time": "10:00:00",
}


class Sources(LogSession):
    """log_resolve_target by identity: `known` maps ("ip" | "hostname", value)
    to the host names of the sources found; anything else has no logs."""

    def __init__(self, known):
        super().__init__(types=("network",))
        self.known = known

    async def call_tool(self, name, args):
        if name != "log_resolve_target":
            return await super().call_tool(name, args)
        self.calls.append((name, args))
        [(kind, value)] = args.items()
        hosts = self.known.get((kind, value))
        if not hosts:
            return text_reply(
                {
                    "found": False,
                    "target": value,
                    "similar": [],
                    "hint": "最近 7 天没有来自该目标的日志",
                    "status": "success",
                }
            )
        return text_reply(
            {
                "found": True,
                "target": value,
                "matches": [
                    {
                        "host": host,
                        "ip": "10.0.0.9",
                        "types": ["network"],
                        "count_7d": 9,
                    }
                    for host in hosts
                ],
                "status": "success",
            }
        )

    def resolved(self):
        return [args for name, args in self.calls if name == "log_resolve_target"]

    def targets(self):
        return {
            args.get("target")
            for name, args in self.calls
            if name not in ("log_resolve_target", "log_list_tool_catalog")
        }


@pytest.fixture
def device_logs(monkeypatch):
    """A network device with two interface IPs, its log source per test."""
    config = {**LOG_CONFIG, "mcp_url": "http://zabbix.invalid/mcp"}
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))
    session = {}

    class ZabbixSession:
        async def list_tools(self):
            schema = {"output": {"type": "string"}, "extra_params": {"type": "object"}}
            return SimpleNamespace(
                tools=[tool(n, schema) for n in ("host_get", "item_get", "event_get")],
                nextCursor=None,
            )

        async def call_tool(self, name, args):
            rows = [DEVICE] if name == "host_get" else []
            return SimpleNamespace(
                structuredContent={"result": rows}, content=[], isError=False
            )

    @asynccontextmanager
    async def zabbix_connect(*args, **kwargs):
        yield ZabbixSession()

    @asynccontextmanager
    async def log_connect(*args, **kwargs):
        yield session["logs"]

    @asynccontextmanager
    async def no_ssh(*args, **kwargs):
        raise ssh_mcp.IntegrationError("SSH MCP 未启用")
        yield

    monkeypatch.setattr(zabbix, "connect", zabbix_connect)
    monkeypatch.setattr(log_mcp, "connect", log_connect)
    monkeypatch.setattr(ssh_mcp, "configured", no_ssh)

    def run(known):
        session["logs"] = sources = Sources(known)
        task, sent, _ = analyze(LINK_DOWN)
        return task, sent, sources

    return run


def test_several_sources_behind_one_ip_are_ambiguous_and_not_read(device_logs):
    task, sent, sources = device_logs({("ip", "198.51.100.50"): ["edge-a", "edge-b"]})
    state = sent["capabilities"]["logs"]
    assert state == {
        "status": "unavailable",
        "error_code": "ambiguous",
        "reason": "198.51.100.50 对应多个日志来源（edge-a、edge-b），"
        "无法确定哪个是目标主机，未合并读取",
    }
    # Neither the other identities nor any log tool: that source stops here.
    assert sources.resolved() == [{"ip": "198.51.100.50"}]
    assert sources.targets() == set()
    assert "platform-logs" not in sent["applied_skills"]
    assert task["status"] == "success" and task["report"]["limitations"] == []
    assert "日志 MCP不可用：198.51.100.50 对应多个日志来源" in task["report"]["answer"]


def test_one_host_sending_from_two_addresses_is_not_ambiguous(device_logs):
    _, sent, sources = device_logs(
        {("ip", "198.51.100.50"): ["core-switch-01", "CORE-SWITCH-01"]}
    )
    assert sent["capabilities"]["logs"]["target"] == "198.51.100.50"
    assert sources.targets() == {"198.51.100.50"}


def test_an_ip_without_logs_moves_on_to_the_next_ip(device_logs):
    task, sent, sources = device_logs({("ip", "198.51.100.51"): ["core-switch-01"]})
    assert sources.resolved() == [{"ip": "198.51.100.50"}, {"ip": "198.51.100.51"}]
    log_target = dict(sent["evidence"]["log_target"])
    assert log_target.pop("evidence_id")
    assert log_target == {
        "target": "198.51.100.51",
        "identity": "ip",
        "tried": ["198.51.100.50"],
        "source_types": ["network"],
    }
    assert sources.targets() == {"198.51.100.51"}
    report = task["report"]
    assert report["capabilities"]["logs"] == {
        "status": "used",
        "target": "198.51.100.51",
        "identity": "ip",
        "tried": ["198.51.100.50"],
    }
    assert (
        "日志来源按 IP 198.51.100.51 定位（198.51.100.50 最近 7 天没有日志）"
        in (report["answer"])
    )


def test_the_host_name_is_tried_last_and_named(device_logs):
    task, sent, sources = device_logs(
        {("hostname", "core-switch-01"): ["core-switch-01"]}
    )
    assert sources.resolved() == [
        {"ip": "198.51.100.50"},
        {"ip": "198.51.100.51"},
        {"hostname": "core-switch-01"},
    ]
    assert sources.targets() == {"core-switch-01"}
    logs = task["report"]["capabilities"]["logs"]
    assert (logs["identity"], logs["target"]) == ("hostname", "core-switch-01")
    assert (
        "日志来源按主机名 core-switch-01 定位"
        "（198.51.100.50、198.51.100.51 最近 7 天没有日志）"
    ) in task["report"]["answer"]
    assert "platform-logs" in sent["applied_skills"]


def test_no_identity_with_logs_lists_every_one_tried(device_logs):
    task, sent, sources = device_logs({})
    assert len(sources.resolved()) == 3 and sources.targets() == set()
    assert sent["capabilities"]["logs"] == {
        "status": "not_onboarded",
        "reason": "198.51.100.50、198.51.100.51、主机名 core-switch-01 "
        "最近 7 天没有来自该目标的日志",
    }
    assert task["status"] == "success"


# --- OPS-CORE-09: a failed analysis round still ends in a summary; prefetch's cap ----

CPU_ALERT = "Linux: Load average is too high"
REQUEST = httpx.Request("POST", "https://model.invalid/v1/responses")


def cpu_alert(clock):
    return Zabbix(
        LINUX_HOST,
        [item("201", "system.cpu.load[all,avg5]", 12.4)],
        [item("202", "system.cpu.util", 18.5)],
        [{"eventid": "880001", "clock": str(clock), "value": "1", "name": "load"}],
        {"201": step(clock, 3.0, 12.0), "202": step(clock, 15.0, 18.0)},
        {"201": (1.0, 2.5, 4.0), "202": (5.0, 15.0, 30.0)},
    )


def test_an_analysis_round_the_model_did_not_answer_still_ends_in_a_summary(
    monkeypatch,
):
    """It used to end in the evidence fallback: a list of tools, no conclusion."""
    clock = alert_clock()
    rig(monkeypatch, cpu_alert(clock), SSH({}))

    def times_out(request):
        raise APITimeoutError(request=REQUEST)

    def summary(request):
        history = prefetched(request, "history_get")[0]
        return answer(
            json.dumps(
                {
                    "cause": f"告警后负载升至 12（{history}）",
                    "action": ["核对批处理任务"],
                    "evidence": [{"id": history, "quote": "after avg 12"}],
                },
                ensure_ascii=False,
            )
        )

    model = Model(times_out, times_out, summary)
    task, _ = run_alert(event_for(CPU_ALERT, "71001", clock), model)
    # The round and its own retry timed out; then one summary round.
    assert len(model.requests) == 3
    last = model.requests[-1]
    assert last["tool_choice"] == "none"
    assert last["input"][-1]["content"] == skill_runtime.SUMMARY_TURN
    report = task["report"]
    assert report["answer"].startswith("诊断结论\n告警后负载升至 12")
    assert "模型未完成最终诊断" not in report["answer"]
    assert task["status"] == "partial" and report["model_error"] is None
    assert any(
        gap.startswith("AI 模型请求超时（第 1 轮），平台改为总结轮")
        for gap in report["limitations"]
    )


def test_a_rejected_model_request_is_not_repeated_as_a_summary(monkeypatch):
    clock = alert_clock()
    rig(monkeypatch, cpu_alert(clock), SSH({}))

    def rejected(request):
        raise APIStatusError(
            "bad", response=httpx.Response(400, request=REQUEST), body={}
        )

    model = Model(rejected)
    task, _ = run_alert(event_for(CPU_ALERT, "71001", clock), model)
    assert len(model.requests) == 1
    assert task["report"]["model_error"] == "ModelRequestError"


def test_a_slow_mcp_service_cannot_use_the_whole_task_time(monkeypatch):
    """A host_get the service sits on: its own 18 s timeout used to come
    first, then the rest of prefetch, before the model saw anything."""
    # Standard profile, 180 s: a 9 % share stops prefetch after about 16 s,
    # while the slow call is still waiting.
    monkeypatch.setattr(skill_runtime, "PREFETCH_SHARE", 0.09)
    clock = alert_clock()
    zbx = cpu_alert(clock)
    answered = zbx.call_tool

    async def call_tool(name, args):
        if name == "host_get":
            await asyncio.sleep(600)
        return await answered(name, args)

    zbx.call_tool = call_tool
    rig(monkeypatch, zbx, SSH({}))
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论"))
    )
    report = task["report"]
    assert {
        "tool": "host_get",
        "reason": skill_runtime.PREFETCH_LATE,
    } in report["coverage"]["skipped"]
    assert any(
        hit.startswith("预采集超过时间上限（16 秒") and "host_get" in hit
        for hit in report["budget"]["limits_hit"]
    )
    # Not a failed collection (no gap); what answered in time stays and the
    # model ran with the time left.
    assert not any(e["tool"] == "host_get" for e in report["coverage"]["failed"])
    assert "item_get" in report["coverage"]["collected"]
    assert report["budget"]["used"]["rounds"] >= 1


def test_ssh_time_budget_ends_before_the_prefetch_cap(monkeypatch):
    clock = alert_clock()
    ssh = SSH({})
    listed = ssh.list_tools

    async def list_tools():
        result = await listed()
        for remote in result.tools:
            if remote.name == "ssh_collect":
                remote.inputSchema["properties"]["timeout_seconds"] = {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 120,
                }
        return result

    ssh.list_tools = list_tools
    rig(monkeypatch, cpu_alert(clock), ssh)
    base = mcp_runtime.read_setting
    monkeypatch.setattr(
        mcp_runtime,
        "read_setting",
        lambda key: "120" if key == "ssh_mcp_timeout_seconds" else base(key),
    )
    run_alert(event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论")))
    bundle = next(args for name, args in ssh_calls(ssh) if name == "ssh_collect")
    # Standard: 180 s, prefetch at most 90 s: answered ~10 s before that (was 110 s).
    assert 10 <= bundle["timeout_seconds"] <= 80
