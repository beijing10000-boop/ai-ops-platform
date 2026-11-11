"""Regression tests for the remaining P2 findings on the diagnosis path (2026-11 audit).

Citation confidence only from checked quotes (OPS-SKILL-09); dates, times and
small integers no longer ground a quote (OPS-SKILL-10); platform Skills
replaced only by a newer template version (OPS-SKILL-11); a stored Skill that
no longer validates is skipped and shown, not fatal (OPS-SKILL-12); an alert
analysis whose Skills cannot load says why (OPS-SKILL-13); log sources found
by exact, unambiguous identities in turn (OPS-CORE-08); a failed analysis
round still ends in a summary, and prefetch has its own time cap (OPS-CORE-09).

The independent review of these fixes found: correct quotes of small values
and states rejected while wrong small counts and times next to a large value
passed, two "status: success" quotes reaching 高; versioned containers taking
turns rewriting a template one of them could not read; prefetch's cap
abandoning SSH diagnostics the server keeps running and leaving a session
without tools; one log source called two (a sender IP as host name, FQDN and
short name) and a host name from foreign addresses called one. Each case of
the review is a test below.
"""

import asyncio
import base64
from contextlib import asynccontextmanager
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

from cryptography.fernet import Fernet
import httpx
from openai import APIStatusError, APITimeoutError
import pytest

from app import evidence_check, main, mcp_runtime, operations, skill_runtime, worker
from app import skill_store as skills
from app.diagnostics import playbooks
from app.integrations import log_mcp, ssh_mcp, zabbix
from app.orchestrator import tasks
from app.skill_mcp import SkillMCP, clear_catalog_cache
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
from test_log_mcp import Call, LogSession, analyze, response, text_reply, tool
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
    assert [item["basis"] for item in result["valid"]] == ["number", "text"]
    assert evidence_check.parse_answer(answer)[1] == "json"
    assert evidence_check.parse_answer("纯文本") == (None, None)


# Review (cmp_high.py): quotes that prove nothing used to reach 高.
ENVELOPES = {
    "E1": {
        "provider": "ssh_mcp",
        "tool": "ssh_diagnose_cpu",
        "text": json.dumps(
            {"evidence_id": "E1", "status": "success", "data": {"load_1": 1.2}}
        ),
    },
    "E2": {
        "provider": "zabbix_mcp",
        "tool": "item_get",
        "text": json.dumps(
            {
                "evidence_id": "E2",
                "status": "success",
                "records": [{"key_": "system.cpu.load", "lastvalue": "1.1"}],
            }
        ),
    },
}


def test_status_success_quotes_do_not_prove_a_contradicted_conclusion():
    answer = json.dumps(
        {
            "cause": "负载 38.5（E1），远超核数（E2）",
            "evidence": [
                {"id": "E1", "quote": "status: success"},
                {"id": "E2", "quote": "status: success"},
            ],
            "findings": {"confirmed": [{"statement": "负载 38.5", "evidence": ["E1"]}]},
        },
        ensure_ascii=False,
    )
    result = evidence_check.check(answer, ENVELOPES)
    # At most 中; here 低, since neither quote checks out.
    assert result["confidence"] == "低" and result["valid"] == []
    assert [item["reason"] for item in result["invalid"]] == [
        evidence_check.GENERIC
    ] * 2
    assert result["facts"]["counts"]["demoted"] == 1
    # A key name alone is no quote either.
    assert quotes(("E1", "load_1"), index=ENVELOPES) == []


def test_text_quotes_alone_reach_medium_at_most():
    """Two text quotes from two sources match real values, but no number was
    checked: 中, and the report says why."""
    index = {
        "E1": {
            "provider": "ssh_mcp",
            "tool": "ssh_diagnose_service_detail",
            "text": json.dumps(
                {"data": {"unit": "nginx.service", "result": "oom-kill"}},
            ),
        },
        "E2": {
            "provider": "logs",
            "tool": "log_search",
            "text": json.dumps(
                {"data": {"lines": ["Out of memory: Killed process java"]}},
            ),
        },
    }
    answer = json.dumps(
        {
            "cause": "x",
            "evidence": [
                {"id": "E1", "quote": "result oom-kill"},
                {"id": "E2", "quote": "Killed process java"},
            ],
        }
    )
    result = evidence_check.check(answer, index)
    assert [item["basis"] for item in result["valid"]] == ["text", "text"]
    assert result["confidence"] == "中"
    assert result["confidence_note"] == evidence_check.NO_NUMBER
    assert evidence_check.NO_NUMBER in evidence_check.render(result)


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


def test_small_integers_must_name_their_field():
    """ "D 状态 6 个" passed because some 6 was somewhere in the evidence (here
    the R count); a small number is now compared with the field it names."""
    assert quotes(("E4", "D 状态 6 个")) == []
    assert quotes(("E4", "state_counts D 2"), ("E4", "D 状态 2 个")) == [
        "state_counts D 2",
        "D 状态 2 个",
    ]


def test_a_quote_resting_on_a_time_alone_must_match_as_text():
    # Its digits all occur in the evidence's timestamps, which proved nothing.
    assert quotes(("E4", "19:55 发生告警")) == []
    # A moment as the evidence shows it, or a value next to a time, still
    # checks out: the time is compared as a time, not as numbers.
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
        # Named: the signal's own field.
        ("E5", "7 个监控项"),
        # Named, but that field holds 14; and a bare 7.
        ("E5", "7 个事件"),
        ("E5", "7"),
        index=index,
    ) == ["是基线的 2.5 倍", "触发 14 次", "7 个监控项"]


# The review's quotes (cmp_quotes.py) against the evidence they were written
# for: correct small values with their field pass, a bare small number does
# not; a wrong small count, time or date next to a correct large value fails.
REVIEWED = {
    "cpu": {
        "evidence_id": "E1",
        "data": {
            "cpu_count": 4,
            "load_1": 12.4,
            "load_5": 9.87,
            "idle_pct": 3.2,
            "iowait_pct": 45.3,
            "state_counts": {"R": 5, "D": 2, "S": 312},
            "captured_at": "2026-10-29 19:12:21",
        },
    },
    "ports": {
        "evidence_id": "E2",
        "data": {
            "listen": [{"local": "0.0.0.0:8080", "process": "java"}, {"local": "*:22"}]
        },
    },
    "mem": {
        "evidence_id": "E3",
        "data": {"mem_total_gib": 7.62, "mem_available_gib": 0.42},
    },
    "disk": {
        "evidence_id": "E4",
        "records": [{"key_": "vfs.fs.size[/,pused]", "lastvalue": "95.3"}],
    },
    "version": {
        "evidence_id": "E5",
        "data": {"server": "nginx/1.24.0", "agent": "zabbix_agent 6.0.25"},
    },
    "logs": {"evidence_id": "E6", "data": {"errors": 1234, "previous": 56}},
    "proc": {
        "evidence_id": "E7",
        "data": {"processes": [{"pid": 4242, "comm": "java", "pcpu": 380.5}]},
    },
    "loss": {
        "evidence_id": "E8",
        "records": [{"key_": "icmppingloss", "lastvalue": "0"}],
    },
    "svc": {
        "evidence_id": "E9",
        "data": {"unit": "nginx.service", "restarts": 3, "result": "oom-kill"},
    },
}
REVIEWED_QUOTES = [
    ("cpu", "load_1 12.4", True),
    ("cpu", "4", False),
    ("cpu", "CPU 核数 4", True),
    ("cpu", "cpu_count 4", True),
    ("cpu", "空闲 3%", True),
    ("cpu", "idle 3.2", True),
    ("cpu", "D 状态 2 个", True),
    ("cpu", '"D": 2', True),
    ("cpu", "load 12.4，D 状态进程 6 个", False),
    ("cpu", "19:55 负载 12.4", False),
    ("cpu", "2026-10-30 负载 12.4", False),
    ("ports", "8080 端口监听", True),
    ("ports", "端口 22", True),
    ("mem", "可用 0.42 GiB", True),
    ("mem", "总内存 8 GiB", True),
    ("disk", "使用率 95%", True),
    ("disk", "95.3%", True),
    ("version", "nginx/1.24.0", True),
    ("version", "zabbix agent 6.0", True),
    ("logs", "错误 1234 条", True),
    ("logs", "上一窗口 56 条", True),
    ("proc", "java PID 4242 CPU 380.5%", True),
    ("loss", "丢包率 0%", True),
    ("loss", "0", False),
    ("svc", "重启 3 次", True),
    ("svc", "restarts 3", True),
    ("svc", "result oom-kill", True),
    # Beyond the review's list: the same names with a wrong value, a pid
    # alone, the time the evidence was taken, numbers written without spaces.
    ("cpu", "D 状态 6 个", False),
    ("cpu", "6 个 D 状态进程", False),
    ("cpu", "19:12 负载 12.4", True),
    ("mem", "可用 8 GiB", False),
    ("proc", "PID 4242", False),
    ("loss", "丢包率 1%", False),
    ("svc", "重启3次", True),
    ("svc", "restarts 4", False),
]


@pytest.mark.parametrize("key, quote, valid", REVIEWED_QUOTES)
def test_reviewed_quotes(key, quote, valid):
    index = {
        "E1": {
            "provider": "ssh_mcp",
            "tool": key,
            "text": json.dumps(REVIEWED[key], ensure_ascii=False),
        }
    }
    assert quotes(("E1", quote), index=index) == ([quote] if valid else [])


def reasons(*pairs, index):
    answer = json.dumps(
        {"cause": "x", "evidence": [{"id": i, "quote": q} for i, q in pairs]},
        ensure_ascii=False,
    )
    return [item["reason"] for item in evidence_check.check(answer, index)["invalid"]]


def test_rejections_say_what_is_wrong():
    index = {
        "E1": {
            "provider": "ssh_mcp",
            "tool": "ssh_diagnose_cpu",
            "text": json.dumps(REVIEWED["cpu"], ensure_ascii=False),
        }
    }
    assert reasons(
        ("E1", "4"),
        ("E1", "19:55 负载 12.4"),
        ("E1", "load 12.4，D 状态进程 6 个"),
        ("E1", "load_1"),
        index=index,
    ) == [
        evidence_check.UNNAMED,
        evidence_check.WRONG_MOMENT,
        evidence_check.MISMATCH,
        evidence_check.GENERIC,
    ]


# The review's availability evidence (cmp_state.py): item_get as prefetch asks
# for it, and a state-change signal of a history query.
AVAILABILITY = {
    "evidence_id": "E2",
    "records": [
        {
            "itemid": "45120",
            "name": "Zabbix agent ping",
            "key_": "agent.ping",
            "value_type": "3",
            "units": "",
            "lastvalue": "0",
            "lastclock": "1793274921",
        },
        {
            "itemid": "45121",
            "name": "Number of CPUs",
            "key_": "system.cpu.num",
            "value_type": "3",
            "units": "",
            "lastvalue": "8",
            "lastclock": "1793274921",
        },
    ],
    "total_records": 2,
}


def availability():
    index = {
        "E2": {
            "provider": "zabbix_mcp",
            "tool": "item_get",
            "text": json.dumps(AVAILABILITY),
        },
        "E3": {
            "provider": "zabbix_mcp",
            "tool": "history_get",
            "text": json.dumps({"evidence_id": "E3", "records": []}),
        },
    }
    evidence_check.attach_signals(
        index,
        [
            {
                "evidence_id": "E3",
                "value": {
                    "itemid": "45120",
                    "key": "icmpping",
                    "changes": 2,
                    "latest": 0,
                    "latest_at": "2026-10-29 19:55:21",
                    "last_change": {
                        "from": 1,
                        "to": 0,
                        "local_time": "2026-10-29 19:55:21",
                    },
                },
            }
        ],
    )
    return index


def test_states_are_checked_against_the_item_or_field_they_name():
    index = availability()
    assert quotes(
        ("E2", "agent.ping 0"),
        ("E2", "agent.ping lastvalue 0"),
        ("E2", "system.cpu.num 8"),
        ("E3", "changes 2"),
        ("E3", "latest 0"),
        # The platform's own hint, and the clock of the item in Beijing time.
        ("E3", "19:55:21 由 1 变为 0"),
        ("E2", "lastclock 2026-10-29 19:55:21"),
        index=index,
    ) == [
        "agent.ping 0",
        "agent.ping lastvalue 0",
        "system.cpu.num 8",
        "changes 2",
        "latest 0",
        "19:55:21 由 1 变为 0",
        "lastclock 2026-10-29 19:55:21",
    ]
    # Wrong values for the same names, a value column that names no item, the
    # row's value_type (3) taken for agent.ping, a bare 0.
    assert (
        quotes(
            ("E2", "agent.ping 1"),
            ("E2", "system.cpu.num 4"),
            ("E2", '"lastvalue": "0"'),
            ("E2", "agent.ping 3"),
            ("E3", "changes 3"),
            ("E3", "0"),
            index=index,
        )
        == []
    )


def test_a_mixed_quote_needs_every_number_and_moment():
    """A correct large value used to carry a wrong small count and a wrong time
    along (cmp_high.py): every number and moment of the quote must be found."""
    assert quotes(("E1", "08:15 load_1 1.2，D 状态 7 个"), index=ENVELOPES) == []
    assert quotes(("E1", "load_1 1.2"), index=ENVELOPES) == ["load_1 1.2"]
    # A timestamp with its zone is compared in Beijing time.
    index = {
        "E1": {
            "provider": "logs",
            "tool": "log_search",
            "text": json.dumps({"lines": [{"ts": "2026-10-29T11:12:21Z", "n": 37}]}),
        }
    }
    assert quotes(
        ("E1", "19:12:21 出现 37 次"), ("E1", "11:12:21 出现 37 次"), index=index
    ) == ["19:12:21 出现 37 次", "11:12:21 出现 37 次"]
    assert quotes(("E1", "19:13 出现 37 次"), index=index) == []


# --- OPS-SKILL-11: platform Skills only replaced by a newer template ------------------

# (template version, sha256 of the template's files with LF line ends). A
# failure here means a template changed: raise its platform-template-version
# comment, or containers keep the stored copy, then record the new pair.
TEMPLATE_LOCK = {
    "platform-base": (
        2,
        "57e30766d04ed4a957f943c18736bac0c83d787f45e79ff33ec6bbb657d0f689",
    ),
    "platform-logs": (
        4,
        "490d5c83b84469181b81855c61d2da24d113c2ad29d029f9bb93c0c6c3b11040",
    ),
    "platform-linux": (
        2,
        "b7e122ec4407bda4b50294812dcf3f43041249f4fef1f76e07412e6915c2a7a4",
    ),
    "platform-windows": (
        1,
        "e2fbb741c8dd44ece6ae17e388f668cfd28be9e925111c003d0a0346640f1738",
    ),
    "platform-network": (
        2,
        "ce54d4efab39b4ab2410cea044b82fd978f8e77da780a3057dd68a45a42c5bae",
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
        2,
        "6470b9bb56a27ca718eed6c6b5efb299e7934340e34782d60b708d63feb4750f",
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


def test_platform_logs_says_how_the_log_source_is_found():
    """It said the source is found by the alert IP alone."""
    package = skills.managed_package("platform-logs")
    text = package["instructions"]
    assert "Zabbix 主机名" in text and "`identity`" in text and "`tried`" in text
    assert "完整域名与短名" in text and "`ambiguous`" in text
    assert "IP 与主机名" in package["description"]


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


def tamper(name, bundle):
    """A stored platform copy other than the bundled one."""
    with main.connection() as db:
        db.execute(
            "UPDATE platform_skills SET bundle=?,digest='x' WHERE name=?",
            (bundle, name),
        )


def stored_bundle(name):
    with main.connection() as db:
        row = db.execute(
            "SELECT bundle,revision FROM platform_skills WHERE name=?", (name,)
        ).fetchone()
    return skills.decode(row[0]), row[1]


def test_a_newer_copy_this_release_cannot_read_is_kept_and_not_used(
    monkeypatch, caplog
):
    """After a rollback, or next to a newer container: the copy a newer release
    stored with metadata this one does not know stays in the database for
    that release; this process loads its own bundled template instead, and
    says so once."""
    monkeypatch.setattr(skills, "_LOGGED", set())
    first = stored_row("platform-java")
    text = (
        "---\nname: platform-java\ndescription: 下一版本\nfuture_key: 1\n---\n\n正文\n"
        "\n<!-- platform-template-version: 99 -->\n"
    )
    tamper("platform-java", skills.encode({"SKILL.md": text}))
    bundled_files = skills.managed_package("platform-java")["files"]
    for _ in range(3):
        served = stored_row("platform-java")
        assert served["digest"] == skills.digest(bundled_files)
        assert "invalid" not in served and served["revision"] == first["revision"]
    assert stored_bundle("platform-java") == ({"SKILL.md": text}, first["revision"])
    loaded = next(
        row for row in skills.snapshot({}, "web") if row["name"] == "platform-java"
    )
    assert loaded["files"] == bundled_files
    assert (
        loaded["instructions"]
        == skills.managed_package("platform-java")["instructions"]
    )
    assert caplog.text.count("PLATFORM_SKILL_NEWER_UNREADABLE name=platform-java") == 1


def test_an_unreadable_platform_copy_is_repaired_in_the_database():
    first = stored_row("platform-java")
    bundled_files = skills.managed_package("platform-java")["files"]
    broken = [
        # Encrypted with another key, without SKILL.md, and rejected by this
        # release at a version not above its own.
        Fernet(Fernet.generate_key())
        .encrypt(json.dumps({"SKILL.md": "x"}).encode())
        .decode(),
        skills.encode({"references/notes.md": "x"}),
        skills.encode(
            {
                "SKILL.md": "---\nname: platform-java\ndescription: x\nfuture_key: 1\n"
                "---\n\n正文\n\n<!-- platform-template-version: 1 -->\n"
            }
        ),
    ]
    for count, bundle in enumerate(broken, 1):
        tamper("platform-java", bundle)
        repaired = stored_row("platform-java")
        assert repaired["digest"] == skills.digest(bundled_files)
        assert repaired["revision"] == first["revision"] + count
        assert stored_bundle("platform-java")[0] == bundled_files


def test_versioned_containers_no_longer_take_turns(monkeypatch, caplog):
    """The review's rolling upgrade: container B's platform-linux v2 adds a
    prefetch rule for a diagnostic type container A does not know. A used to
    "repair" it on every read and B to upgrade it again, the revision
    climbing with each read (1, 2, 3 ... 7 in three rounds)."""
    monkeypatch.setattr(skills, "_LOGGED", set())
    original_package = skills.managed_package
    original_playbooks = dict(playbooks.PLAYBOOKS)
    base = original_package("platform-linux")["files"]["SKILL.md"]
    version = skills.template_version({"SKILL.md": base})
    newer = skills.TEMPLATE_VERSION.sub(
        f"<!-- platform-template-version: {version + 1} -->",
        base.replace(
            "prefetch:\n",
            "prefetch:\n- scopes: [alert]\n  types: [database]\n"
            "  ssh: [ssh_diagnose_processes]\n",
            1,
        ),
    )

    def as_b():
        monkeypatch.setattr(
            playbooks,
            "PLAYBOOKS",
            {**original_playbooks, "database": original_playbooks["cpu"]},
        )
        skills._checked.cache_clear()
        package = {
            **skills.parse_document(newer),
            "files": {**original_package("platform-linux")["files"], "SKILL.md": newer},
        }
        monkeypatch.setattr(
            skills,
            "managed_package",
            lambda name: (
                package if name == "platform-linux" else original_package(name)
            ),
        )

    def as_a():
        monkeypatch.setattr(playbooks, "PLAYBOOKS", original_playbooks)
        skills._checked.cache_clear()
        monkeypatch.setattr(skills, "managed_package", original_package)

    as_a()
    first = stored_row("platform-linux")
    as_b()
    upgraded = stored_row("platform-linux")
    assert upgraded["revision"] == first["revision"] + 1
    for _ in range(3):
        as_a()
        seen = stored_row("platform-linux")
        assert seen["revision"] == upgraded["revision"] and "invalid" not in seen
        assert seen["digest"] == skills.digest(
            original_package("platform-linux")["files"]
        )
        as_b()
        assert stored_row("platform-linux")["revision"] == upgraded["revision"]
    assert stored_bundle("platform-linux")[0]["SKILL.md"] == newer
    as_a()
    loaded = next(
        row for row in skills.snapshot({}, "web") if row["name"] == "platform-linux"
    )
    assert loaded["files"]["SKILL.md"] == base
    assert caplog.text.count("PLATFORM_SKILL_NEWER_UNREADABLE name=platform-linux") == 1


def test_a_template_changed_without_its_version_is_logged_once(monkeypatch, caplog):
    """Every rows() call used to log PLATFORM_SKILL_VERSION_UNCHANGED."""
    monkeypatch.setattr(skills, "_LOGGED", set())
    original = skills.managed_package
    version = skills.template_version(original("platform-base")["files"])
    other = bundled("platform-base", version, "\n另一份同版本的规则。\n")
    monkeypatch.setattr(
        skills,
        "managed_package",
        lambda name: other if name == "platform-base" else original(name),
    )
    stored_row("platform-base")
    monkeypatch.setattr(skills, "managed_package", original)
    for _ in range(3):
        assert stored_row("platform-base")["digest"] == skills.digest(other["files"])
    assert caplog.text.count("PLATFORM_SKILL_VERSION_UNCHANGED name=platform-base") == 1


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


def test_a_skill_that_fails_validation_covers_no_scope(monkeypatch):
    """The coverage check counted a Skill new tasks never load: switching
    platform-base off left a scope with nothing that loads, unasked, and
    the failed task blamed the disabled base Skill alone."""
    client = client_for()
    imported(client, "legacy-rules", scopes=["qa"])
    overwrite(
        "legacy-rules",
        skills.encode(
            {
                "SKILL.md": "---\nname: legacy-rules\ndescription: 旧\nretired: 1\n---\n\n旧正文\n"
            }
        ),
    )
    base = stored_row("platform-base")
    refused = client.put(P + "/" + base["id"], json={"scopes": ["web", "alert"]})
    assert refused.status_code == 409
    assert refused.json()["detail"]["scopes"] == ["qa"]
    confirmed = client.put(
        P + "/" + base["id"], json={"scopes": ["web", "alert"], "confirm": True}
    )
    assert confirmed.status_code == 200
    assert skills.uncovered(client.get(P).json()["items"]) == ["qa"]
    # A question in that scope fails and says which Skills did not load.
    monkeypatch.setattr(
        mcp_runtime,
        "read_setting",
        lambda key: "fixture" if key == "openai_model" else "",
    )
    create = AsyncMock()
    reply, usage = asyncio.run(
        mcp_runtime.run(
            "report",
            "CPU 为什么高",
            client=SimpleNamespace(responses=SimpleNamespace(create=create)),
            return_usage=True,
        )
    )
    task = tasks.get(usage["task_id"])
    assert task["status"] == "failed" and task["error_type"] == "NoSkillEnabled"
    assert not create.called
    assert "legacy-rules" in reply and "未通过当前版本的校验" in reply
    assert "也已停用" not in reply and task["report"]["answer"] == reply
    # Deleting the broken Skill takes no coverage away: no confirmation asked.
    legacy = next(
        row for row in client.get(P).json()["items"] if row["name"] == "legacy-rules"
    )
    assert client.delete(P + "/" + legacy["id"]).status_code == 200


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
    """log_resolve_target as the log platform answers it (GROUP BY host,
    sender IP): `known` maps ("ip" | "hostname", value) to its rows, each a
    host name sent from the IP looked up (from 10.0.0.9 for a host name) or a
    (host, sender IP) pair; anything else has no logs. `flagged`: the log
    platform v0.2.0 also says `ambiguous` (more than one row) and `relayed`."""

    def __init__(self, known, flagged=True, slow_first_listing=False):
        super().__init__(types=("network",))
        self.known, self.flagged = known, flagged
        self.listings, self.slow_first_listing = 0, slow_first_listing

    async def list_tools(self, cursor=None):
        self.listings += 1
        if self.slow_first_listing and self.listings == 1:
            # Never answers: prefetch's time cap cuts the session's opening.
            await asyncio.sleep(3600)
        return await super().list_tools(cursor)

    async def call_tool(self, name, args):
        if name != "log_resolve_target":
            return await super().call_tool(name, args)
        self.calls.append((name, args))
        [(kind, value)] = args.items()
        rows = [
            (row, value if kind == "ip" else "10.0.0.9")
            if isinstance(row, str)
            else row
            for row in self.known.get((kind, value)) or []
        ]
        if not rows:
            return text_reply(
                {
                    "found": False,
                    "target": value,
                    "similar": [],
                    "hint": "最近 7 天没有来自该目标的日志",
                    "status": "success",
                }
            )
        relayed = self.flagged and kind == "ip"
        return text_reply(
            {
                "found": True,
                "target": value,
                "matches": [
                    {
                        "host": host,
                        "ip": ip,
                        "types": ["network"],
                        "count_7d": 9,
                        **({"relayed": True} if relayed and ip != value else {}),
                    }
                    for host, ip in rows
                ],
                **({"ambiguous": len(rows) > 1} if self.flagged else {}),
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

    def run(known, *replies, **options):
        clear_catalog_cache()
        session["logs"] = sources = Sources(known, **options)
        task, sent, create = analyze(LINK_DOWN, *replies)
        sources.create = create
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


def test_one_host_whose_name_differs_only_in_case_is_not_ambiguous(device_logs):
    """Both rows come from the IP looked up; only the case of the name differs
    (this test once claimed to cover "two addresses")."""
    _, sent, sources = device_logs(
        {("ip", "198.51.100.50"): ["core-switch-01", "CORE-SWITCH-01"]}
    )
    assert sent["capabilities"]["logs"]["target"] == "198.51.100.50"
    assert sources.targets() == {"198.51.100.50"}


def test_rows_the_sender_ip_names_are_that_sender_not_another_source(device_logs):
    """The log platform writes the sender IP as host of a message without a
    host name: the device's own other messages. The review's repro called
    this one device ambiguous and read no logs."""
    task, sent, sources = device_logs(
        {("ip", "198.51.100.50"): ["core-switch-01", "198.51.100.50"]}
    )
    state = sent["capabilities"]["logs"]
    assert (state["status"], state["target"]) == ("available", "198.51.100.50")
    assert sources.targets() == {"198.51.100.50"}
    assert task["report"]["capabilities"]["logs"]["status"] == "used"


def test_a_host_name_sent_from_foreign_addresses_is_ambiguous(device_logs):
    """By host name, two senders that are not this device's interfaces are two
    machines with one name; the review's repro merged them."""
    _, sent, sources = device_logs(
        {
            ("hostname", "core-switch-01"): [
                ("core-switch-01", "10.0.0.8"),
                ("core-switch-01", "10.0.0.9"),
            ]
        }
    )
    assert sent["capabilities"]["logs"] == {
        "status": "unavailable",
        "error_code": "ambiguous",
        "reason": "主机名 core-switch-01 对应多个日志来源（core-switch-01（10.0.0.8）、"
        "core-switch-01（10.0.0.9）），无法确定哪个是目标主机，未合并读取",
    }
    assert sources.targets() == set()


INTERFACES = {"198.51.100.50", "198.51.100.51"}


def sources_of(kind, value, rows, flagged=True):
    """log_sources() for an answer as Sources gives it."""
    matches = [
        {
            "host": host,
            "ip": ip,
            **({"relayed": True} if flagged and ip != value and kind == "ip" else {}),
        }
        for host, ip in rows
    ]
    data = {"found": True, "target": value, "matches": matches}
    if flagged:
        data["ambiguous"] = len(rows) > 1
    return skill_runtime.log_sources(kind, value, data, INTERFACES)


def test_which_answers_name_one_source():
    ip = "198.51.100.50"
    # One machine: a fully qualified name and its short form, a case
    # difference, the sender's rows without a host name next to its named ones.
    assert sources_of(
        "ip", ip, [("core-sw-01", ip), ("core-sw-01.example.net", ip)]
    ) == (False, ["core-sw-01", "core-sw-01.example.net"])
    assert not sources_of("ip", ip, [("core-sw-01", ip), ("CORE-SW-01", ip)])[0]
    assert not sources_of("ip", ip, [("core-sw-01", ip), ("", ip), (ip, ip)])[0]
    # Two machines behind one address (NAT), and two FQDNs of other domains.
    assert sources_of("ip", ip, [("edge-a", ip), ("edge-b", ip)])[0]
    assert sources_of("ip", ip, [("app.a.example", ip), ("app.b.example", ip)])[0]
    # A device a relay forwards names itself by the IP: one relay is the
    # source (log platform v0.2.0), two relays are not one source.
    assert sources_of("ip", ip, [(ip, "10.0.0.8")]) == (False, [f"{ip}（10.0.0.8）"])
    assert sources_of("ip", ip, [(ip, "10.0.0.8"), (ip, "10.0.0.9")])[0]
    # By host name: senders that are all this host's interfaces are one
    # device (a log platform without `ambiguous`), foreign ones are not, and
    # the platform's own `ambiguous` is honored.
    both = [("core-sw-01", "198.51.100.50"), ("core-sw-01", "198.51.100.51")]
    assert not sources_of("hostname", "core-sw-01", both, flagged=False)[0]
    assert sources_of("hostname", "core-sw-01", both)[0]
    foreign = [("core-sw-01", "198.51.100.50"), ("core-sw-01", "10.0.0.9")]
    assert sources_of("hostname", "core-sw-01", foreign, flagged=False)[0]
    assert not sources_of("hostname", "core-sw-01", [("core-sw-01", "10.0.0.9")])[0]


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
    # The cap fired before stage B: SSH was cut short, not "authorized but
    # not called".
    assert report["capabilities"]["ssh_mcp"] == {
        "status": "unavailable",
        "error_code": "timeout",
        "reason": "预采集超过时间上限（16 秒），未到 SSH 实时诊断阶段",
    }
    assert "已授权但本次未调用" not in report["answer"]


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


def test_only_ssh_diagnostics_with_a_time_budget_are_left_to_the_cap():
    bridge = SkillMCP(
        lambda key: "",
        ["ssh_mcp", "zabbix_mcp", "logs"],
        deadline=time.monotonic() + 60,
    )
    budget = {"host_id": {"type": "integer"}, "timeout_seconds": {"type": "integer"}}
    bridge.tools["ssh_mcp"] = {
        "ssh_collect": tool("ssh_collect", budget),
        "ssh_diagnose_cpu": tool("ssh_diagnose_cpu", {"host_id": {"type": "integer"}}),
    }
    assert bridge.stoppable("ssh_mcp", "ssh_collect")
    assert not bridge.stoppable("ssh_mcp", "ssh_diagnose_cpu")
    # Lookups run nothing on a host; Zabbix and log queries keep the cap.
    assert bridge.stoppable("ssh_mcp", "ssh_resolve_host")
    assert bridge.stoppable("zabbix_mcp", "history_get")
    assert bridge.stoppable("logs", "log_overview")


def test_an_ssh_diagnostic_the_server_cannot_stop_is_waited_for(monkeypatch):
    """The cap used to abandon an ssh_collect the SSH MCP server kept running
    on the host (no `timeout_seconds` to tell it when to answer): its result
    was lost. Now prefetch waits for it; the Zabbix query is still skipped."""
    monkeypatch.setattr(skill_runtime, "PREFETCH_SHARE", 0.05)  # 180 s -> 9 s
    clock = alert_clock()
    zbx = cpu_alert(clock)
    answered = zbx.call_tool
    capped = asyncio.Event()

    async def call_tool(name, args):
        if name == "history_get":
            try:
                await asyncio.sleep(600)
            except asyncio.CancelledError:
                capped.set()
                raise
        return await answered(name, args)

    zbx.call_tool = call_tool
    ssh = SSH({})
    original = ssh.call_tool

    async def collect_after_the_cap(name, args):
        if name == "ssh_collect":
            # The host is slow: the bundle answers only after the cap fired.
            await asyncio.wait_for(capped.wait(), 120)
        return await original(name, args)

    ssh.call_tool = collect_after_the_cap
    rig(monkeypatch, zbx, ssh)
    model = Model(lambda r: answer("结论"))
    task, _ = run_alert(event_for(CPU_ALERT, "71001", clock), model)
    report = task["report"]
    assert "ssh_collect" in report["coverage"]["collected"]
    assert not any(e["tool"] == "ssh_collect" for e in report["coverage"]["skipped"])
    assert {
        "tool": "history_get",
        "reason": skill_runtime.PREFETCH_LATE,
    } in report["coverage"]["skipped"]
    assert prefetched(model.requests[0], "ssh_collect")
    hit = next(
        hit
        for hit in report["budget"]["limits_hit"]
        if hit.startswith("预采集超过时间上限（9 秒")
    )
    assert (
        "history_get" in hit
        and "SSH 诊断不能中途停止，已等到结果（ssh_collect）" in hit
    )
    assert report["capabilities"]["ssh_mcp"]["status"] == "used"


def test_a_session_cancelled_while_listing_its_tools_is_opened_again(monkeypatch):
    """Registered before its tools were listed, a session the cap cancelled in
    between answered every later call with "MCP 工具发现失败"."""
    session = Sources({}, slow_first_listing=True)

    @asynccontextmanager
    async def connect(*args, **kwargs):
        yield session

    monkeypatch.setattr(log_mcp, "connect", connect)
    clear_catalog_cache()

    async def scenario():
        async with SkillMCP(
            lambda key: LOG_CONFIG.get(key, ""),
            ["logs"],
            deadline=time.monotonic() + 60,
        ) as bridge:
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.5):
                    await bridge.catalog("logs")
            assert "logs" not in bridge.sessions and "logs" not in bridge.tools
            assert "logs" not in bridge.failures
            assert "log_overview" in await bridge.catalog("logs")
            assert bridge.sessions["logs"] is session and session.listings == 2

    asyncio.run(scenario())


def test_a_log_session_cut_while_it_opens_still_serves_the_model(
    device_logs, monkeypatch
):
    """The review's repro: the cap fired while the log session listed its
    tools; the model's log query then failed with "MCP 工具发现失败"."""
    monkeypatch.setattr(skill_runtime, "PREFETCH_SHARE", 0.05)  # 180 s -> 9 s
    ask = response(
        Call(
            "call_mcp_tool",
            {
                "provider": "logs",
                "name": "log_overview",
                "arguments": {"target": "198.51.100.50"},
            },
        )
    )
    task, _, sources = device_logs(
        {("ip", "198.51.100.50"): ["core-switch-01"]}, ask, slow_first_listing=True
    )
    second = sources.create.call_args_list[1].kwargs["input"]
    [output] = [
        item["output"]
        for item in second
        if isinstance(item, dict) and item.get("type") == "function_call_output"
    ]
    assert "MCP 工具发现失败" not in output and "5210" in output
    assert sources.listings == 2 and sources.targets() == {"198.51.100.50"}
    report = task["report"]
    assert report["capabilities"]["logs"]["status"] == "used"
    assert any(
        hit.startswith("预采集超过时间上限（9 秒")
        for hit in report["budget"]["limits_hit"]
    )


def test_what_the_cap_cut_short_is_not_reported_unused(device_logs, monkeypatch):
    """The log session never finished opening and the model did not ask for
    logs: 能力说明 says the cap cut it, not "authorized but not called". A
    network device's SSH was not applicable whatever the cap."""
    monkeypatch.setattr(skill_runtime, "PREFETCH_SHARE", 0.05)  # 180 s -> 9 s
    task, sent, sources = device_logs(
        {("ip", "198.51.100.50"): ["core-switch-01"]}, slow_first_listing=True
    )
    report = task["report"]
    assert report["capabilities"]["logs"] == {
        "status": "unavailable",
        "error_code": "timeout",
        "reason": "预采集超过时间上限（9 秒），日志 MCP 连接未完成",
    }
    assert sent["capabilities"]["ssh_mcp"]["status"] == "not_applicable"
    assert report["capabilities"]["ssh_mcp"]["status"] == "not_applicable"
    assert (
        "日志 MCP不可用：预采集超过时间上限（9 秒），日志 MCP 连接未完成"
        in (report["answer"])
    )
    assert "已授权但本次未调用" not in report["answer"]
    assert sources.resolved() == []


def test_named_small_values_need_no_extra_evidence_round(monkeypatch):
    """Correct quotes of small values were rejected, so the platform sent the
    model back for more evidence it did not need. A bare small number is
    still no citation, and the round is still asked for."""
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [
            item("201", "system.cpu.load[all,avg5]", 12.4),
            item("203", "system.cpu.num", 4, "3"),
        ],
        [item("202", "system.cpu.util", 18.5)],
        [],
        {"201": step(clock, 3.0, 12.0), "202": step(clock, 15.0, 18.0)},
        {"201": (1.0, 2.5, 4.0), "202": (5.0, 15.0, 30.0)},
    )
    rig(monkeypatch, zbx, SSH({}))

    def conclude(quote):
        def reply(request):
            items = prefetched(request, "item_get")[0]
            return answer(
                json.dumps(
                    {
                        "cause": f"5 分钟负载 12.4，主机 4 核（{items}）",
                        "action": ["核对告警时段的批处理任务"],
                        "evidence": [
                            {"id": items, "quote": "system.cpu.load[all,avg5] 12.4"},
                            {"id": items, "quote": quote},
                        ],
                    },
                    ensure_ascii=False,
                )
            )

        return reply

    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(conclude("system.cpu.num 4"))
    )
    report = task["report"]
    assert len(report["citations"]["valid"]) == 2
    assert "平台要求模型补充证据后再总结（1 次）" not in report["budget"]["limits_hit"]
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock, event_id="880002"), Model(conclude("4"))
    )
    report = task["report"]
    assert [item["reason"] for item in report["citations"]["invalid"]] == [
        evidence_check.UNNAMED
    ]
    assert "平台要求模型补充证据后再总结（1 次）" in report["budget"]["limits_hit"]
