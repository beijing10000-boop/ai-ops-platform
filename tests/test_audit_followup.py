"""Regressions for the review of the 2026-11 audit fixes (PR #76).

Worker shutdown and reconcile, the Swap filter, SSH time budgets, log window
notes, derived signals, Skill deletion, card fields, the owner of a Web
question, sizes, Skill line breaks and links in Feishu cards.
"""

import asyncio
import base64
import json
import logging
import os
import runpy
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import redis
from rq.exceptions import NoSuchJobError, StopRequested
from rq.worker import WorkerStatus

from app import (
    ai_agent,
    conversation_context,
    feishu_client,
    main,
    mcp_runtime,
    qa_worker,
    skill_runtime,
    worker,
)
from app import skill_store as skills
from app.orchestrator import queues, tasks
from app.skill_context import MAX_SIGNALS, derive_signals
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
    rig,
    run_alert,
    ssh_calls,
    step,
)
from test_audit_core import CPU_ALERT, budgets, cpu_alert, layered
from test_platform import client_for

P = "/api/v1/platform/skills"
REPORT = "http://ops.example.com:8088/#report/" + "0" * 32


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def settings(monkeypatch, **values):
    merged = {
        "web_protocol": "http",
        "web_public_host": "ops.example.com:8088",
        **values,
    }
    monkeypatch.setattr(worker, "cfg", lambda key: merged.get(key, ""))


# --- 1. Worker shutdown and reconcile -------------------------------------------------


@pytest.fixture
def signals_restored():
    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


def test_sigterm_during_maintenance_stops_an_idle_worker(monkeypatch, signals_restored):
    """RQ raises StopRequested from its SIGTERM handler while the worker is
    idle, as it is during maintenance: reconcile lets it through, so the work
    loop stops instead of running on until Docker kills it."""
    idle = object.__new__(worker.MaintainedWorker)
    for name, value in {
        "_state": WorkerStatus.IDLE,
        "_stop_requested": False,
        "_shutdown_requested_date": None,
        "scheduler": None,
        "name": "fixture",
        "pid": os.getpid(),
        "log": logging.getLogger("rq.worker"),
        "connection": None,
    }.items():
        setattr(idle, name, value)
    monkeypatch.setattr(worker.Worker, "run_maintenance_tasks", lambda self: None)
    later = []

    def signal_arrives(job_state=None):
        # Docker's SIGTERM lands while the first reconcile step runs.
        idle.request_stop(signal.SIGTERM, None)

    monkeypatch.setattr(tasks, "reconcile", signal_arrives)
    monkeypatch.setattr(worker, "sync_ai_states", lambda: later.append("sync"))
    monkeypatch.setattr(
        worker, "close_abandoned_progress", lambda: later.append("progress")
    )
    with pytest.raises(StopRequested):
        idle.run_maintenance_tasks()
    assert later == []


def test_closing_progress_cards_lets_a_stop_through(monkeypatch):
    monkeypatch.setattr(
        conversation_context,
        "abandoned_progress",
        lambda older_than: iter([("om_lost", {"chat_id": "oc_group", "kind": "qa"})]),
    )
    monkeypatch.setattr(conversation_context, "clear_pending", lambda *args: None)

    async def stopped(*args, **kwargs):
        raise StopRequested()

    monkeypatch.setattr(feishu_client, "update_card", stopped)
    with pytest.raises(StopRequested):
        worker.close_abandoned_progress()


def test_an_unexpected_job_state_never_fails_a_queued_task(monkeypatch):
    waiting, _ = tasks.create({}, event_id="993101")
    gone, _ = tasks.create({}, event_id="993102")
    with main.connection() as db:
        db.execute(
            "UPDATE diagnostic_tasks SET created_at=datetime('now','-20 minutes')"
        )

    def fetch(job_id, connection=None):
        if job_id == gone["task_id"]:
            raise NoSuchJobError(job_id)
        raise redis.exceptions.ResponseError("WRONGTYPE Operation against a key")

    monkeypatch.setattr(worker, "Job", SimpleNamespace(fetch=fetch))
    monkeypatch.setattr(worker, "sync_ai_states", lambda: None)
    monkeypatch.setattr(worker, "close_abandoned_progress", lambda: None)
    worker.reconcile(redis=object())
    assert tasks.get(waiting["task_id"])["status"] == "queued"
    lost = tasks.get(gone["task_id"])
    assert (lost["status"], lost["error_type"]) == ("failed", "QueueLost")

    # A stop RQ requested during the lookup is not taken for a Redis error.
    def stopping(job_id):
        raise StopRequested()

    with pytest.raises(StopRequested):
        tasks.reconcile(stopping)


@pytest.mark.filterwarnings("ignore:'app.worker' found in sys.modules:RuntimeWarning")
@pytest.mark.parametrize(
    "args, kind, names",
    [
        ([], "Worker", [queues.ALERTS]),
        (
            ["analysis"],
            "MaintainedWorker",
            [queues.ALERT_MANUAL, queues.ALERT_ANALYSIS],
        ),
    ],
)
def test_only_the_analysis_workers_reconcile(monkeypatch, args, kind, names):
    """Reconcile's Feishu calls and SQLite waits never delay alert delivery."""
    import rq

    started = []

    class Worker:
        def __init__(self, listened, connection=None):
            self.listened = listened

        def work(self):
            started.append((type(self).__name__, self.listened))

    monkeypatch.setattr(rq, "Worker", Worker)
    monkeypatch.setattr(rq, "Queue", lambda name, connection=None: name)
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: None)
    monkeypatch.setattr(sys, "argv", ["app.worker", *args])
    runpy.run_module("app.worker", run_name="__main__")
    assert started == [(kind, names)]


# --- 2. Swap filter -------------------------------------------------------------------


def test_swap_advice_joined_to_other_advice_loses_only_the_swap_part(monkeypatch):
    settings(monkeypatch)
    text = "内存不足，建议增加内存或启用 swap 分区；磁盘 40 GB"
    assert worker.without_swap_notes(text) == "内存不足，建议增加内存；磁盘 40 GB"
    assert worker.card_text(text) == "内存不足，建议增加内存；磁盘 40.00 GiB"
    assert (
        worker.card_text("内存使用率 98%，建议扩容内存或增加 Swap。")
        == "内存使用率 98%，建议扩容内存。"
    )
    # A clause only about Swap still goes, "create and enable" included.
    for only in (
        "建议开启 swap 作为缓冲。",
        "建议创建并启用 2 GiB Swap 文件。",
        "并且未配置 Swap。",
    ):
        assert (
            worker.without_swap_notes("内存使用率 98%。" + only) == "内存使用率 98%。"
        )
    # So does a line only saying Swap is absent; a finding that mentions it
    # stays whole.
    assert worker.without_swap_notes("- 内存：98%\n- Swap：未启用（总量 0 B）") == (
        "- 内存：98%"
    )
    kept = "内存不足并且未配置 Swap，导致 OOM。"
    assert worker.card_text(kept) == kept


def test_action_items_lose_only_their_swap_part(monkeypatch):
    settings(monkeypatch)
    card = worker.card_summary(
        {
            "cause": "内存使用率 98%",
            "action": [
                "扩容内存或增加 Swap 空间",
                "建议配置 2 GB Swap 作为缓冲",
                "重启 dsp-api 并启用 swap",
            ],
            "_diagnostic_status": "success",
        }
    )
    assert card == (
        "**诊断结论**\n内存使用率 98%\n\n**处理建议**\n1. 扩容内存\n2. 重启 dsp-api"
    )


def chat(monkeypatch, question, reply, limitations=()):
    """The Feishu card a chat question gets when the analysis answers `reply`."""
    settings(
        monkeypatch,
        openai_base_url="https://llm.example.com/v1",
        openai_model="fixture",
        openai_api_key="sk-fixture",
    )
    task, _ = tasks.create({"question": question}, source="qa")
    tasks.finish(task["task_id"], {"answer": reply, "limitations": list(limitations)})
    cards = []

    async def ask(question, context, return_usage=False, actor="system", **kwargs):
        return reply, {"available": False, "task_id": task["task_id"]}

    async def reply_card(message_id, title, body, template="blue"):
        return "om_progress"

    async def update_card(message_id, title, body, template="green"):
        cards.append(body)

    for name, value in {
        "ask": ask,
        "reply_card": reply_card,
        "update_card": update_card,
        "record_ai_question": lambda *args, **kwargs: None,
        "recall": lambda *args: None,
        "is_pending": lambda *args: False,
        "mark_pending": lambda *args: None,
        "clear_pending": lambda *args: None,
        "remember": lambda *args, **kwargs: None,
    }.items():
        monkeypatch.setattr(qa_worker, name, value)
    asyncio.run(qa_worker.execute("oc_group", question, "om_question"))
    [body] = cards
    return body


def test_a_question_about_swap_gets_its_answer_whole(monkeypatch):
    for question in ("这台主机配置 swap 了吗？", "交换分区有多大"):
        body = chat(monkeypatch, question, "主机未配置 Swap。", ["主机未配置 Swap"])
        assert body.startswith("主机未配置 Swap。"), body
        assert "\n- 主机未配置 Swap" in body
    # Asked about something else, the Swap-less design of the hosts is noise.
    body = chat(
        monkeypatch,
        "查一下 db-test-01 的内存",
        "主机未配置 Swap。",
        ["主机未配置 Swap"],
    )
    assert "Swap" not in body


# --- 3. A time budget the model passes ------------------------------------------------


def test_a_time_budget_from_the_model_is_capped_like_the_platforms(monkeypatch):
    clock = alert_clock()
    zbx, ssh = cpu_alert(clock), SSH({})
    listed = ssh.list_tools

    async def list_tools():
        result = await listed()
        for tool in result.tools:
            if tool.name == "ssh_collect":
                tool.inputSchema["properties"]["timeout_seconds"] = {
                    "anyOf": [
                        {"type": "integer", "minimum": 10, "maximum": 120},
                        {"type": "null"},
                    ],
                    "default": None,
                }
        return result

    ssh.list_tools = list_tools
    rig(monkeypatch, zbx, ssh)
    layered(monkeypatch, ssh_mcp_timeout_seconds="60")
    collect = {"host_id": 7, "actions": ["io", "disk"], "timeout_seconds": 120}
    rounds = [
        lambda r: answer(
            "",
            [
                Call(
                    "c1",
                    "call_mcp_tool",
                    {
                        "provider": "ssh_mcp",
                        "name": "ssh_collect",
                        "arguments": collect,
                    },
                )
            ],
        ),
        lambda r: answer("结论"),
    ]
    run_alert(event_for(CPU_ALERT, "71001", clock), Model(*rounds))
    sent = [args for name, args in ssh_calls(ssh) if name == "ssh_collect"]
    assert sent[-1]["actions"] == ["io", "disk"]
    # 120 s would outlast the platform's own 60 s call timeout.
    assert 10 <= sent[-1]["timeout_seconds"] <= 50


# --- 4. Log window notes --------------------------------------------------------------


def with_catalog_minutes(ssh):
    """The bundle's `minutes` ceiling (120) only in the SSH MCP catalog."""
    original = ssh.call_tool

    async def call_tool(name, args):
        response = await original(name, args)
        if name == "ssh_list_tool_catalog":
            for entry in response.structuredContent["result"]:
                if entry["id"] == "collect":
                    entry["params"].append({"name": "minutes", "maximum": 120})
        return response

    ssh.call_tool = call_tool


def window_notes(task):
    report = task["report"]
    return report["coverage"].get("limited") or [
        hit for hit in report["budget"]["limits_hit"] if "未覆盖告警时刻" in hit
    ]


def test_a_bundle_without_log_steps_has_no_window_to_fall_short(monkeypatch):
    """A CPU alert analysed 3 h later: cpu, processes, pressure read no logs."""
    clock = int(time.time()) - 3 * 3600
    zbx, ssh = cpu_alert(clock), SSH({})
    with_catalog_minutes(ssh)
    rig(monkeypatch, zbx, ssh)
    task, _ = run_alert(
        event_for(CPU_ALERT, "71001", clock), Model(lambda r: answer("结论"))
    )
    bundle = next(args for name, args in ssh_calls(ssh) if name == "ssh_collect")
    assert set(bundle["actions"]) <= {"cpu", "processes", "pressure"}
    assert window_notes(task) == []


def test_a_window_note_only_for_a_bundle_that_ran(monkeypatch):
    """A memory alert 3 h ago: its bundle reads the OOM log, but the budget
    left it out, so no window of it fell short."""
    clock = int(time.time()) - 3 * 3600
    zbx = Zabbix(
        LINUX_HOST,
        [item("301", "vm.memory.utilization", 97.0)],
        [],
        [{"eventid": "880001", "clock": str(clock), "value": "1", "name": "mem"}],
        {"301": step(clock, 60.0, 97.0)},
        {"301": (40.0, 60.0, 80.0)},
    )
    ssh = SSH({})
    with_catalog_minutes(ssh)
    rig(monkeypatch, zbx, ssh)
    budgets(standard={"calls": 6, "follow_up_calls": 2})
    task, _ = run_alert(
        event_for("Linux: High memory utilization", "71002", clock),
        Model(lambda r: answer("结论")),
    )
    assert "ssh_collect" not in [name for name, _ in ssh_calls(ssh)]
    assert {
        "tool": "ssh_collect",
        "reason": skill_runtime.PREFETCH_SHORT,
    } in task["report"]["coverage"]["skipped"]
    assert window_notes(task) == []


# --- 5. Derived signals ---------------------------------------------------------------


def test_repeated_ssh_findings_become_one_signal_and_leave_room_for_zabbix():
    clock = 1_793_274_921
    findings = [
        {
            "level": "warning",
            "metric": "heap_max_unset",
            "value": f"app-{n} (pid {1000 + n})",
            "threshold": "-Xmx",
            "hint": "启动命令未设置 -Xmx",
        }
        for n in range(14)
    ]
    history = {
        "records": [
            {"itemid": "11", "clock": str(clock - (10 - i) * 60), "value": "30"}
            for i in range(10)
        ]
        + [
            {"itemid": "11", "clock": str(clock + i * 60), "value": "90"}
            for i in range(10)
        ]
    }
    collected = [
        (
            "zabbix_mcp",
            "item_get",
            {"records": [{"itemid": "11", "key_": "vm.memory.utilization"}]},
            "E1",
        ),
        ("ssh_mcp", "ssh_diagnose_java", {"data": {"findings": findings}}, "E2"),
        ("zabbix_mcp", "history_get", history, "E3"),
    ]
    signals = derive_signals(collected, clock, "memory")
    assert "rise_at_alert" in [signal["metric"] for signal in signals]
    [heap] = [signal for signal in signals if signal["metric"] == "heap_max_unset"]
    assert heap["count"] == 14 and heap["values"][0] == "app-0 (pid 1000)"
    assert heap["evidence_id"] == "E2" and "value" not in heap


def test_ssh_signals_take_at_most_half_the_cap_beside_other_sources():
    findings = [
        {"level": "warning", "metric": f"check_{n}", "value": n, "hint": f"线索 {n}"}
        for n in range(MAX_SIGNALS)
    ]
    full = [
        {"itemid": str(500 + n), "key_": f"vfs.fs.size[/d{n},pused]", "lastvalue": "95"}
        for n in range(10)
    ]
    ssh = ("ssh_mcp", "ssh_collect", {"data": {"findings": findings}}, "E1")
    disks = ("zabbix_mcp", "item_get", {"records": full}, "E2")
    signals = derive_signals([ssh, disks], None, "disk")
    sources = [signal["source"] for signal in signals]
    assert len(signals) == MAX_SIGNALS
    assert sources.count("ssh_mcp") == MAX_SIGNALS // 2
    # Alone, or beside one other signal, SSH findings fill the rest.
    signals = derive_signals(
        [ssh, ("zabbix_mcp", "item_get", {"records": full[:1]}, "E2")]
    )
    assert [signal["source"] for signal in signals].count("ssh_mcp") == MAX_SIGNALS - 1


# --- 6. Deleting a Skill --------------------------------------------------------------


def skill_file(name):
    text = f"---\nname: {name}\ndescription: 自定义\n---\n\n按本环境规则诊断。\n"
    return base64.b64encode(text.encode()).decode()


def test_deleting_the_last_skill_of_a_scope_needs_confirmation():
    client = client_for()
    items = client.get(P).json()["items"]
    base = next(row for row in items if row["name"] == skills.BASE_NAME)
    custom = client.post(
        P,
        json={
            "filename": "SKILL.md",
            "data": skill_file("only-custom"),
            "enabled": True,
            "scopes": ["qa", "web", "alert"],
            "mode": "standalone",
        },
    ).json()
    # The custom Skill serves every scope, so the base can be switched off.
    assert client.put(P + "/" + base["id"], json={"enabled": False}).status_code == 200
    refused = client.delete(P + "/" + custom["id"])
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert detail["code"] == "skill_scopes_uncovered"
    assert detail["scopes"] == ["qa", "web", "alert"]
    assert skills.get(custom["id"])["name"] == "only-custom"
    assert client.delete(P + "/" + custom["id"] + "?confirm=true").status_code == 200
    assert skills.uncovered(client.get(P).json()["items"]) == ["qa", "web", "alert"]


NODE = shutil.which("node")


@pytest.mark.skipif(not NODE, reason="needs node to run web/assets/skills.js")
def test_skills_page_states_what_deleting_costs_and_confirms_it(tmp_path):
    script = r"""
const vm = require("vm"), fs = require("fs");
const answers = [];
const context = {
  document: {addEventListener() {}},
  window: {},
  UIKit: {confirm: async ({title, message, confirmText}) => { context.asked.push(title + message + "|" + confirmText); return answers.shift(); }},
  asked: [],
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);
const run = code => vm.runInContext(code, context);
const base = {id: "b", name: "platform-base", managed: true, enabled: false, scopes: ["qa", "web", "alert"]};
const custom = {id: "c", name: "only-custom", managed: false, enabled: true, scopes: ["qa", "web", "alert"]};
context.items = [base, custom];
context.custom = custom;
(async () => {
  const out = {}, sent = [];
  context.send = async extra => { sent.push(extra); };
  answers.push(false);
  out.cancelled = await run("confirmedSkillDelete(custom, items, send)");
  out.sentAfterCancel = sent.length;
  answers.push(true);
  out.accepted = await run("confirmedSkillDelete(custom, items, send)");
  out.sentAfterAccept = sent.slice();
  out.costly = context.asked.slice();
  sent.length = 0;
  context.asked.length = 0;
  context.refuse = async extra => {
    sent.push(extra);
    if (!extra.confirm) { const error = new Error("保存后以下场景将没有任何可用的 Skill"); error.status = 409; error.detail = {code: "skill_scopes_uncovered"}; throw error; }
  };
  context.items = [{...base, enabled: true}, custom];
  answers.push(true, true);
  out.retried = await run("confirmedSkillDelete(custom, items, refuse)");
  out.retrySent = sent.slice();
  out.asked = context.asked;
  console.log(JSON.stringify(out));
})();
"""
    path = Path(__file__).resolve().parents[1] / "web" / "assets" / "skills.js"
    runner = tmp_path / "skills_delete_check.js"
    runner.write_text(script, encoding="utf-8")
    done = subprocess.run(
        [NODE, str(runner), str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    out = json.loads(done.stdout)
    assert out["cancelled"] is False and out["sentAfterCancel"] == 0
    assert out["accepted"] is True and out["sentAfterAccept"] == [{"confirm": True}]
    # Both questions named the cost before anything was sent.
    assert len(out["costly"]) == 2
    assert all(
        text.startswith("删除 only-custom？") and "飞书问答、Web 诊断、告警分析" in text
        for text in out["costly"]
    )
    # The list changed meanwhile: the server's 409 is confirmed and retried.
    assert out["retried"] is True and out["retrySent"] == [{}, {"confirm": True}]
    assert out["asked"][0] == "删除 only-custom？历史任务保留已加载的版本。|删除"
    assert out["asked"][1].endswith("|仍要删除")


# --- 7. Card fields under other names -------------------------------------------------


def test_card_fields_under_other_names_after_a_heading_or_in_a_fence(monkeypatch):
    settings(monkeypatch)
    fields = {
        "conclusion": "dsp-api 堆内存占满（E2）",
        "suggestions": ["调低 -Xmx", "重启 dsp-api"],
    }
    body = json.dumps(fields, ensure_ascii=False)
    for raw in (
        "## 诊断结果\n" + body,
        "结论如下：\n```json\n" + body + "\n```",
        "```json\n" + body + "\n```",
    ):
        data = worker.card_fields(raw)
        assert data["cause"] == fields["conclusion"], raw
        assert data["action"] == fields["suggestions"], raw
    assert worker.card_summary(worker.card_fields("## 诊断结果\n" + body)) == (
        "**诊断结论**\ndsp-api 堆内存占满\n\n**处理建议**\n1. 调低 -Xmx\n2. 重启 dsp-api"
    )
    # Prose quoting other JSON stays prose.
    assert worker.card_fields('日志里有 {"level": "error"} 一行') is None


# --- 8. The owner of a Web question ---------------------------------------------------


def test_a_web_question_is_the_askers_while_it_runs_and_when_it_fails(monkeypatch):
    created, owners = [], []

    async def run(prompt, question, *, actor="system", **kwargs):
        task, _ = mcp_runtime.create_task(question, actor=actor)
        created.append(task["task_id"])
        owners.append(tasks.get(task["task_id"])["actor"])
        raise RuntimeError("model gateway 500")

    monkeypatch.setattr(ai_agent, "run", run)
    response = client_for("operator").post("/api/v1/ask", json={"question": "CPU"})
    assert response.status_code == 502
    assert owners == ["ou_operator"]
    assert tasks.get(created[0])["actor"] == "ou_operator"
    with main.connection() as db:
        rows = db.execute("SELECT actor FROM audit WHERE action='web_question'")
        assert rows.fetchall() == [("ou_operator",)]


# --- 9. Sizes -------------------------------------------------------------------------


def test_only_groups_of_three_digits_are_thousands(monkeypatch):
    settings(monkeypatch)
    assert worker.card_text("各节点内存 16,32,64 GB") == "各节点内存 16,32,64 GB"
    assert worker.card_text("缓存 1,024 MB，堆 1,5 GB") == "缓存 1.00 GiB，堆 1,5 GB"
    assert worker.card_text("分别为 8GB,16GB") == "分别为 8.00 GiB,16.00 GiB"


# --- 10. Skill line breaks ------------------------------------------------------------

CRLF = (
    "---\r\nname: crlf-skill\r\ndescription: 自定义  # 注释\r\n"
    "types: [cpu]\r\n---\r\n\r\n## 规则\r\n第一行\r\n第二行\r\n"
)


def test_a_crlf_skill_saved_from_the_web_form_keeps_its_file():
    client = client_for()
    created = client.post(
        P,
        json={
            "filename": "SKILL.md",
            "data": base64.b64encode(CRLF.encode()).decode(),
            "enabled": False,
            "scopes": ["qa"],
            "mode": "supplement",
        },
    ).json()
    row = client.get(P + "/" + created["id"]).json()
    # What the browser's textarea gives back: line breaks as LF.
    body = {
        "description": row["description"],
        "instructions": row["instructions"].replace("\r\n", "\n"),
        "enabled": True,
        "scopes": ["qa"],
        "providers": row["providers"],
        "priority": row["priority"],
        "mode": row["mode"],
    }
    assert client.put(P + "/" + created["id"], json=body).status_code == 200
    saved = skills.get(created["id"])
    assert saved["enabled"] and saved["files"]["SKILL.md"] == CRLF


# --- 11. Links in Feishu cards --------------------------------------------------------


def test_other_markdown_link_forms_cannot_link_out(monkeypatch):
    settings(monkeypatch)
    for text in (
        "[[x]](http://evil.example)",
        "[x](http://evil.example/a(b))",
        "[x]( http://evil.example)",
        '[x](http://evil.example "t")',
    ):
        assert "](" not in worker.lark_safe(text), text
    # The platform's own report stays a link; bare URLs stay as written.
    for text in (
        f"[报告]({REPORT})",
        f"[[报告]]({REPORT})",
        "见 http://evil.example/a",
    ):
        assert worker.lark_safe(text) == text
