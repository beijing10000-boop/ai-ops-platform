"""Regression tests for the 2026-11 console audit, P2 follow-ups.

OPS-FE-04 cancelling a task and lifting a mute ask first, OPS-FE-05 the log
MCP in the diagnostic tools, OPS-FE-06 muting from an alert row, OPS-FE-25
collapsible report blocks across the polling refresh, OPS-FE-13 error and
success feedback, OPS-FE-08 framing and content policy headers. The console
scripts run in node with a stub DOM.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from test_platform import client_for

WEB = Path(__file__).resolve().parents[1] / "web"
ASSETS = WEB / "assets"
NODE = shutil.which("node")


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


# experience.js and app.js in one context, with just enough DOM: every
# element is a recording stub, api() records its calls and answers from
# `reply`, UIKit.notify / UIKit.confirm record what they were given.
PRELUDE = r"""
const vm = require("vm"), fs = require("fs"), path = require("path");
const listeners = {}, elements = {};
const element = () => ({
  attributes: {}, dataset: {}, classList: {toggle() {}, add() {}, remove() {}},
  hidden: false, open: false, isConnected: true, textContent: "", innerHTML: "", className: "",
  addEventListener() {}, setAttribute(name, value) { this.attributes[name] = String(value); },
  getAttribute(name) { return this.attributes[name]; }, querySelector: () => element(),
  querySelectorAll: () => [], closest: () => null, scrollIntoView() {}, focus() {},
});
const byId = id => (elements[id] ||= element());
const context = {
  console, URL, URLSearchParams, structuredClone, setTimeout, clearTimeout,
  calls: [], asked: [], notes: [], answers: [], reply: null,
  location: {hash: ""},
  sessionStorage: {getItem: () => null, setItem() {}, removeItem() {}},
  window: {addEventListener() {}, history: {replaceState() {}}, scrollTo() {}, confirm: () => true},
  // The start-up sign-in check never settles.
  fetch: () => new Promise(() => {}),
  document: {
    addEventListener(type, fn) { (listeners[type] ||= []).push(fn); },
    querySelector: selector => /^#[\w-]+$/.test(selector) ? byId(selector.slice(1)) : element(),
    querySelectorAll: () => [],
    getElementById: id => elements[id] || null,
    createElement: () => element(),
  },
};
context.UIKit = {
  icon: () => "",
  notify: (message, options = {}) => { context.notes.push([message, options.type]); },
  confirm: async question => { context.asked.push(question); return context.answers.shift(); },
};
const {calls, asked, notes, answers} = context;
vm.createContext(context);
for (const file of ["experience.js", "app.js"])
  vm.runInContext(fs.readFileSync(path.join(process.argv[2], file), "utf8"), context, {filename: file});
const run = code => vm.runInContext(code, context);
run(`api = async (path, method = "GET", body) => { calls.push([method, path, body ?? null]); return reply ? reply(path, method, body) : {}; }`);
run(`state.user = {permissions: ["*"], open_id: "ou_super"}`);
// A click on a [data-action] button, as the document listener receives it.
const click = async (action, id = "") => {
  const button = {dataset: {action, id}, disabled: false, closest: () => null};
  for (const listener of listeners.click) await listener({target: {closest: s => s === "[data-action]" ? button : null}});
  return button;
};
"""


def run_console(tmp_path, body):
    script = tmp_path / "console_check.js"
    script.write_text(PRELUDE + "(async () => {\n" + body + "\n})();", encoding="utf-8")
    done = subprocess.run(
        [NODE, str(script), str(ASSETS)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


needs_node = pytest.mark.skipif(not NODE, reason="needs node to run web/assets/*.js")
TASK = "0123456789abcdef0123456789abcdef"


# --- OPS-FE-04: cancelling a task and lifting a mute ask first ----------------------


@needs_node
def test_cancelling_a_task_and_lifting_a_mute_ask_first(tmp_path):
    out = run_console(
        tmp_path,
        f"""
  run(`state.currentTask = {{task_id: "{TASK}", status: "running", stage: "skill_prefetch",
    diagnostic_type: "cpu", event_id: "8003", alert: {{host_name: "web-01"}}}}`);
  const out = {{}};
  answers.push(false);
  const declined = await click("cancel-task", "{TASK}");
  out.declinedCalls = calls.length; out.reenabled = !declined.disabled;
  answers.push(true);
  await click("cancel-task", "{TASK}");
  out.cancel = calls[0]; out.cancelAsked = asked.slice();
  calls.length = 0; asked.length = 0;
  run(`state.mutes = [{{host_id: "10001", trigger_id: "20002", created_at: "", expires_at: 1793600000}}]`);
  answers.push(false);
  await click("unmute", "10001:20002");
  out.unmuteDeclinedCalls = calls.length;
  answers.push(true);
  await click("unmute", "10001:20002");
  out.unmute = calls[0]; out.unmuteAsked = asked.slice(); out.notes = notes;
  console.log(JSON.stringify(out));
""",
    )
    # Declining sends nothing and frees the button.
    assert out["declinedCalls"] == 0 and out["reenabled"]
    assert out["cancel"] == ["POST", f"/api/v1/platform/tasks/{TASK}/cancel", None]
    question = out["cancelAsked"][0]
    assert question["danger"] is True and question["confirmText"] == "取消任务"
    assert question["cancelText"] == "继续执行" and TASK[:12] in question["title"]
    # It names the task's host, type and event, and what cancelling costs.
    for text in ("web-01", "CPU 异常", "8003", "不能恢复", "重新消耗分析预算"):
        assert text in question["message"], text
    assert out["unmuteDeclinedCalls"] == 0
    assert out["unmute"] == ["DELETE", "/api/v1/alert-mutes/10001/20002", None]
    lift = out["unmuteAsked"][0]
    assert lift["danger"] is True and lift["confirmText"] == "解除屏蔽"
    assert "10001" in lift["title"] and "20002" in lift["title"]
    assert "到期" in lift["message"] and "照常发送飞书告警通知" in lift["message"]
    assert ["屏蔽已解除", "success"] in out["notes"]


# --- OPS-FE-05: the log MCP in the diagnostic tools ----------------------------------

LOG_HEALTH = {
    "provider": "logs",
    "status": "success",
    "checked_at": "2026-11-01 05:00:00",
    "detail": json.dumps({"authorized_tools": ["log_search", "<b>x</b>"]}),
}


@needs_node
def test_the_log_mcp_shows_its_status_and_tools_with_the_other_two(tmp_path):
    out = run_console(
        tmp_path,
        """
  const section = overview => run(`logToolsSection(logMcpState(${JSON.stringify(overview)}))`);
  const out = {};
  out.none = section({log_mcp_configured: false, health: []});
  out.unchecked = section({log_mcp_configured: true, health: []});
  out.passed = section({log_mcp_configured: true, health: [HEALTH]});
  out.failed = section({log_mcp_configured: true, health: [{provider: "logs", status: "failed", checked_at: "2026-11-01 05:00:00", detail: "日志 MCP 拒绝令牌（HTTP 401）"}]});
  out.unreadable = section({error: "当前角色没有此操作权限"});
  context.reply = path => path.endsWith("/overview") ? {log_mcp_configured: true, health: [HEALTH]} : {tools: [], playbooks: {}, ssh_mcp_error: "未启用"};
  out.page = await run("diagnosticTools()");
  out.read = context.calls.map(call => call[1]);
  // 检测 MCP 工具 checks the configured log MCP and shows the result in place.
  context.calls.length = 0;
  context.reply = path => ({provider: path.split("provider=")[1], ok: true, authorized_tools: ["log_aggregate"]});
  elements["log-mcp-tools"] = element();
  await click("discover");
  out.checked = context.calls.map(call => call[1].split("provider=")[1]);
  out.updated = elements["log-mcp-tools"].outerHTML;
  out.toast = context.notes.at(-1);
  // Without a saved address and token it is skipped, and the toast says so.
  run("state.logMcp = {configured: false}");
  context.calls.length = 0;
  await click("discover");
  out.skipped = context.calls.map(call => call[1].split("provider=")[1]);
  out.skipToast = context.notes.at(-1);
  console.log(JSON.stringify(out));
""".replace("HEALTH", json.dumps(LOG_HEALTH)),
    )
    assert "未配置" in out["none"] and "log_" not in out["none"].split("</h4>")[1]
    assert "待验证" in out["unchecked"] and "检测 MCP 工具" in out["unchecked"]
    passed = out["passed"]
    assert "最近检测通过" in passed and "日志 MCP · 历史日志（2）" in passed
    assert '<span class="tag mono">log_search</span>' in passed
    # Tool names are data from another service.
    assert "&lt;b&gt;x&lt;/b&gt;" in passed and "<b>x</b>" not in passed
    assert "最近检测失败" in out["failed"] and "HTTP 401" in out["failed"]
    assert "无法读取日志 MCP 的连接状态" in out["unreadable"]
    # The tools area reads the registry and the last checks, and lists all three.
    assert "/api/v1/platform/overview" in out["read"]
    for title in (
        "SSH MCP · Linux 实时诊断",
        "Zabbix MCP · 监控数据",
        "日志 MCP · 历史日志",
    ):
        assert title in out["page"], title
    assert sorted(out["checked"]) == ["logs", "ssh_mcp", "zabbix_mcp"]
    assert "最近检测通过" in out["updated"] and "log_aggregate" in out["updated"]
    assert out["toast"][1] == "success" and "日志 MCP：连接成功" in out["toast"][0]
    assert out["skipped"] == ["zabbix_mcp", "ssh_mcp"]
    assert "日志 MCP：未配置，未检测" in out["skipToast"][0]


@needs_node
def test_a_log_mcp_saved_for_the_first_time_is_checked_without_a_reload(tmp_path):
    """The page read the log MCP's state before anything was saved; saving
    its connection form updates that state, so 检测 MCP 工具 includes it."""
    out = run_console(
        tmp_path,
        """
  // FormData over a form stub's values, as the browser builds it.
  context.FormData = class {
    constructor(form) { this.entries = Object.entries(form.values); }
    [Symbol.iterator]() { return this.entries[Symbol.iterator](); }
    getAll(name) { return this.entries.filter(([key]) => key === name).map(([, value]) => value); }
  };
  const result = element();
  const form = {
    id: "logs-form", dataset: {provider: "logs"}, classList: {contains: name => name === "connection-form", toggle() {}},
    values: {log_mcp_url: "http://198.51.100.7:7077/mcp", log_mcp_token: "logmcp_fixture"},
    querySelector: selector => selector === "[data-verify-result]" ? result : element(),
    querySelectorAll: () => [],
  };
  const submit = async changed => {
    context.reply = (path, method) => method === "PUT" ? {ok: true, changed} : {provider: path.split("provider=")[1], ok: true, authorized_tools: ["log_search"]};
    for (const listener of listeners.submit) await listener({target: form, preventDefault() {}});
  };
  const discover = async () => {
    calls.length = 0;
    await click("discover");
    return calls.map(call => call[1].split("provider=")[1]);
  };
  const out = {};
  run(`state.logMcp = logMcpState({log_mcp_configured: false, health: []})`);
  elements["log-mcp-tools"] = element();
  await submit(["log_mcp_url", "log_mcp_token"]);
  out.saved = calls[0];
  out.section = elements["log-mcp-tools"].outerHTML;
  out.checked = await discover();
  out.toast = notes.at(-1);
  // Saved again unchanged: the check just made stays.
  await submit([]);
  out.kept = elements["log-mcp-tools"].outerHTML;
  // A new address drops it, as the server does.
  form.values.log_mcp_url = "http://198.51.100.8:7077/mcp";
  await submit(["log_mcp_url"]);
  out.dropped = elements["log-mcp-tools"].outerHTML;
  // Cleared: not checked again.
  form.values = {log_mcp_url: "", log_mcp_token: ""};
  await submit(["log_mcp_url", "log_mcp_token"]);
  out.cleared = await discover();
  console.log(JSON.stringify(out));
""",
    )
    assert out["saved"][:2] == ["PUT", "/api/v1/settings"]
    assert "待验证" in out["section"] and "未配置" not in out["section"]
    assert sorted(out["checked"]) == ["logs", "ssh_mcp", "zabbix_mcp"]
    assert "日志 MCP：连接成功" in out["toast"][0]
    assert "最近检测通过" in out["kept"] and "log_search" in out["kept"]
    assert "待验证" in out["dropped"] and "log_search" not in out["dropped"]
    assert out["cleared"] == ["zabbix_mcp", "ssh_mcp"]


# --- OPS-FE-06: muting from an alert row ---------------------------------------------


def test_alert_rows_name_their_mute_rule():
    with main.connection() as db:
        for event_id, event in (
            ("9001", {"host_id": "10084", "trigger_id": "23050", "private": "x"}),
            ("9002", {"host_id": 10085, "trigger_id": 23051}),
            ("9003", {"host_id": "10086"}),
        ):
            db.execute(
                "INSERT INTO alert_events(event_id,event_value,host_name,event_name,severity,event_json) VALUES (?,'1','h','e',3,?)",
                (event_id, json.dumps(event)),
            )
        # A malformed or missing payload leaves the IDs empty, not the page broken.
        db.execute(
            "INSERT INTO alert_events(event_id,event_value,event_json) VALUES ('9004','1','not json')"
        )
        db.execute("INSERT INTO alert_events(event_id,event_value) VALUES ('9005','1')")
    response = client_for("auditor").get("/api/v1/platform/alerts")
    assert response.status_code == 200
    rows = {row["event_id"]: row for row in response.json()["items"]}
    assert (rows["9001"]["host_id"], rows["9001"]["trigger_id"]) == ("10084", "23050")
    assert (rows["9002"]["host_id"], rows["9002"]["trigger_id"]) == ("10085", "23051")
    assert rows["9003"]["trigger_id"] is None
    assert rows["9004"]["host_id"] is None and rows["9005"]["trigger_id"] is None
    assert not any({"event_json", "private"} & row.keys() for row in rows.values())


ALERTS = {
    "total": 3,
    "items": [
        {
            "event_id": "8001",
            "event_name": "CPU high",
            "host_name": "web-01",
            "severity": 4,
            "received_at": "2026-11-01 05:00:00",
            "status": "active",
            "notify_status": "sent",
            "ai_status": "not_required",
            "host_id": "10001",
            "trigger_id": "20001",
        },
        # No trigger ID, or a Zabbix macro that was not resolved: no button.
        {"event_id": "8002", "host_id": "10002", "trigger_id": None},
        {"event_id": "8003", "host_id": "{HOST.ID}", "trigger_id": "20003"},
    ],
}


@needs_node
def test_an_alert_row_opens_the_mute_form_filled_in(tmp_path):
    out = run_console(
        tmp_path,
        """
  const out = {}, alerts = ALERTS;
  context.reply = () => alerts;
  out.page = await run("alerts()");
  await click("mute-event", "8001");
  out.hash = context.location.hash;
  out.draft = run("state.muteDraft");
  context.reply = path => path.endsWith("status=active") ? [{host_id: "10001", trigger_id: "20001", created_at: "", expires_at: 1793600000}] : [];
  out.form = await run("mutesPanel()");
  // The 暂时屏蔽 tab itself starts from an empty form.
  await click("go-mutes");
  out.cleared = run("state.muteDraft");
  run('state.user = {permissions: ["reports.read"], open_id: "ou_auditor"}');
  context.reply = () => alerts;
  out.readOnly = await run("alerts()");
  console.log(JSON.stringify(out));
""".replace("ALERTS", json.dumps(ALERTS)),
    )
    assert re.findall(r'data-action="mute-event" data-id="(\d+)"', out["page"]) == [
        "8001"
    ]
    assert out["hash"] == "alerts/mutes"
    assert out["draft"] == {
        "event_id": "8001",
        "host_id": "10001",
        "trigger_id": "20001",
        "host_name": "web-01",
        "event_name": "CPU high",
    }
    form = out["form"]
    assert re.search(r'name="host_id" type="text" value="10001"', form)
    assert re.search(r'name="trigger_id" type="text" value="20001"', form)
    # The banner names the alert and the rule already in force.
    assert "屏蔽告警 8001 所属的触发器" in form and "web-01 · CPU high" in form
    assert "已有屏蔽" in form and 'data-action="clear-mute-draft"' in form
    assert out["cleared"] is None
    assert 'data-action="mute-event"' not in out["readOnly"]


# --- OPS-FE-25: report blocks keep their state across the polling refresh -----------

ROUNDS = {
    "content_visible": True,
    "items": [
        {
            "id": 7,
            "round_number": 1,
            "model": "m",
            "status": "completed",
            "duration_ms": 1200,
            "created_at": "2026-11-01 05:00:00",
            "payload": {
                "request": {
                    "instructions": {"text": "sys", "original_chars": 3},
                    "input": {"text": "in", "original_chars": 2},
                    "tools": ["history_get"],
                },
                "response": {
                    "text": {"text": "out", "original_chars": 3},
                    "items": [{"type": "message"}],
                },
            },
        },
        {
            "id": 9,
            "round_number": 2,
            "model": "m",
            "status": "failed",
            "duration_ms": 800,
            "created_at": "2026-11-01 05:01:00",
            "payload": {
                "request": {"instructions": {"text": "sys", "original_chars": 3}}
            },
        },
    ],
}
SKILLS = [
    {
        "name": "platform-base",
        "revision": 3,
        "providers": [],
        "digest": "a",
        "applied": True,
    },
    {
        "name": "platform-java",
        "revision": 2,
        "providers": [],
        "digest": "b",
        "applied": False,
    },
]


@needs_node
def test_report_blocks_keep_their_state_across_the_polling_refresh(tmp_path):
    out = run_console(
        tmp_path,
        """
  const out = {};
  out.first = run(`modelInteractionsPanel(${JSON.stringify(ROUNDS)})`);
  out.second = run(`modelInteractionsPanel(${JSON.stringify(ROUNDS)})`);
  out.skills = run(`skillsPanel(${JSON.stringify(SKILLS)})`);
  // Before the refresh: a keyed block and a block without a key are open.
  const block = (key, open) => ({dataset: key === null ? {} : {evidence: key}, open});
  const root = blocks => ({querySelectorAll: selector => blocks.filter(el =>
    (!selector.includes("[open]") || el.open) && (!selector.includes("[data-evidence]") || "evidence" in el.dataset))});
  context.before = root([block("mi-7", true), block("mi-7-input", false), block(null, true), block("12", false)]);
  out.kept = run("openReportBlocks(before)");
  // After it every block is new and closed; only the kept keys reopen.
  const after = [block("mi-7", false), block("mi-7-input", false), block(null, false), block("12", false)];
  context.after = root(after);
  run(`restoreReportBlocks(${JSON.stringify(out.kept)}, after)`);
  out.reopened = after.map(el => el.open);
  console.log(JSON.stringify(out));
""".replace("ROUNDS", json.dumps(ROUNDS)).replace("SKILLS", json.dumps(SKILLS)),
    )
    keys = re.findall(
        r'<details class="evidence" data-evidence="([^"]+)"', out["first"]
    )
    # Every collapsible block has a key, unique and the same on every render.
    assert out["first"].count('<details class="evidence"') == len(keys)
    assert len(keys) == len(set(keys)) and out["first"] == out["second"]
    assert keys == [
        "mi-7",
        "mi-7-instructions",
        "mi-7-input",
        "mi-7-output",
        "mi-7-items",
        "mi-9",
        "mi-9-instructions",
    ]
    assert out["skills"].count('<details class="evidence"') == 1
    assert 'data-evidence="skills-skipped"' in out["skills"]
    # A block without a key no longer reopens every other one.
    assert out["kept"] == ["mi-7"]
    assert out["reopened"] == [True, False, False, False]


# --- OPS-FE-13: errors and successes look and sound different ------------------------


@needs_node
def test_feedback_says_whether_an_action_failed(tmp_path):
    out = run_console(
        tmp_path,
        """
  const out = {};
  run('toast("配置已保存", "success")');
  run('toast("正在验证…")');
  // A failing action reports an error.
  context.reply = () => { const error = new Error("诊断队列不可用"); error.status = 503; throw error; };
  await click("retry-task", "abc");
  out.notes = context.notes.slice();
  // In the member dialog the message joins its form, styled by its type.
  byId("editor").open = true;
  const feedback = byId("editor-feedback");
  run('toast("成员信息验证通过；未保存。", "success")');
  out.dialogSuccess = [feedback.className, feedback.attributes.role, feedback.textContent];
  run('toast("验证未通过：Open ID 格式无效", "error")');
  out.dialogError = [feedback.className, feedback.attributes.role, feedback.textContent];
  out.notesAfter = context.notes.length;
  console.log(JSON.stringify(out));
""",
    )
    assert out["notes"] == [
        ["配置已保存", "success"],
        ["正在验证…", "info"],
        ["诊断队列不可用", "error"],
    ]
    assert out["dialogSuccess"] == [
        "notice success",
        "status",
        "成员信息验证通过；未保存。",
    ]
    assert out["dialogError"] == [
        "inline-error",
        "alert",
        "验证未通过：Open ID 格式无效",
    ]
    assert out["notesAfter"] == 3


def test_every_failure_toast_is_an_error():
    for name in ("app.js", "skills.js"):
        source = (ASSETS / name).read_text(encoding="utf-8")
        calls = re.findall(r"toast\(([^;]*?\.message[^;]*)\);", source)
        assert calls, name
        assert all(call.endswith('"error"') for call in calls), (name, calls)


# --- OPS-FE-08: nothing frames the console; its pages get a strict policy ------------

STRICT = (
    "default-src 'self'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'; object-src 'none'"
)


def test_every_response_refuses_framing_and_console_pages_are_strict():
    client = TestClient(main.app)
    for path, status in (
        ("/", 200),
        ("/setup", 200),
        ("/assets/app.js", 200),
        ("/assets/favicon.svg", 200),
        ("/healthz", 200),
        ("/api/v1/setup/status", 200),
        ("/api/v1/platform/tasks", 401),
        ("/no-such-page", 404),
    ):
        response = client.get(path)
        assert response.status_code == status, path
        assert response.headers["x-frame-options"] == "DENY", path
        assert response.headers["content-security-policy"] == STRICT, path
    # FastAPI's API docs keep their inline scripts and CDN assets: framing only.
    for path in ("/docs", "/redoc"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.headers["x-frame-options"] == "DENY", path
        assert response.headers["content-security-policy"] == (
            "frame-ancestors 'none'"
        ), path


def test_the_console_needs_nothing_the_strict_policy_blocks():
    """default-src 'self' refuses inline scripts, event handler attributes,
    inline styles, eval and other origins: the pages and scripts use none."""
    pages, scripts = sorted(WEB.glob("*.html")), sorted(ASSETS.glob("*.js"))
    styles = sorted(ASSETS.glob("*.css"))
    assert [page.name for page in pages] == ["index.html", "setup.html"]
    assert scripts and styles
    for page in pages:
        html = page.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", html), page.name
        assert not re.search(r"<style|\sstyle=|\son[a-z]+=|javascript:", html, re.I)
        for url in re.findall(r'\s(?:src|href)="([^"]*)"', html):
            assert url.startswith(("/", "#")) and not url.startswith("//"), url
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        # Markup built by the scripts carries no handler or style attribute.
        assert not re.search(r"""\son[a-z]+=["'\\$]|\sstyle=["'\\$]""", source), (
            script.name
        )
        assert not re.search(
            r"""\beval\(|new Function\(|set(?:Timeout|Interval)\(\s*["'`]|javascript:""",
            source,
        ), script.name
    for style in styles:
        css = style.read_text(encoding="utf-8")
        assert "@import" not in css and "url(" not in css, style.name
