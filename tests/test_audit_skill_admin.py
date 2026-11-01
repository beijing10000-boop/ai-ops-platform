"""Regression tests for the 2026-11 Skill administration fixes.

Web edits that keep a Skill's metadata, and no scope left without a Skill
unless the change is confirmed (API 409 and the Skills page).
"""

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app import main, skill_store as skills
from test_platform import client_for

P = "/api/v1/platform/skills"
CLOCK = 1_793_274_921  # 2026-10-29 19:55:21 Beijing time


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


# --- OPS-SKILL-05: Web edits keep types and devices ----------------------------------

SCOPED = (
    "---\nname: site-linux\ndescription: 本环境 Linux 规则\n"
    "types: [cpu, memory]\ndevices: [linux]\n"
    "prefetch:\n- scopes: [alert]\n  types: [cpu]\n  ssh: [ssh_diagnose_cpu]\n"
    "---\n只对 Linux CPU 与内存告警适用的本环境规则。\n"
)


def upload(text, **values):
    return {
        "filename": "SKILL.md",
        "data": base64.b64encode(text.encode()).decode(),
        **values,
    }


def test_web_edits_keep_a_skills_types_and_devices():
    client = client_for()
    row = client.post(P, json=upload(SCOPED, enabled=True, mode="supplement")).json()
    assert (row["types"], row["devices"]) == (["cpu", "memory"], ["linux"])
    # Switching it off leaves SKILL.md exactly as imported.
    assert client.put(P + "/" + row["id"], json={"enabled": False}).status_code == 200
    off = skills.get(row["id"])
    assert off["files"]["SKILL.md"] == SCOPED and off["digest"] == row["digest"]
    assert not off["enabled"] and off["revision"] == row["revision"] + 1
    # Editing the text keeps every metadata field.
    assert (
        client.put(
            P + "/" + row["id"],
            json={"instructions": "改写后的规则。", "enabled": True},
        ).status_code
        == 200
    )
    edited = skills.get(row["id"])
    assert edited["instructions"] == "改写后的规则。"
    assert (edited["types"], edited["devices"]) == (["cpu", "memory"], ["linux"])
    assert edited["prefetch"][0]["ssh"] == ["ssh_diagnose_cpu"]
    assert not skills.applies(edited, "cpu", "windows")


def test_document_writes_types_and_devices_only_when_declared():
    text = skills.document("x", "说明", "正文", types=["cpu"], devices=["linux"])
    parsed = skills.parse_document(text)
    assert (parsed["types"], parsed["devices"]) == (["cpu"], ["linux"])
    plain = skills.document("x", "说明", "正文")
    assert "types" not in plain and "devices" not in plain


# --- OPS-FE-01: no scope left without a Skill unless confirmed -----------------------


def base_row(client):
    return next(
        row for row in client.get(P).json()["items"] if row["name"] == skills.BASE_NAME
    )


def test_switching_off_the_base_skill_needs_confirmation():
    client = client_for()
    base = base_row(client)
    refused = client.put(P + "/" + base["id"], json={"enabled": False})
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert detail["code"] == "skill_scopes_uncovered"
    assert detail["scopes"] == ["qa", "web", "alert"]
    assert "飞书问答、Web 诊断、告警分析" in detail["message"]
    assert (
        base_row(client)["enabled"] and base_row(client)["revision"] == base["revision"]
    )
    # Narrowing its scenarios is the same loss for the scenario dropped.
    narrowed = client.put(P + "/" + base["id"], json={"scopes": ["qa", "web"]})
    assert narrowed.status_code == 409 and narrowed.json()["detail"]["scopes"] == [
        "alert"
    ]
    confirmed = client.put(
        P + "/" + base["id"], json={"enabled": False, "confirm": True}
    )
    assert confirmed.status_code == 200 and not confirmed.json()["enabled"]
    assert skills.snapshot({}, "web") == []
    # Switching it back on needs nothing.
    assert client.put(P + "/" + base["id"], json={"enabled": True}).status_code == 200


def test_a_custom_skill_covering_every_scope_lets_the_base_go():
    client = client_for()
    text = "---\nname: site-rules\ndescription: 本环境规则\n---\n本环境规则。"
    assert (
        client.post(P, json=upload(text, enabled=True, mode="supplement")).status_code
        == 201
    )
    base = base_row(client)
    assert client.put(P + "/" + base["id"], json={"enabled": False}).status_code == 200


def test_switching_off_the_last_custom_skill_of_a_scope_needs_confirmation():
    client = client_for()
    text = "---\nname: qa-only\ndescription: 问答规则\n---\n问答规则。"
    row = client.post(P, json=upload(text, enabled=True, scopes=["qa"])).json()
    base = base_row(client)
    # The base is off for every scope: Web and alerts lose their last Skill.
    off = client.put(P + "/" + base["id"], json={"enabled": False})
    assert off.json()["detail"]["scopes"] == ["web", "alert"]
    client.put(P + "/" + base["id"], json={"enabled": False, "confirm": True})
    # Already uncovered scopes are not reported again; Q&A is the new loss.
    refused = client.put(P + "/" + row["id"], json={"enabled": False})
    assert refused.status_code == 409 and refused.json()["detail"]["scopes"] == ["qa"]
    # Re-importing it switched off is the same change.
    again = upload(text, enabled=False, scopes=["qa"], replace_existing=True)
    assert client.post(P, json=again).status_code == 409
    assert client.post(P, json={**again, "confirm": True}).status_code == 201
    assert not skills.get(row["id"])["enabled"]


def test_uncovered_mirrors_the_snapshot_selection():
    def row(name, enabled=True, scopes=("qa", "web", "alert"), managed=True):
        return {
            "name": name,
            "enabled": enabled,
            "scopes": list(scopes),
            "managed": managed,
        }

    platform = [row("platform-base", enabled=False), row("platform-linux")]
    assert skills.uncovered(platform) == ["qa", "web", "alert"]
    assert skills.uncovered(
        [*platform, row("site", scopes=["web"], managed=False)]
    ) == [
        "qa",
        "alert",
    ]
    assert skills.uncovered([row("platform-base", scopes=["alert"])]) == ["qa", "web"]


NODE = shutil.which("node")


@pytest.mark.skipif(not NODE, reason="needs node to run web/assets/skills.js")
def test_skills_page_confirms_what_a_change_costs_before_sending_it(tmp_path):
    script = r"""
const vm = require("vm"), fs = require("fs");
const answers = [];
const context = {
  document: {addEventListener() {}},
  window: {},
  UIKit: {confirm: async ({title, message, confirmText}) => { context.asked.push([title, message, confirmText].join("\n")); return answers.shift(); }},
  asked: [],
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context);
const run = code => vm.runInContext(code, context);
const base = {id: "b", name: "platform-base", managed: true, enabled: true, scopes: ["qa", "web", "alert"]};
const linux = {id: "l", name: "platform-linux", managed: true, enabled: true, scopes: ["qa", "web", "alert"]};
context.items = [base, linux];
context.base = base;
(async () => {
  const out = {};
  out.uncovered = run("uncoveredScopes(items.map(r => r.id === 'b' ? {...r, enabled: false} : r))");
  out.warnings = run("skillChangeWarnings(base, {enabled: false, scopes: base.scopes}, items)");
  out.enabling = run("skillChangeWarnings({...base, enabled: false}, {enabled: true, scopes: base.scopes}, items)");
  const sent = [];
  context.send = async extra => { sent.push(extra); };
  answers.push(false);
  out.cancelled = await run("confirmedSkillSave('platform-base', ['x'], send)");
  out.sentAfterCancel = sent.length;
  answers.push(true);
  out.accepted = await run("confirmedSkillSave('platform-base', ['x'], send)");
  out.sentAfterAccept = sent.slice();
  sent.length = 0;
  let calls = 0;
  context.refuse = async extra => {
    calls += 1; sent.push(extra);
    if (!extra.confirm) { const error = new Error("保存后以下场景将没有任何可用的 Skill"); error.status = 409; error.detail = {code: "skill_scopes_uncovered"}; throw error; }
  };
  answers.push(true);
  out.retried = await run("confirmedSkillSave('qa-only', [], refuse)");
  out.retrySent = sent.slice();
  out.asked = context.asked;
  console.log(JSON.stringify(out));
})();
"""
    path = Path(__file__).resolve().parents[1] / "web" / "assets" / "skills.js"
    runner = tmp_path / "skills_check.js"
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
    assert out["uncovered"] == ["飞书问答", "Web 诊断", "告警分析"]
    assert len(out["warnings"]) == 2 and "platform-linux" in out["warnings"][0]
    assert "飞书问答、Web 诊断、告警分析" in out["warnings"][1]
    assert out["enabling"] == []
    assert out["cancelled"] is False and out["sentAfterCancel"] == 0
    assert out["accepted"] is True and out["sentAfterAccept"] == [{"confirm": True}]
    assert out["retried"] is True and out["retrySent"] == [{}, {"confirm": True}]
    assert "仍要保存" in out["asked"][-1]
