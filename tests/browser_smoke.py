"""Desktop regression against a disposable local API and database, never a user browser."""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/screenshots"
OUT.mkdir(exist_ok=True)
# Failed runs must not upload the checked-in results of an older successful run.
(ROOT / "docs/UI-TEST-RESULTS.json").unlink(missing_ok=True)
for name in (
    "overview-1440.png",
    "assets-1440.png",
    "diagnosis-1440.png",
    "diagnosis-dark-1440.png",
    "host-keys-1440.png",
):
    (OUT / name).unlink(missing_ok=True)
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
base = "http://127.0.0.1:" + str(port)
log = Path("/tmp/aiops-browser-test.log").open("w")
server = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "uvicorn",
        "tests.ui_server:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ],
    cwd=ROOT,
    env={**os.environ, "AIOPS_UI_TEST": "1"},
    stdout=log,
    stderr=log,
)
checks = []
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(100):
        try:
            opener.open(base + "/healthz", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("UI test API failed to start")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        page = browser.new_page(
            viewport={"width": 1440, "height": 1080}, device_scale_factor=1
        )
        errors = []
        failed = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on(
            "response",
            lambda response: (
                failed.append(response.url) if response.status >= 500 else None
            ),
        )
        page.goto(base + "/__ui_login")
        page.locator('nav [data-page="overview"]').wait_for()
        for width in (1280, 1440, 1920):
            page.set_viewport_size({"width": width, "height": 1080})
            for name in (
                "overview",
                "alerts",
                "diagnostics",
                "assets",
                "tools",
                "connections",
                "history",
                "feishu",
                "ai",
                "settings",
                "audit",
            ):
                page.locator('nav [data-page="' + name + '"]').click()
                page.wait_for_function(
                    "!document.querySelector('#content').textContent.includes('正在加载…')"
                )
                assert not page.locator('#content [role="alert"]').count(), (
                    width,
                    name,
                    page.locator("#content").inner_text(),
                )
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= window.innerWidth"
                ), (width, name, "horizontal overflow")
                checks.append({"width": width, "page": name, "ok": True})
        page.set_viewport_size({"width": 1440, "height": 1080})
        page.locator('[data-page="assets"]').click()
        assert page.locator('[data-action="asset-prev"]').is_disabled()
        page.locator('[data-action="asset-next"]').click()
        page.locator(".pagination").get_by_text("第 2 页 / 2 页").wait_for()
        assert page.locator('[data-action="asset-next"]').is_disabled()
        page.locator('[data-action="asset-prev"]').click()
        page.locator(".pagination").get_by_text("第 1 页 / 2 页").wait_for()
        checks.append({"workflow": "asset pagination boundaries", "ok": True})
        page.locator('[data-action="new-asset"]').click()
        page.locator('dialog input[name="name"]').fill("浏览器验证资产")
        page.locator('dialog button[type="submit"]').click()
        page.locator("#content").get_by_text("浏览器验证资产", exact=True).wait_for()
        row = page.locator("tr").filter(has_text="浏览器验证资产")
        row.locator('[data-action="edit-asset"]').click()
        page.locator('dialog input[name="username"]').fill("bad user")
        page.locator('dialog button[type="submit"]').click()
        feedback = page.locator("#editor-feedback")
        feedback.get_by_text("诊断模式或 SSH 用户名无效").wait_for()
        assert feedback.is_visible(), "保存失败的提示必须显示在弹窗内"
        assert "诊断模式或 SSH 用户名无效" not in page.locator("#toast").inner_text()
        # A valid root account saves in standard mode without gateway approval.
        page.locator('dialog input[name="username"]').fill("root")
        page.locator('dialog button[type="submit"]').click()
        page.locator("#editor").wait_for(state="hidden")
        row.locator('[data-action="edit-asset"]').click()
        assert page.locator('dialog input[name="username"]').input_value() == "root"
        assert (
            page.locator('dialog select[name="diagnostic_mode"]').input_value()
            == "standard"
        )
        approval = page.locator('dialog input[name="privileged_approved"]')
        assert not approval.is_checked()
        assert page.locator("#editor-feedback").is_hidden()
        page.locator("#close-editor").click()
        checks.append(
            {"workflow": "asset create + inline error + root edit", "ok": True}
        )
        # Exercise both group names in table cells and asset-editor help text.
        payload = '<img src=x onerror="window.__storedXss=1">'
        page.locator('[data-action="new-group"]').click()
        assert page.locator("#editor-feedback").is_hidden(), "新弹窗不应显示旧错误"
        page.locator('dialog input[name="name"]').fill(payload)
        page.locator('dialog button[type="submit"]').click()
        page.get_by_role("cell", name=payload, exact=True).wait_for()
        page.locator('[data-action="new-asset"]').click()
        page.locator('dialog input[name="name"]').wait_for()
        assert page.evaluate("window.__storedXss || 0") == 0
        page.locator('dialog input[name="name"]').fill("分组选择验证")
        page.locator("dialog").get_by_label(payload, exact=True).check()
        page.locator('dialog button[type="submit"]').click()
        row = page.locator("tr").filter(has_text="分组选择验证")
        row.locator('[data-action="edit-asset"]').click()
        assert page.locator("dialog").get_by_label(payload, exact=True).is_checked()
        page.locator('dialog select[name="device_type"]').select_option("windows")
        assert page.locator("#asset-ssh-fields").is_hidden()
        page.locator('dialog button[type="submit"]').click()
        page.locator("#editor").wait_for(state="hidden")
        row.get_by_text("Windows", exact=True).wait_for()
        page.locator("#asset-group").select_option(label=payload)
        page.locator('[data-action="search-assets"]').click()
        page.locator(".toolbar").get_by_text("共 1 台", exact=True).wait_for()
        page.locator("tr").filter(has_text="分组选择验证").wait_for()
        assert page.locator('[data-action="edit-asset"]').count() == 1
        assert page.locator('[data-action="asset-next"]').is_disabled()
        assert (
            "仅监控分析"
            in page.locator("tr").filter(has_text="分组选择验证").inner_text()
        )
        assert page.locator('[data-action="test-asset"]').count() == 0
        row = page.locator("tr").filter(has_text="分组选择验证")
        row.locator('[data-action="edit-asset"]').click()
        assert (
            page.locator('dialog select[name="device_type"]').input_value() == "windows"
        )
        assert page.locator("dialog").get_by_label(payload, exact=True).is_checked()
        page.locator('dialog input[name="enabled"]').uncheck()
        page.locator('dialog button[type="submit"]').click()
        page.locator("tr").filter(has_text="分组选择验证").get_by_text(
            "已禁用"
        ).wait_for()
        assert page.locator('[data-action="diagnose-asset"]').count() == 0
        checks.append(
            {"workflow": "group assignment/filter + device-aware editing", "ok": True}
        )
        group = page.locator("tr").filter(has_text=payload)
        group.locator('[data-action="edit-group"]').click()
        page.locator('dialog input[name="name"]').fill("浏览器验证组")
        page.locator('dialog button[type="submit"]').click()
        page.get_by_role("cell", name="浏览器验证组", exact=True).wait_for()
        page.locator("tr").filter(has_text="浏览器验证组").locator(
            '[data-action="delete-group"]'
        ).click()
        page.get_by_role("cell", name="浏览器验证组", exact=True).wait_for(
            state="detached"
        )
        checks.append(
            {"workflow": "group create/edit/delete + stored HTML escaping", "ok": True}
        )
        page.locator("#asset-group").select_option("")
        page.locator('[data-action="search-assets"]').click()
        page.locator('[data-action="asset-next"]').wait_for()
        # Cross-page/filter selection and two-phase trust use the real UI/API/DB.
        page.locator('[data-action="keys-select-filter"]').click()
        page.locator("#key-target-count").get_by_text(
            "已选 3 台", exact=False
        ).wait_for()
        page.locator('[data-action="asset-next"]').click()
        assert "已选 3 台" in page.locator("#key-target-count").inner_text()
        page.locator('[data-action="keys-start"]').click()
        page.get_by_role("heading", name="批量获取 SSH 主机公钥", exact=True).wait_for()
        fresh = page.locator("tr").filter(has_text="UI 测试 · Linux 资产")
        changed = page.locator("tr").filter(has_text="公钥变化样本")
        failed_row = page.locator("tr").filter(has_text="获取失败样本")
        fresh.get_by_text("待确认", exact=True).wait_for()
        changed.get_by_text("公钥变化", exact=True).wait_for()
        failed_row.get_by_text("获取失败", exact=True).wait_for()
        for width in (1280, 1440, 1920):
            page.set_viewport_size({"width": width, "height": 1080})
            assert page.evaluate(
                "document.documentElement.scrollWidth <= window.innerWidth"
            )
            checks.append({"width": width, "page": "host-keys", "ok": True})
        page.set_viewport_size({"width": 1440, "height": 1080})
        page.screenshot(path=str(OUT / "host-keys-1440.png"), full_page=True)
        before = page.request.get(
            base + "/api/v1/platform/assets?device_type=linux"
        ).json()["items"]
        new_before = next(r for r in before if r["name"] == "UI 测试 · Linux 资产")
        old_key = next(r for r in before if r["name"] == "公钥变化样本")["host_key"]
        assert new_before["host_key"] == "" and old_key
        page.locator('[data-action="keys-select-new"]').click()
        fresh.locator(".key-candidate").wait_for()
        assert fresh.locator(".key-candidate").is_checked()
        assert not changed.locator(".key-candidate").is_checked()
        assert page.locator('[data-action="keys-confirm"]').is_disabled()
        page.locator("#key-verified").check()
        page.locator('[data-action="keys-confirm"]').click()
        fresh.get_by_text("已保存", exact=True).wait_for()
        middle = page.request.get(
            base + "/api/v1/platform/assets?device_type=linux"
        ).json()["items"]
        assert next(r for r in middle if r["id"] == new_before["id"])["host_key"]
        assert (
            next(r for r in middle if r["name"] == "公钥变化样本")["host_key"]
            == old_key
        )
        page.reload()
        changed.locator(".key-candidate").wait_for()
        assert not page.locator("#key-verified").is_checked()
        assert not changed.locator(".key-candidate").is_checked()
        changed.locator(".key-candidate").check()
        assert page.locator('[data-action="keys-confirm"]').is_disabled()
        page.locator("#key-verified").check()
        assert "替换 1 台" in page.locator('[data-action="keys-confirm"]').inner_text()
        page.locator('[data-action="keys-confirm"]').click()
        changed.get_by_text("已保存", exact=True).wait_for()
        after = page.request.get(
            base + "/api/v1/platform/assets?device_type=linux"
        ).json()["items"]
        assert (
            next(r for r in after if r["name"] == "公钥变化样本")["host_key"] != old_key
        )
        checks.append(
            {
                "workflow": "batch keys + cross-page selection + explicit new/changed trust + reload",
                "ok": True,
            }
        )
        page.locator('[data-action="keys-retry"]').click()
        page.get_by_text("待确认", exact=True).wait_for()
        assert page.locator(".key-candidate").count() == 1
        page.locator("tr").filter(has_text="获取失败样本").get_by_text(
            "待确认", exact=True
        ).wait_for()
        page.locator('[data-action="keys-select-new"]').click()
        page.locator("#key-verified").check()
        page.locator('[data-action="keys-confirm"]').click()
        page.locator("tr").filter(has_text="获取失败样本").get_by_text(
            "已保存", exact=True
        ).wait_for()
        page.locator('[data-action="keys-back"]').click()
        page.get_by_role("heading", name="最近的公钥获取批次", exact=True).wait_for()
        assert page.locator('[data-action="keys-open"]').count() == 2
        checks.append(
            {
                "workflow": "batch keys failed-only retry + persisted recent batches",
                "ok": True,
            }
        )
        page.locator('[data-page="feishu"]').click()
        page.locator('[data-action="new-member"]').click()
        page.locator('dialog input[name="open_id"]').fill("ou_browser_member")
        page.locator('dialog button[type="submit"]').click()
        member = page.locator("tr").filter(has_text="ou_browser_member")
        member.locator('[data-action="edit-member"]').click()
        assert (
            page.locator('dialog input[name="open_id"]').input_value()
            == "ou_browser_member"
        )
        assert (
            page.locator('dialog input[name="open_id"]').get_attribute("readonly")
            is not None
        )
        page.locator('dialog select[name="role"]').select_option("auditor")
        page.locator('dialog input[name="enabled"]').uncheck()
        page.locator('dialog button[type="submit"]').click()
        member.get_by_text("已停用").wait_for()
        assert "只读审计" in member.inner_text()
        member.locator('[data-action="edit-member"]').click()
        assert page.locator('dialog select[name="role"]').input_value() == "auditor"
        assert not page.locator('dialog input[name="enabled"]').is_checked()
        page.locator("#close-editor").click()
        checks.append(
            {"workflow": "member create/edit/disable persistence", "ok": True}
        )
        page.locator('#mute-form input[name="host_id"]').fill("991")
        page.locator('#mute-form input[name="trigger_id"]').fill("992")
        page.locator('#mute-form button[type="submit"]').click()
        page.locator('[data-action="unmute"][data-id="991:992"]').wait_for()
        page.locator('[data-action="unmute"][data-id="991:992"]').click()
        page.locator('[data-action="unmute"][data-id="991:992"]').wait_for(
            state="detached"
        )
        checks.append({"workflow": "Web mute create + early unmute", "ok": True})
        page.locator('[data-page="history"]').click()
        page.locator('[data-action="task-next"]').click()
        page.locator(".pagination").get_by_text("第 2 页 / 2 页").wait_for()
        assert page.locator('[data-action="task-next"]').is_disabled()
        page.locator("#task-status").select_option("partial")
        page.locator(".pagination").get_by_text("第 1 页 / 1 页").wait_for()
        assert page.locator('[data-action="task-prev"]').is_disabled()
        assert page.locator('[data-action="task-next"]').is_disabled()
        checks.append(
            {"workflow": "history pagination + filter resets page", "ok": True}
        )
        page.locator("#task-status").select_option("all")
        page.locator(".pagination").get_by_text("第 1 页 / 2 页").wait_for()
        # A response completing after navigation must not write into a removed form.
        pending = []
        page.route("**/api/v1/ask", lambda route: pending.append(route))
        page.locator('[data-page="diagnostics"]').click()
        page.locator('#ask-form textarea[name="question"]').fill("导航期间的问答")
        page.locator('#ask-form button[type="submit"]').click()
        page.wait_for_function(
            "document.querySelector('#ask-result').textContent.includes('正在查询')"
        )
        page.locator('[data-page="overview"]').click()
        page.locator(".hero").wait_for()
        assert len(pending) == 1
        pending[0].fulfill(json={"answer": "延迟返回的测试结论"})
        page.unroute("**/api/v1/ask")
        page.wait_for_timeout(100)
        checks.append({"workflow": "late answer after page navigation", "ok": True})
        page.locator("#toast").wait_for(state="hidden", timeout=8000)
        page.evaluate("document.fonts.ready")
        page.screenshot(path=str(OUT / "overview-1440.png"), full_page=True)
        page.locator('[data-page="assets"]').click()
        page.locator('[data-action="new-asset"]').wait_for()
        page.screenshot(path=str(OUT / "assets-1440.png"), full_page=True)
        page.locator('[data-page="history"]').click()
        page.locator('[data-action="report"]').first.click()
        page.get_by_text("证据与工具执行记录", exact=True).wait_for()
        page.screenshot(path=str(OUT / "diagnosis-1440.png"), full_page=True)
        page.locator("#theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.screenshot(path=str(OUT / "diagnosis-dark-1440.png"), full_page=True)
        checks.append({"workflow": "report, evidence, theme toggle", "ok": True})
        assert errors == [], errors
        assert failed == [], failed
        browser.close()
    (ROOT / "docs/UI-TEST-RESULTS.json").write_text(
        json.dumps(
            {
                "browser": "Chromium headless",
                "fixture": "disposable local database; no production data",
                "checks": checks,
                "javascript_errors": errors,
                "http_5xx": failed,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "passed": len(checks),
                "widths": [1280, 1440, 1920],
                "javascript_errors": errors,
                "http_5xx": failed,
            }
        )
    )
finally:
    server.terminate()
    server.wait(timeout=5)
    log.close()
