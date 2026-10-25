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
    "diagnostics-1440.png",
    "diagnosis-1440.png",
    "diagnosis-dark-1440.png",
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
        assert page.locator('nav [data-page="assets"]').count() == 0
        page.locator('[data-page="diagnostics"]').click()
        assert page.locator('input[name="asset_id"]').count() == 0
        page.locator("#host-search").fill("Linux")
        page.locator('[data-action="search-hosts"]').click()
        page.locator("#host-search-result").get_by_text(
            "已查询 1 台主机", exact=False
        ).wait_for()
        page.locator('select[name="zabbix_hostid"]').select_option("10001")
        page.locator('select[name="profile"]').select_option("quick")
        page.locator('[data-action="validate-diagnostic"]').click()
        page.locator("#diagnostic-form [data-verify-result]").get_by_text(
            "诊断参数验证通过", exact=False
        ).wait_for()
        page.locator("#host-search").fill("10002")
        page.locator('[data-action="search-hosts"]').click()
        page.locator('select[name="zabbix_hostid"] option[value="10002"]').wait_for(
            state="attached"
        )
        assert (
            page.locator('select[name="zabbix_hostid"] option[value="10001"]').count()
            == 0
        )
        page.locator("#host-search").fill("")
        page.locator('[data-action="search-hosts"]').click()
        page.locator("#host-search-result").get_by_text(
            "已查询 3 台主机", exact=False
        ).wait_for()
        assert page.evaluate("window.__storedXss || 0") == 0
        assert (
            "<img src=x"
            in page.locator(
                'select[name="zabbix_hostid"] option[value="10003"]'
            ).inner_text()
        )
        checks.append(
            {
                "workflow": "removed local inventory + live Zabbix host search/selection + preflight + escaping",
                "ok": True,
            }
        )
        page.locator('[data-page="connections"]').click()
        page.locator('#zabbix_mcp-form input[name="mcp_url"]').fill(
            "http://127.0.0.1:9999/mcp"
        )
        page.locator('#zabbix_mcp-form [data-action="validate-connection"]').click()
        page.locator("#zabbix_mcp-form [data-verify-result]").get_by_text(
            "填写内容校验通过", exact=False
        ).wait_for()
        assert page.request.get(base + "/api/v1/settings").json()["mcp_url"] == ""
        page.locator('#zabbix_mcp-form button[type="submit"]').click()
        page.locator('#ssh_mcp-form input[name="ssh_mcp_url"]').fill(
            "http://127.0.0.1:9099/mcp"
        )
        page.locator('#ssh_mcp-form input[name="ssh_mcp_token"]').fill("test-ssh-token")
        page.locator('#ssh_mcp-form select[name="ssh_mcp_enabled"]').select_option(
            "true"
        )
        page.locator('#ssh_mcp-form button[type="submit"]').click()
        page.locator('[data-page="overview"]').click()
        page.locator(".hero").wait_for()
        page.locator('[data-page="connections"]').click()
        page.locator('#ssh_mcp-form input[name="ssh_mcp_url"]').wait_for()
        assert (
            page.locator('#ssh_mcp-form input[name="ssh_mcp_token"]').input_value()
            == "********"
        )
        assert page.locator('[data-action="new-credential"]').count() == 0
        checks.append(
            {
                "workflow": "two MCP forms + draft validation + masked token persistence",
                "ok": True,
            }
        )
        page.locator('[data-page="ai"]').click()
        page.locator('textarea[name="ai_alert_prompt"]').wait_for()
        assert (
            "Zabbix" in page.locator('textarea[name="ai_alert_prompt"]').input_value()
        )
        assert page.locator('textarea[name="ai_profile_budgets"]').count() == 0
        budget = page.get_by_role("spinbutton", name="标准分析 采集次数", exact=True)
        budget.fill("9")
        page.locator('[data-action="validate-settings"]').click()
        page.locator("[data-verify-result]").get_by_text(
            "填写内容校验通过", exact=False
        ).wait_for()
        page.locator('#settings-form button[type="submit"]').click()
        page.locator('textarea[name="ai_alert_prompt"]').fill(
            "临时测试提示词内容，需要恢复成项目提供的默认提示词"
        )
        page.locator('[data-action="reset-prompts"]').click()
        assert (
            "运维经理" in page.locator('textarea[name="ai_alert_prompt"]').input_value()
        )
        page.locator('[data-page="settings"]').click()
        page.locator('input[name="enabled_tool"]').first.uncheck()
        assert page.locator('textarea[name="disabled_tools"]').count() == 0
        page.locator('[data-action="validate-settings"]').click()
        page.locator("[data-verify-result]").get_by_text(
            "填写内容校验通过", exact=False
        ).wait_for()
        checks.append(
            {
                "workflow": "budget number inputs + tool checkboxes + default prompt restore",
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
        page.locator('[data-page="diagnostics"]').click()
        page.locator('[data-action="search-hosts"]').wait_for()
        page.screenshot(path=str(OUT / "diagnostics-1440.png"), full_page=True)
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
