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
    "settings-1440.png",
    "connections-1440.png",
    "alerts-1440.png",
    "settings-ai-1440.png",
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
                "connections",
                "history",
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
                if name == "settings":
                    for tab in ("基础设置", "飞书配置", "AI 配置", "服务与维护"):
                        page.get_by_role("tab", name=tab, exact=True).click()
                        assert page.evaluate(
                            "document.documentElement.scrollWidth <= window.innerWidth"
                        ), (width, tab)
                checks.append({"width": width, "page": name, "ok": True})
        page.set_viewport_size({"width": 1440, "height": 1080})
        page.locator('nav [data-page="alerts"]').click()
        page.locator('[data-action="alert-next"]').click()
        page.locator(".pagination").get_by_text("第 2 页 / 2 页").wait_for()
        page.locator('#alert-filter select[name="status"]').select_option("recovered")
        page.locator('#alert-filter button[type="submit"]').click()
        page.locator(".pagination").get_by_text("第 1 页 / 1 页").wait_for()
        assert page.locator("tbody tr").count() == 8
        page.locator('#alert-filter input[name="q"]').fill("测试主机-3")
        page.locator('#alert-filter button[type="submit"]').click()
        page.locator("tbody tr").filter(has_text="测试主机-3").wait_for()
        assert page.locator("tbody tr").count() == 1
        page.locator('[data-action="analyze-event"]').click()
        page.locator(".context-banner").wait_for()
        assert page.locator('input[name="event_id"]').input_value() == "8003"
        page.locator('[data-action="clear-event"]').click()
        page.locator(".context-banner").wait_for(state="detached")
        assert page.locator('input[name="event_id"]').input_value() == ""
        page.locator('nav [data-page="alerts"]').click()
        page.locator('[data-action="reset-alert-filter"]').click()
        checks.append(
            {
                "workflow": "alert pagination + recovery/search filters + diagnostic event context",
                "ok": True,
            }
        )
        assert page.locator('nav [data-page="assets"]').count() == 0
        for retired in ("tools", "feishu", "ai"):
            assert page.locator(f'nav [data-page="{retired}"]').count() == 0
        assert "系统配置" in page.locator('nav [data-page="settings"]').inner_text()
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
        assert page.get_by_role("heading", name="诊断工具", exact=True).count() == 1
        assert page.get_by_role("heading", name="标准诊断流程", exact=True).count() == 1
        discovered = []

        def discover(route):
            discovered.append(route.request.url.split("provider=")[1])
            route.fulfill(
                json={
                    "provider": discovered[-1],
                    "ok": True,
                    "authorized_tools": ["fixture"],
                }
            )

        page.route("**/api/v1/platform/tools/discover?provider=*", discover)
        page.locator('[data-action="discover"]').click()
        page.locator("#toast").get_by_text("ssh_mcp：连接成功", exact=False).wait_for()
        assert sorted(discovered) == ["ssh_mcp", "zabbix_mcp"]
        page.unroute("**/api/v1/platform/tools/discover?provider=*")
        checks.append(
            {
                "workflow": "diagnostic tools and saved MCP detection in connections",
                "ok": True,
            }
        )
        page.locator('[data-page="settings"]').click()
        page.get_by_role("tab", name="基础设置", exact=True).click()
        page.locator('textarea[name="ai_alert_prompt"]').wait_for(state="attached")
        general = page.locator("#settings-settings-form")
        feishu = page.locator("#feishu-settings-form")
        ai = page.locator("#ai-settings-form")
        assert page.locator("form.settings-form").count() == 3
        assert len(
            page.locator("[id]").evaluate_all("nodes => nodes.map(n => n.id)")
        ) == len(
            set(page.locator("[id]").evaluate_all("nodes => nodes.map(n => n.id)"))
        )
        general.locator('input[name="web_public_host"]').fill("draft-host:8088")
        dialogs = []

        def handle_dialog(dialog):
            dialogs.append(dialog.message)
            if len(dialogs) == 1:
                dialog.dismiss()
            else:
                dialog.accept()

        page.on("dialog", handle_dialog)
        page.locator('nav [data-page="history"]').click()
        page.wait_for_function("location.hash === '#settings/general'")
        assert len(dialogs) == 1
        assert page.locator("#page-title").inner_text() == "系统配置"
        assert (
            general.locator('input[name="web_public_host"]').input_value()
            == "draft-host:8088"
        )
        page.get_by_role("tab", name="飞书配置", exact=True).click()
        feishu.locator('input[name="allowed_chat_ids"]').fill("oc_browser_draft")
        page.get_by_role("tab", name="AI 配置", exact=True).click()
        assert (
            general.locator('input[name="web_public_host"]').input_value()
            == "draft-host:8088"
        )
        assert (
            feishu.locator('input[name="allowed_chat_ids"]').input_value()
            == "oc_browser_draft"
        )
        assert (
            "Zabbix" in page.locator('textarea[name="ai_alert_prompt"]').input_value()
        )
        assert page.locator('textarea[name="ai_profile_budgets"]').count() == 0
        budget = page.get_by_role("spinbutton", name="标准分析 采集次数", exact=True)
        budget.fill("9")
        ai.locator('[data-action="validate-settings"]').click()
        ai.locator("[data-verify-result]").get_by_text(
            "填写内容校验通过", exact=False
        ).wait_for()
        assert general.locator("[data-verify-result]").inner_text() == ""
        with page.expect_response(
            lambda response: (
                response.request.method == "PUT"
                and response.url.endswith("/api/v1/settings")
            )
        ) as saved:
            ai.locator('button[type="submit"]').click()
        assert saved.value.ok
        values = page.request.get(base + "/api/v1/settings").json()
        assert json.loads(values["ai_profile_budgets"])["standard"]["calls"] == 9
        assert values["web_public_host"] == "127.0.0.1:8765"
        assert values["allowed_chat_ids"] == ""
        draft_checks = []

        def verify_draft(route):
            draft_checks.append(
                (route.request.url, route.request.post_data_json["values"])
            )
            route.fulfill(json={"ok": True, "message": "草稿连接验证通过"})

        page.route("**/api/v1/test/**", verify_draft)
        ai.locator('input[name="openai_model"]').fill("draft-model")
        ai.locator('[data-action="test-model"]').click()
        ai.locator("[data-verify-result]").get_by_text("草稿连接验证通过").wait_for()
        assert draft_checks[-1][1]["openai_model"] == "draft-model"
        assert "lark_app_id" not in draft_checks[-1][1]
        page.get_by_role("tab", name="飞书配置", exact=True).click()
        for action in ("verify-feishu", "verify-feishu-groups"):
            with page.expect_response(
                lambda response: "/api/v1/test/feishu" in response.url
            ):
                feishu.locator(f'[data-action="{action}"]').click()
            assert draft_checks[-1][1]["allowed_chat_ids"] == "oc_browser_draft"
            assert "openai_model" not in draft_checks[-1][1]
        page.unroute("**/api/v1/test/**")
        page.get_by_role("tab", name="AI 配置", exact=True).click()
        page.locator('textarea[name="ai_alert_prompt"]').fill(
            "临时测试提示词内容，需要恢复成项目提供的默认提示词"
        )
        page.locator('[data-action="reset-prompts"]').click()
        assert (
            "运维经理" in page.locator('textarea[name="ai_alert_prompt"]').input_value()
        )
        page.get_by_role("tab", name="基础设置", exact=True).click()
        general.locator('input[name="enabled_tool"]').first.uncheck()
        assert page.locator('textarea[name="disabled_tools"]').count() == 0
        general.locator('[data-action="validate-settings"]').click()
        general.locator("[data-verify-result]").get_by_text(
            "填写内容校验通过", exact=False
        ).wait_for()
        checks.append(
            {
                "workflow": "unified configuration + section jumps retain drafts + independent save/validation + budget/tool inputs + prompt restore",
                "ok": True,
            }
        )
        page.get_by_role("tab", name="飞书配置", exact=True).click()
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
        assert (
            general.locator('input[name="web_public_host"]').input_value()
            == "draft-host:8088"
        )
        checks.append(
            {
                "workflow": "unsaved navigation guard + tab changes and member updates retain drafts",
                "ok": True,
            }
        )
        # Mute management belongs to the alert center, not settings or sidebar.
        assert page.locator('nav [data-page="mutes"]').count() == 0
        assert page.locator("#mute-form").count() == 0
        page.locator('nav [data-page="alerts"]').click()
        page.get_by_role("button", name="暂时屏蔽").click()
        page.wait_for_url(base + "/#alerts/mutes")
        page.locator("#mute-form").wait_for()
        assert (
            page.get_by_role(
                "heading", name="当前生效的飞书告警屏蔽", exact=False
            ).count()
            == 1
        )
        page.locator('#mute-form input[name="host_id"]').fill("991")
        page.locator('#mute-form input[name="trigger_id"]').fill("992")
        page.locator('#mute-form button[type="submit"]').click()
        page.locator('[data-action="unmute"][data-id="991:992"]').wait_for()
        page.locator('[data-action="unmute"][data-id="991:992"]').click()
        page.locator('[data-action="unmute"][data-id="991:992"]').wait_for(
            state="detached"
        )
        page.get_by_role("button", name="告警记录").click()
        page.wait_for_url(base + "/#alerts")
        page.get_by_role("heading", name="告警事件").wait_for()
        page.goto(base + "/#mutes")
        page.wait_for_url(base + "/#alerts/mutes")
        page.locator("#mute-form").wait_for()
        checks.append(
            {
                "workflow": "alert center tabs + Web mute create/unmute + legacy link",
                "ok": True,
            }
        )
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
        task_id = page.locator('tbody [data-action="report"]').first.get_attribute(
            "data-id"
        )
        page.locator('#history-filter input[name="q"]').fill(task_id)
        page.locator('#history-filter button[type="submit"]').click()
        page.locator(".pagination").get_by_text("第 1 页 / 1 页").wait_for()
        assert page.locator('tbody [data-action="report"]').count() == 2
        page.locator('#history-filter input[name="q"]').fill("")
        page.locator('#history-filter button[type="submit"]').click()
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
        page.locator('[data-page="settings"]').click()
        page.get_by_role("tab", name="基础设置", exact=True).click()
        page.screenshot(path=str(OUT / "settings-1440.png"), full_page=True)
        page.get_by_role("tab", name="AI 配置", exact=True).click()
        page.screenshot(path=str(OUT / "settings-ai-1440.png"), full_page=True)
        page.get_by_role("tab", name="服务与维护", exact=True).click()
        page.locator('[data-action="runtime-status"]').click()
        page.locator("#runtime-result .runtime-summary").wait_for()
        assert not page.locator("#runtime-result pre").count()
        page.locator('[data-page="alerts"]').click()
        page.locator("#alert-filter").wait_for()
        page.screenshot(path=str(OUT / "alerts-1440.png"), full_page=True)
        page.locator('[data-page="connections"]').click()
        page.locator("#connection-tools").wait_for()
        page.screenshot(path=str(OUT / "connections-1440.png"), full_page=True)
        for old, new in (
            ("ai", "settings/ai"),
            ("feishu", "settings/feishu"),
            ("tools", "connections/tools"),
        ):
            page.goto(base + "/#" + old)
            page.wait_for_url(base + "/#" + new)
            page.locator(
                "#ai-settings-form"
                if old == "ai"
                else "#feishu-settings-form"
                if old == "feishu"
                else "#connection-tools"
            ).wait_for()
        checks.append(
            {
                "workflow": "legacy configuration/tools bookmarks redirect to merged sections",
                "ok": True,
            }
        )
        page.locator('[data-page="history"]').click()
        page.locator('[data-action="report"]').first.click()
        page.get_by_text("证据与工具执行记录", exact=True).wait_for()
        assert page.locator(".report-answer h3").count() == 3
        with page.expect_download() as downloaded:
            page.locator('[data-action="download-report"]').click()
        exported = Path(downloaded.value.path()).read_text()
        assert "AI 运维诊断报告" in exported and "诊断不足" in exported
        assert "Trace ID" in exported
        unsafe = page.evaluate(
            "OpsUI.answer('## 结论\\n<img src=x onerror=window.bad=1> **证据**\\n```html\\n<script>window.bad=1</script>\\n```')"
        )
        assert (
            "<img" not in unsafe
            and "<script>" not in unsafe
            and "<strong>证据</strong>" in unsafe
        )
        page.screenshot(path=str(OUT / "diagnosis-1440.png"), full_page=True)
        page.locator("#theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.screenshot(path=str(OUT / "diagnosis-dark-1440.png"), full_page=True)
        checks.append({"workflow": "report, evidence, theme toggle", "ok": True})
        running_id = page.request.get(base + "/__ui_running").json()["task_id"]
        detail_requests = []
        page.on(
            "request",
            lambda request: (
                detail_requests.append(request.url)
                if request.url.endswith("/tasks/" + running_id)
                else None
            ),
        )
        page.goto(base + "/#report/" + running_id)
        page.locator("details.evidence summary").first.click()
        with page.expect_response(
            lambda response: response.url.endswith("/tasks/" + running_id + "/status")
        ):
            pass
        assert len(detail_requests) == 1
        assert page.locator("details.evidence").first.get_attribute("open") is not None
        page.request.post(base + "/__ui_progress")
        with page.expect_response(
            lambda response: response.url.endswith("/tasks/" + running_id)
        ):
            pass
        page.wait_for_function(
            "document.querySelectorAll('details.evidence').length === 2"
        )
        assert page.locator("details.evidence").first.get_attribute("open") is not None
        assert "AI 分析中" in page.locator(".report-progress").inner_text()
        checks.append(
            {
                "workflow": "safe report formatting/export + lightweight polling preserves open evidence",
                "ok": True,
            }
        )
        for role in ("operator", "auditor", "ops_admin"):
            page.goto(base + "/__ui_login?role=" + role)
            page.locator('nav [data-page="connections"]').click()
            page.locator("#connection-tools").wait_for()
            assert (
                page.get_by_role("heading", name="工具注册表", exact=True).count() == 1
            )
            if role == "ops_admin":
                page.locator("#ssh_mcp-form").wait_for()
                page.locator('nav [data-page="settings"]').click()
                page.locator("#ai-settings-form").wait_for(state="attached")
                assert page.locator('input[name="feishu_admin_open_ids"]').count() == 0
                assert page.locator('input[name="enabled_tool"]').count() == 0
                assert page.locator('[data-action="new-member"]').count() == 0
            else:
                assert page.locator("form.connection-form").count() == 0
                assert page.locator('[data-action="discover"]').count() == 0
                assert page.locator('nav [data-page="settings"]').count() == 0
                assert page.request.get(base + "/api/v1/settings").status == 403
            checks.append(
                {
                    "workflow": role + " retains scoped access after consolidation",
                    "ok": True,
                }
            )
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
