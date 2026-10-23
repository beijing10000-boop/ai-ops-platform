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
        page.locator('[data-action="new-asset"]').click()
        page.locator('dialog input[name="name"]').fill("浏览器验证资产")
        page.locator('dialog button[type="submit"]').click()
        page.locator("#content").get_by_text("浏览器验证资产", exact=True).wait_for()
        row = page.locator("tr").filter(has_text="浏览器验证资产")
        row.locator('[data-action="edit-asset"]').click()
        page.locator('dialog input[name="username"]').fill("root")
        page.locator('dialog button[type="submit"]').click()
        page.get_by_role("status").filter(
            has_text="标准免 Agent 模式禁止 root"
        ).wait_for()
        page.locator("#close-editor").click()
        checks.append({"workflow": "asset create + rejected root edit", "ok": True})
        page.locator('[data-page="overview"]').click()
        page.locator(".hero").wait_for()
        page.locator('#toast').wait_for(state='hidden',timeout=8000)
        page.evaluate('document.fonts.ready')
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
