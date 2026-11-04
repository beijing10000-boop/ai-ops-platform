"""Chat replies in Feishu show Markdown that lark_md cannot as what it can.

Production (2026-10-30 – 11-04): most Q&A answers had "## 已确认事实" or
"# … 报告" headings and inline code (one had 108 backticks); a v1 card's
lark_md shows **bold**, but its "#", backticks and fences as typed. Alert
cards (CardBody) and the Web report are not touched.
"""

import re

import pytest

from app import main, qa_worker, worker
from app.mcp_runtime import readable_report_answer
from test_audit_followup import chat

REPORT = "http://ops.example.com:8088/#report/" + "0" * 32
ANSWER = (
    "# 主机巡检报告\n\n## 已确认事实\n"
    "- 域名 `erp.example.com` 解析到 192.0.2.10（E1）\n"
    "- 可用内存 8192 MB（E2，E3）\n\n"
    "### 1. Nginx 状态 ###\n运行中，监听 `:443`（E4）。\n\n"
    "```bash\nsystemctl status nginx\nss -ltnp | grep 443\n```\n\n"
    "**处理建议**\n1. 检查 ``/etc/nginx/conf.d/erp.conf``\n"
    f"2. 查看 [报告]({REPORT})"
)
SCOPE = (
    "诊断范围（平台生成）\n- 目标：web-01（地址 192.0.2.10）\n"
    "## 能力说明\n- 日志 MCP：`log_search` 超时（E5）"
)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    merged = {"web_protocol": "http", "web_public_host": "ops.example.com:8088"}
    monkeypatch.setattr(worker, "cfg", lambda key: merged.get(key, ""))


def shown_as_typed(text):
    """Marks lark_md would show as they are, and evidence ids."""
    return [
        line
        for line in text.splitlines()
        if line.lstrip().startswith("#") or "\x60" in line or re.search(r"E\d", line)
    ]


def test_headings_become_bold_and_code_loses_its_backticks():
    text = qa_worker.reply_text({"chat_scope": SCOPE}, ANSWER)
    assert text == (
        "**主机巡检报告**\n\n**已确认事实**\n"
        "- 域名 erp.example.com 解析到 192.0.2.10\n"
        "- 可用内存 8.00 GiB\n\n"
        "**1. Nginx 状态**\n运行中，监听 :443。\n\n"
        "systemctl status nginx\nss -ltnp | grep 443\n\n"
        "**处理建议**\n1. 检查 /etc/nginx/conf.d/erp.conf\n"
        f"2. 查看 [报告]({REPORT})\n\n"
        # The platform's scope reads the same way.
        "诊断范围（平台生成）\n- 目标：web-01（地址 192.0.2.10）\n"
        "**能力说明**\n- 日志 MCP：log_search 超时"
    )
    assert not shown_as_typed(text)


def test_a_heading_already_in_bold_is_not_bolded_twice():
    text = qa_worker.reply_text(
        {},
        "**已确认事实**\n- 磁盘 / 使用率 91%\n## **待验证假设**\n"
        "## 结论：**日志未轮转**\n##已确认\n###　补查\n#tag 不是标题",
    )
    assert text == (
        "**已确认事实**\n- 磁盘 / 使用率 91%\n**待验证假设**\n"
        "**结论：日志未轮转**\n**已确认**\n**补查**\n#tag 不是标题"
    )


def test_a_table_becomes_one_line_per_row():
    text = qa_worker.reply_text(
        {},
        "各项指标：\n\n| 指标 | 当前值 |\n|---|---:|\n| CPU | 95%（E1） |\n"
        "| 内存 | `12 GB` |\n| 状态 \\| 备注 | |\n\n以上。",
    )
    assert text == (
        "各项指标：\n\n**指标 · 当前值**\n- CPU · 95%\n- 内存 · 12.00 GiB\n"
        "- 状态 | 备注 · -\n\n以上。"
    )


def test_what_a_code_block_holds_is_kept_as_written():
    # A shell comment in a fence is code, not a heading; a fence the answer
    # never closed keeps the rest as code.
    text = qa_worker.reply_text(
        {}, "查看监听：\n```\n# 只看 443\nss -ltnp | grep `cat port`\n"
    )
    assert text == "查看监听：\n# 只看 443\nss -ltnp | grep `cat port`"


def test_an_unfinished_reply_reads_the_same():
    text = qa_worker.unfinished_text(
        {"chat_scope": SCOPE},
        "## 分析未完成\n模型未完成最终诊断：`ssh_collect` 超时（E2）。\n\n"
        "### 建议\n1. 重试 `log_search`",
    )
    assert text == (
        "模型未完成最终诊断：ssh_collect 超时。\n\n**处理建议**\n1. 重试 log_search"
        "\n\n诊断范围（平台生成）\n- 目标：web-01（地址 192.0.2.10）\n"
        "**能力说明**\n- 日志 MCP：log_search 超时"
    )


def test_the_chat_card_and_its_limitations_end_to_end(monkeypatch):
    body = chat(
        monkeypatch,
        "erp 站点正常吗",
        ANSWER,
        ["`log_search` 超时（E5），未取得 Nginx 日志"],
    )
    reply = body.split("\n\n---\n")[0]
    assert reply.startswith("**主机巡检报告**\n\n**已确认事实**\n"), reply
    assert "\n- log_search 超时，未取得 Nginx 日志" in reply
    assert not shown_as_typed(reply)
    # The Web report keeps the answer as the model wrote it.
    assert "## 已确认事实" in readable_report_answer(ANSWER)
