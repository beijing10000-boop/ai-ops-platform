"""Feishu Q&A entrypoint using the shared native MCP agent."""

from .mcp_runtime import run

# Output contract only; task-specific analysis policy comes from enabled Skills.
QA_OUTPUT_CONTRACT = (
    "使用中文回答用户问题；简短问题直接回答。诊断类回答分三部分写清："
    "已确认事实（注明证据编号）、高可信推断、待验证的假设与验证方法；"
    "证据不足时写明缺口，不编造。追问只使用已提供的可信上下文，需要新数据时调用工具重新核验。"
)


async def ask(
    question, extra_context="", return_usage=False, event=None, actor="system"
):
    """`event` set: a follow-up in that alert's thread (same host, chat question)."""
    result = await run(
        QA_OUTPUT_CONTRACT,
        question[:3000],
        context=extra_context,
        return_usage=return_usage,
        actor=actor,
        **({"event": event, "follow_up": True} if event else {}),
    )
    if return_usage:
        text, usage = result
        return text or "模型未返回可显示的分析结论", usage
    return result or "模型未返回可显示的分析结论"
