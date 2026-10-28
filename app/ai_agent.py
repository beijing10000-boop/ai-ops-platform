"""Feishu Q&A entrypoint using the shared native MCP agent."""

from .mcp_runtime import run

# Output contract only; task-specific analysis policy comes from enabled Skills.
QA_OUTPUT_CONTRACT = (
    "使用中文回答用户问题；简短问题直接回答，诊断结论要区分事实、"
    "推断与待核验事项。追问只使用已提供的可信上下文。"
)


async def ask(question, extra_context="", return_usage=False, event=None):
    prompt = QA_OUTPUT_CONTRACT
    result = await run(
        prompt,
        question[:3000],
        context=extra_context,
        return_usage=return_usage,
        **({"event": event} if event else {}),
    )
    if return_usage:
        text, usage = result
        return text or "模型未返回可显示的分析结论", usage
    return result or "模型未返回可显示的分析结论"
