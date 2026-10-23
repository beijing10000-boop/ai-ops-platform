"""Mock the Responses API and MCP ClientSession without network."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app import ai_agent, mcp_runtime

class Item:
    def __init__(self, kind, name="", call_id="", arguments="{}"):
        self.type=kind
        self.name=name
        self.call_id=call_id
        self.arguments=arguments
    def model_dump(self, exclude_none=True):
        return {"type":self.type, "name":self.name, "call_id":self.call_id, "arguments":self.arguments}

class Context:
    def __init__(self, value):self.value=value
    async def __aenter__(self):return self.value
    async def __aexit__(self,*args):return False

def setup(monkeypatch, calls, final_text="分析完成"):
    client_session=SimpleNamespace(
        initialize=AsyncMock(),
        list_tools=AsyncMock(return_value=SimpleNamespace(tools=[SimpleNamespace(name="event_get", description="", inputSchema={"type":"object","properties":{}})])),
        call_tool=AsyncMock(return_value=SimpleNamespace(isError=False, content=[SimpleNamespace(text="{}")]))
    )
    captured=[]
    index=[0]
    async def responses_create(**kwargs):
        captured.append(kwargs)
        i=index[0];index[0]+=1
        if i==0:return SimpleNamespace(output=calls, output_text="")
        return SimpleNamespace(output=[], output_text=final_text)
    model=SimpleNamespace(responses=SimpleNamespace(create=responses_create))
    monkeypatch.setattr(ai_agent, "read_setting", lambda k: {
        "mcp_url":"http://example.invalid/mcp","openai_api_key":"unit-test",
        "openai_model":"test-model","openai_base_url":"https://example.invalid/v1"
    }.get(k, ""))
    monkeypatch.setattr(mcp_runtime,"streamablehttp_client",lambda *a,**k:Context(("read","write",None)))
    monkeypatch.setattr(mcp_runtime,"ClientSession",lambda *a,**k:Context(client_session))
    monkeypatch.setattr(mcp_runtime,"AsyncOpenAI",lambda **kwargs:Context(model))
    monkeypatch.setattr(mcp_runtime,"read_setting",lambda k: {"mcp_url":"http://example.invalid/mcp","openai_api_key":"unit-test","openai_model":"test-model","openai_base_url":"https://example.invalid/v1","ai_tool_loading":"full"}.get(k,""))
    return client_session,captured

def test_ten_calls_get_ten_outputs_but_only_four_executed_in_standard(monkeypatch):
    calls=[Item("function_call","event_get",str(i)) for i in range(10)]
    m,requests=setup(monkeypatch,calls)
    assert asyncio.run(ai_agent.ask("状态?"))=="分析完成"
    outputs=[x for x in requests[1]["input"] if isinstance(x,dict) and x.get("type")=="function_call_output"]
    assert len(outputs)==10
    assert m.call_tool.await_count==4
    assert "budget exhausted" in outputs[-1]["output"]

def test_disallowed_tool_is_not_executed(monkeypatch):
    m,requests=setup(monkeypatch,[Item("function_call","host_delete","x")])
    asyncio.run(ai_agent.ask("查看主机"))
    assert m.call_tool.await_count==0
    output=[x for x in requests[1]["input"] if isinstance(x,dict) and x.get("type")=="function_call_output"]
    assert json.loads(output[0]["output"])=={"error":"tool absent from MCP discovery"}

def test_model_finishes_without_calls(monkeypatch):
    m,requests=setup(monkeypatch,[])
    # Responses mock returns no calls immediately, so empty output_text fallback
    assert asyncio.run(ai_agent.ask("查询"))=="模型未返回可显示的分析结论"
    assert m.call_tool.await_count==0


def test_native_tools_are_not_filtered():
    remote=[SimpleNamespace(name="graph_get",description="graph",inputSchema={"type":"object","properties":{"graphids":{"type":"array"}}}), SimpleNamespace(name="custom_mcp_tool",description="",inputSchema={"type":"object","properties":{}})]
    definitions=mcp_runtime.native_tools(remote)
    assert [tool["name"] for tool in definitions]==["graph_get","custom_mcp_tool"]
    assert definitions[0]["parameters"]==remote[0].inputSchema

def test_token_usage_aggregation_helpers():
    from types import SimpleNamespace
    first=SimpleNamespace(usage=SimpleNamespace(input_tokens=120, output_tokens=30, total_tokens=150))
    second=SimpleNamespace(usage={"input_tokens":80,"output_tokens":20,"total_tokens":100})
    assert mcp_runtime.usage_counts(first)=={"input":120,"output":30,"total":150}
    assert mcp_runtime.usage_counts(second)=={"input":80,"output":20,"total":100}
    assert mcp_runtime.usage_counts(SimpleNamespace(usage=None)) is None
    assert "250" in mcp_runtime.format_usage({"input":200,"output":50,"total":250,"available":True})
    assert "未返回用量" in mcp_runtime.format_usage({"available":False})
