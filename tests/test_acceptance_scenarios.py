"""十个可复现的诊断验收场景。

每个场景用固定的 Zabbix MCP / SSH MCP 返回数据与脚本化的模型，校验平台层面
可以客观判定的行为：诊断路径与设备类型、预采集的证据维度、加载的 Skill、
事实与推断的代码核对、重复调用与并行执行、失败后继续、降级说明以及耗时与
Token 统计。模型输出是脚本，诊断准确性不依赖 AI 自我评价。
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import json
import re
import time
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from mcp.types import Tool, ToolAnnotations

from app import main, mcp_runtime, worker
from app.integrations import ssh_mcp, zabbix
from app.orchestrator import tasks

BEIJING = ZoneInfo("Asia/Shanghai")


def alert_clock():
    """An alert ten minutes ago, so the ±30 min history window is partly in the past."""
    return int(time.time()) - 600


def event_for(name, trigger_id, clock, host_id="10101", event_id="880001"):
    moment = datetime.fromtimestamp(clock, BEIJING)
    return {
        "event_id": event_id,
        "event_value": "1",
        "event_name": name,
        "severity": "4",
        "host_id": host_id,
        "host_name": "host-" + host_id,
        "trigger_id": trigger_id,
        "event_date": moment.strftime("%Y.%m.%d"),
        "event_time": moment.strftime("%H:%M:%S"),
    }


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_super',0)"
        )


def remote(name, props=None, required=()):
    return Tool(
        name=name,
        inputSchema={
            "type": "object",
            "properties": props or {},
            "required": list(required),
        },
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    )


# --- fixtures of the two MCP servers -------------------------------------------------


class Zabbix:
    """initMAX-style Zabbix MCP: arguments arrive through extra_params."""

    def __init__(self, host, trigger_items, items, events, series, trend):
        self.host, self.trigger_items, self.items = host, trigger_items, items
        self.events, self.series, self.trend = events, series, trend
        self.calls = []

    async def list_tools(self):
        return SimpleNamespace(
            tools=[
                remote(
                    name,
                    {"output": {"type": "string"}, "extra_params": {"type": "object"}},
                )
                for name in sorted(zabbix.READ_TOOLS)
            ],
            nextCursor=None,
        )

    async def call_tool(self, name, args):
        query = {**args.get("extra_params", {}), **args}
        self.calls.append((name, query))
        return SimpleNamespace(
            structuredContent={"result": self.rows(name, query)},
            content=[],
            isError=False,
        )

    def rows(self, name, query):
        if name == "host_get":
            return [self.host]
        if name == "item_get":
            if "triggerids" in query:
                return self.trigger_items
            words = (query.get("search") or {}).get("key_")
            rows = self.items + self.trigger_items
            if words:
                rows = [
                    row for row in rows if any(word in row["key_"] for word in words)
                ]
            return rows[: query.get("limit", 100)]
        if name == "event_get":
            return self.events
        if name == "history_get":
            rows = []
            for ident in query["itemids"]:
                value = self.series.get(ident)
                if value is None:
                    continue
                for clock in range(query["time_from"], query["time_till"] + 1, 60):
                    rows.append(
                        {
                            "itemid": ident,
                            "clock": str(clock),
                            "value": str(value(clock)),
                        }
                    )
            return rows[: query.get("limit", 120)]
        if name == "trend_get":
            rows = []
            for ident in query["itemids"]:
                low, avg, high = self.trend.get(ident, (None, None, None))
                if avg is None:
                    continue
                for hour in range(0, 7 * 24, 6):
                    rows.append(
                        {
                            "itemid": ident,
                            "clock": str(query["time_from"] + hour * 3600),
                            "num": "60",
                            "value_min": str(low),
                            "value_avg": str(avg),
                            "value_max": str(high),
                        }
                    )
            return rows
        return []


CATALOG = [
    ("cpu", "ssh_diagnose_cpu"),
    ("memory", "ssh_diagnose_memory"),
    ("processes", "ssh_diagnose_processes"),
    ("memory_processes", "ssh_diagnose_memory_processes"),
    ("pressure", "ssh_diagnose_pressure"),
    ("oom", "ssh_diagnose_oom"),
    ("io", "ssh_diagnose_io"),
    ("disk", "ssh_diagnose_disk"),
    ("mount_health", "ssh_diagnose_mounts"),
    ("failed_services", "ssh_diagnose_failed_services"),
    ("system", "ssh_diagnose_system"),
    ("java", "ssh_diagnose_java"),
    ("jvm", "ssh_diagnose_jvm"),
    ("syslog", "ssh_diagnose_syslog"),
    ("nginx", "ssh_diagnose_nginx"),
    ("nginx_access", "ssh_diagnose_nginx_access"),
    ("service_detail", "ssh_diagnose_service_detail"),
    ("service_map", "ssh_diagnose_service_map"),
]
COLLECTABLE = [
    "cpu",
    "memory",
    "processes",
    "memory_processes",
    "pressure",
    "oom",
    "io",
    "disk",
    "mount_health",
    "failed_services",
    "system",
]
WINDOW = {"since": {"type": "integer"}, "until": {"type": "integer"}}
SCHEMAS = {
    "ssh_diagnose_syslog": {**WINDOW, "unit": {"type": "string"}},
    "ssh_diagnose_nginx_access": {**WINDOW, "status": {"type": "string"}},
    "ssh_diagnose_nginx": {"minutes": {"type": "integer"}},
    "ssh_diagnose_jvm": {"pid": {"type": "integer"}},
    "ssh_diagnose_oom": {"minutes": {"type": "integer"}},
    "ssh_diagnose_service_detail": {
        "service": {"type": "string"},
        "minutes": {"type": "integer"},
    },
}


class SSH:
    """SSH MCP v0.6: per-tool canned results, collect sessions, a token catalog."""

    def __init__(self, results, resolve=None, delay=0.0):
        self.results = results
        self.resolve = resolve or {
            "status": "success",
            "host_id": 7,
            "address": "10.0.0.11",
            "revision": 3,
            "name": "app-01",
            "zabbix_hostid": "10101",
            "asset_type": "linux",
            "mode": "standard",
        }
        self.delay = delay
        self.calls, self.spans = [], []

    async def list_tools(self):
        tools = [
            remote("ssh_resolve_host", {"zabbix_hostid": {"type": "string"}}),
            remote("ssh_resolve_target", {"address": {"type": "string"}}),
            remote("ssh_list_tool_catalog"),
            remote(
                "ssh_collect",
                {
                    "host_id": {"type": "integer"},
                    "expected_revision": {"type": "integer"},
                    "actions": {"type": "array"},
                    "service": {"type": "string"},
                    "minutes": {"type": "integer"},
                },
                ["host_id", "actions"],
            ),
        ]
        for _, name in CATALOG:
            props = {
                "host_id": {"type": "integer"},
                "expected_revision": {"type": "integer"},
                **SCHEMAS.get(name, {}),
            }
            required = ["host_id"] + (
                ["service"] if name == "ssh_diagnose_service_detail" else []
            )
            required += ["pid"] if name == "ssh_diagnose_jvm" else []
            tools.append(remote(name, props, required))
        return SimpleNamespace(tools=tools, nextCursor=None)

    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        if name == "ssh_list_tool_catalog":
            entries = [{"id": action, "tool": tool} for action, tool in CATALOG]
            entries.append(
                {
                    "id": "collect",
                    "tool": "ssh_collect",
                    "params": [{"name": "actions", "choices": COLLECTABLE}],
                }
            )
            return reply({"result": entries})
        if name in ("ssh_resolve_host", "ssh_resolve_target"):
            return reply(self.resolve)
        started = time.monotonic()
        if self.delay:
            await asyncio.sleep(self.delay)
        self.spans.append((name, started, time.monotonic()))
        if name == "ssh_collect":
            steps, findings = [], []
            for action in args["actions"]:
                tool = dict(CATALOG)[action]
                step = dict(self.result(tool, args))
                step["action"] = action
                steps.append(step)
                findings += [
                    {**f, "source_action": action} for f in step.get("findings", [])
                ]
            status = (
                "success"
                if all(s.get("status") == "success" for s in steps)
                else "partial"
            )
            return reply(
                {
                    "host_id": args["host_id"],
                    "action": "collect",
                    "status": status,
                    "summary": {"steps": steps, "completed": len(steps)},
                    "findings": findings,
                }
            )
        return reply({"host_id": args["host_id"], **self.result(name, args)})

    def result(self, name, args):
        value = self.results.get(name)
        if callable(value):
            value = value(args)
        return value or {
            "status": "success",
            "summary": {"metrics": []},
            "findings": [],
        }


def reply(data):
    return SimpleNamespace(structuredContent=data, content=[], isError=False)


def finding(metric, value, level="warning", hint="线索"):
    return {
        "level": level,
        "metric": metric,
        "value": value,
        "threshold": 1,
        "hint": hint,
    }


# --- a scripted model -----------------------------------------------------------------


class Call:
    type = "function_call"

    def __init__(self, ident, name, args):
        self.call_id, self.name, self.arguments = ident, name, json.dumps(args)

    def model_dump(self, **kwargs):
        return {
            "type": self.type,
            "name": self.name,
            "arguments": self.arguments,
            "call_id": self.call_id,
        }


def answer(text, calls=()):
    return SimpleNamespace(
        output=list(calls),
        output_text=text,
        status="completed",
        usage=SimpleNamespace(
            input_tokens=3000,
            output_tokens=400,
            total_tokens=3400,
            input_tokens_details=SimpleNamespace(cached_tokens=2000),
        ),
    )


def opening(request):
    return json.loads(request["input"][0]["content"])


def prefetched(request, tool):
    """Evidence ids of a prefetched tool, as the model sees them."""
    return [
        item["result"]["evidence_id"]
        for item in opening(request)["evidence"].get("prefetched", [])
        if item["tool"] == tool
    ]


def output_of(request, call_id):
    """The JSON view the platform returned for one of the model's calls."""
    for item in request["input"]:
        if item.get("type") == "function_call_output" and item["call_id"] == call_id:
            text = item["output"]
            return json.loads(text[text.index("{") :])
    raise AssertionError("no output for " + call_id)


class Model:
    """Rounds are functions of the request; the last one answers any further
    round (for example after the platform asked for more evidence)."""

    def __init__(self, *rounds):
        self.rounds, self.requests = list(rounds), []

    async def create(self, **request):
        self.requests.append(request)
        step = self.rounds.pop(0) if len(self.rounds) > 1 else self.rounds[0]
        return step(request)


def run_alert(event, model):
    _, usage = asyncio.run(
        mcp_runtime.run(
            worker.alert_instructions(),
            json.dumps({"alert": event}, ensure_ascii=False),
            client=SimpleNamespace(responses=SimpleNamespace(create=model.create)),
            event=event,
            return_usage=True,
        )
    )
    return tasks.get(usage["task_id"]), usage


def rig(monkeypatch, zabbix_server=None, ssh_server=None, ssh_enabled=True):
    config = {
        "openai_model": "fixture",
        "mcp_url": "http://zabbix.invalid/mcp",
        "ssh_mcp_enabled": "true" if ssh_enabled else "false",
        "ssh_mcp_url": "http://ssh.invalid/mcp",
        "ssh_mcp_token": "never-expose-token",
    }
    monkeypatch.setattr(mcp_runtime, "read_setting", lambda key: config.get(key, ""))

    @asynccontextmanager
    async def zabbix_connect(*args, **kwargs):
        if zabbix_server is None:
            raise AssertionError("Zabbix must not be used")
        yield zabbix_server

    @asynccontextmanager
    async def ssh_connect(read_setting, **kwargs):
        if ssh_server is None:
            raise AssertionError("SSH MCP must not be used for this device")
        if read_setting("ssh_mcp_enabled") != "true":
            raise ssh_mcp.IntegrationError("SSH MCP 未启用")
        yield SimpleNamespace(session=ssh_server)

    monkeypatch.setattr(zabbix, "connect", zabbix_connect)
    monkeypatch.setattr(ssh_mcp, "configured", ssh_connect)


LINUX_HOST = {
    "hostid": "10101",
    "host": "app-01",
    "name": "app-01",
    "status": "0",
    "parentTemplates": [{"templateid": "1", "name": "Linux by Zabbix agent"}],
    "interfaces": [{"type": "1", "ip": "10.0.0.11", "main": "1"}],
}


def item(ident, key, value, value_type="0"):
    return {
        "itemid": ident,
        "key_": key,
        "name": key,
        "value_type": value_type,
        "units": "",
        "lastvalue": str(value),
        "lastclock": str(int(time.time()) - 30),
    }


def step(clock, before, after):
    return lambda now: before if now < clock else after


def ssh_calls(server):
    return [
        (name, args)
        for name, args in server.calls
        if name not in ("ssh_list_tool_catalog",)
    ]


def summary_of(task):
    return {row["name"]: row.get("applied") for row in task["report"]["skills"]}


# --- 1. Linux CPU: high load, CPU not saturated -------------------------------------


def test_linux_load_high_but_cpu_idle_collects_d_state_psi_history_and_baseline(
    monkeypatch,
):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("201", "system.cpu.load[all,avg5]", 12.4)],
        [
            item("202", "system.cpu.util", 18.5),
            item("203", "system.cpu.util[,iowait]", 41.3),
            item("204", "system.cpu.num", 4, "3"),
        ],
        [{"eventid": "880001", "clock": str(clock), "value": "1", "name": "load"}],
        {
            "201": step(clock, 3.0, 12.0),
            "202": step(clock, 15.0, 18.0),
            "203": step(clock, 2.0, 41.0),
            "204": lambda now: 4,
        },
        {"201": (1.0, 2.5, 4.0), "202": (5.0, 15.0, 30.0), "203": (0.5, 2.0, 6.0)},
    )
    ssh = SSH(
        {
            "ssh_diagnose_cpu": {
                "status": "success",
                "summary": {
                    "metrics": [
                        {"metric": "load_per_core", "value": 3.1},
                        {"metric": "cpu_idle_percent", "value": 71.0},
                        {"metric": "cpu_iowait_percent", "value": 24.0},
                    ]
                },
                "findings": [
                    finding(
                        "load_cpu_divergence",
                        {"load_per_core": 3.1, "cpu_idle_percent": 71.0},
                    )
                ],
            },
            "ssh_diagnose_processes": {
                "status": "success",
                "summary": {
                    "state_counts": {"D": 6, "R": 1, "S": 210},
                    "uninterruptible": [
                        {"pid": 811, "wchan": "io_schedule", "name": "jbd2/sdb1-8"}
                    ],
                },
                "findings": [finding("processes_uninterruptible", 6)],
            },
            "ssh_diagnose_pressure": {
                "status": "success",
                "summary": {
                    "metrics": [{"metric": "psi_io_some_avg10", "value": 48.2}]
                },
                "findings": [finding("psi_io_some_avg10", 48.2, "critical")],
            },
        }
    )
    rig(monkeypatch, zbx, ssh)

    def conclude(request):
        cpu = prefetched(request, "ssh_collect")[0]
        history = prefetched(request, "history_get")[0]
        return answer(
            json.dumps(
                {
                    "cause": f"负载高由 I/O 等待的 D 状态任务造成（{cpu}），CPU 并未打满（{history}）。",
                    "action": ["排查 sdb 的写入来源"],
                    "analysis": "负载 / CPU 背离，PSI io 偏高。",
                    "findings": {
                        "confirmed": [
                            {"statement": "存在 6 个 D 状态进程", "evidence": [cpu]},
                            {"statement": "告警后负载升至 12", "evidence": [history]},
                        ],
                        "probable": [{"statement": "sdb 写入拥塞", "evidence": [cpu]}],
                        "hypotheses": [
                            {"statement": "存储后端变慢", "verify": "查看存储时延"}
                        ],
                    },
                    "evidence": [
                        {"id": cpu, "quote": "psi_io_some_avg10 48.2"},
                        {"id": cpu, "quote": "load_per_core 3.1"},
                        {"id": history, "quote": "after avg 12"},
                    ],
                },
                ensure_ascii=False,
            )
        )

    model = Model(conclude)
    task, usage = run_alert(
        event_for("Linux: Load average is too high", "71001", clock), model
    )
    report = task["report"]
    # Path: verified Linux host, Zabbix history + SSH live evidence.
    assert report["capabilities"]["device_type"] == "linux"
    assert report["capabilities"]["diagnostic_path"] == "zabbix+ssh"
    # One SSH session gathers CPU, process states and PSI together.
    calls = ssh_calls(ssh)
    assert [name for name, _ in calls] == ["ssh_resolve_host", "ssh_collect"]
    assert calls[1][1]["actions"] == ["cpu", "processes", "pressure"]
    assert calls[1][1]["expected_revision"] == 3
    # Alert window and 7-day baseline, the trigger's item first.
    histories = [q for name, q in zbx.calls if name == "history_get"]
    assert histories and histories[0]["itemids"][0] == "201"
    first = opening(model.requests[0])
    signals = {(s["source"], s["metric"]) for s in first["evidence"]["signals"]}
    assert ("zabbix_mcp", "load_cpu_divergence") in signals
    assert ("ssh_mcp", "load_cpu_divergence") in signals
    assert ("zabbix_mcp", "alert_vs_baseline") in signals
    assert ("zabbix_mcp", "rise_at_alert") in signals
    split = next(
        p["result"]["series"][0]["alert_split"]
        for p in first["evidence"]["prefetched"]
        if p["tool"] == "history_get"
    )
    assert split["before"]["avg"] == 3.0 and split["after"]["avg"] == 12.0
    # Only the Skills that fit a Linux CPU alert reach the model.
    applied = summary_of(task)
    assert applied["platform-linux"] and applied["platform-base"]
    assert not applied["platform-nginx"] and not applied["platform-windows"]
    assert "## platform-nginx v" not in model.requests[0]["instructions"]
    assert "## platform-linux v" in model.requests[0]["instructions"]
    # Facts are code-checked: two sources, both facts confirmed.
    assert report["citations"]["confidence"] == "高"
    assert report["facts"] == {
        "confirmed": 2,
        "demoted": 0,
        "probable": 1,
        "hypotheses": 1,
    }
    assert task["status"] == "success"
    used = report["budget"]["used"]
    assert used["rounds"] == 1 and used["prefetch_ms"] >= 0 and used["mcp_ms"] >= 0
    # The budget counts input + output minus prompt-cache hits: 3400 − 2000.
    assert usage["cached"] == 2000 and used["billed_tokens"] == 1400


# --- 2. Linux memory with a Java process ---------------------------------------------


def test_memory_alert_with_java_runs_independent_calls_in_parallel_once_each(
    monkeypatch,
):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("301", "vm.memory.utilization", 96.2)],
        [item("302", "vm.memory.size[available]", 310_000_000, "3")],
        [],
        {"301": step(clock, 80.0, 96.0), "302": lambda now: 310_000_000},
        {"301": (60.0, 78.0, 90.0)},
    )
    java = {
        "status": "success",
        "summary": {
            "java_processes": 1,
            "processes": [
                {
                    "pid": 4242,
                    "application": "billing-api",
                    "rss_KiB": 6_400_000,
                    "heap": {"xmx": None, "max_ram_percentage": None},
                }
            ],
        },
        "findings": [finding("heap_max_unset", "billing-api（4242）")],
    }
    ssh = SSH(
        {
            "ssh_diagnose_java": java,
            "ssh_diagnose_memory": {
                "status": "success",
                "summary": {
                    "metrics": [{"metric": "memory_available_percent", "value": 3.8}]
                },
                "findings": [finding("memory_available_percent", 3.8, "critical")],
            },
            "ssh_diagnose_jvm": {
                "status": "success",
                "summary": {"heap": {"used_percent": 97.5}, "gc": {"full_count": 41}},
                "findings": [finding("heap_used", 97.5, "critical")],
            },
            "ssh_diagnose_syslog": {
                "status": "success",
                "summary": {"matched": {"oom": ["Killed process 4242 (java)"]}},
                "findings": [finding("log_oom", 1, "critical")],
            },
        },
        delay=0.3,
    )
    rig(monkeypatch, zbx, ssh)
    jvm = {
        "provider": "ssh_mcp",
        "name": "ssh_diagnose_jvm",
        "arguments": {"host_id": 7, "pid": 4242},
    }
    logs = {
        "provider": "ssh_mcp",
        "name": "ssh_diagnose_syslog",
        "arguments": {"host_id": 7, "since": clock - 900, "until": clock + 300},
    }

    def investigate(request):
        assert prefetched(request, "ssh_diagnose_java")
        return answer(
            "",
            [
                Call("c1", "call_mcp_tool", jvm),
                Call("c2", "call_mcp_tool", logs),
                Call("c3", "call_mcp_tool", jvm),
            ],
        )

    def conclude(request):
        heap = output_of(request, "c1")["evidence_id"]
        oom = output_of(request, "c2")["evidence_id"]
        assert output_of(request, "c3")["evidence_id"] == heap
        mem = prefetched(request, "ssh_collect")[0]
        return answer(
            json.dumps(
                {
                    "cause": f"billing-api（4242）未设堆上限，堆使用 97.5%（{heap}），被 OOM 终止（{oom}）。",
                    "action": ["为 billing-api 设置 -Xmx"],
                    "analysis": "",
                    "findings": {
                        "confirmed": [
                            {"statement": "堆使用率 97.5%", "evidence": [heap]},
                            {"statement": "java 被 OOM 终止", "evidence": [oom]},
                        ]
                    },
                    "evidence": [
                        {"id": heap, "quote": "used_percent 97.5"},
                        {"id": oom, "quote": "Killed process 4242"},
                        {"id": mem, "quote": "memory_available_percent 3.8"},
                    ],
                },
                ensure_ascii=False,
            )
        )

    model = Model(investigate, conclude)
    task, _ = run_alert(
        event_for("Linux: High memory utilization (>90% for 5m)", "71002", clock),
        model,
    )
    calls = ssh_calls(ssh)
    names = [name for name, _ in calls]
    # Prefetch: one collect session plus the Java inventory, then the model's
    # two distinct calls; the repeated JVM probe is not executed again.
    assert (
        names.count("ssh_diagnose_jvm") == 1 and names.count("ssh_diagnose_syslog") == 1
    )
    collect = next(args for name, args in calls if name == "ssh_collect")
    assert collect["actions"] == ["memory", "memory_processes", "pressure", "oom"]
    assert "ssh_diagnose_java" in names
    spans = {name: (start, end) for name, start, end in ssh.spans}
    jvm_span, log_span = spans["ssh_diagnose_jvm"], spans["ssh_diagnose_syslog"]
    # Independent calls of one round ran concurrently.
    assert log_span[0] < jvm_span[1] and jvm_span[0] < log_span[1]
    applied = summary_of(task)
    assert applied["platform-java"] and applied["platform-syslog"]
    assert task["report"]["facts"]["confirmed"] == 2
    assert task["status"] == "success"


# --- 3. Nginx 502 / 504 --------------------------------------------------------------


def test_nginx_errors_read_access_and_error_logs_around_the_alert(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("401", "nginx.requests.5xx.rate", 87.0)],
        [],
        [],
        {"401": step(clock, 0.5, 85.0)},
        {"401": (0.0, 0.4, 3.0)},
    )
    ssh = SSH(
        {
            "ssh_diagnose_nginx": {
                "status": "success",
                "summary": {
                    "errors": {
                        "upstream_errors": {"connect_failed": 410, "timed_out": 175},
                        "top_upstreams": [{"value": "127.0.0.1:8080", "count": 585}],
                    }
                },
                "findings": [finding("upstream_connect_failed", 410, "critical")],
            },
            "ssh_diagnose_nginx_access": {
                "status": "success",
                "summary": {
                    "totals": {"requests": 12000, "by_class": {"5xx": 600}},
                    "codes": [
                        {"code": "502", "count": 420},
                        {"code": "504", "count": 180},
                    ],
                },
                "findings": [finding("http_5xx_ratio", "5.00%（600）", "critical")],
            },
            "ssh_diagnose_service_map": {
                "status": "success",
                "summary": {"listeners": [{"port": 80, "process": "nginx"}]},
                "findings": [],
            },
        }
    )
    rig(monkeypatch, zbx, ssh)

    def conclude(request):
        access = prefetched(request, "ssh_diagnose_nginx_access")[0]
        errors = prefetched(request, "ssh_diagnose_nginx")[0]
        ports = prefetched(request, "ssh_diagnose_service_map")[0]
        return answer(
            json.dumps(
                {
                    "cause": f"上游 127.0.0.1:8080 无监听，502 共 420 次（{access}）。",
                    "action": ["恢复 8080 上游服务"],
                    "analysis": "",
                    "findings": {
                        "confirmed": [
                            {"statement": "502 共 420 次", "evidence": [access]},
                            {"statement": "上游连接失败 410 次", "evidence": [errors]},
                            {"statement": "上游进程已崩溃", "evidence": ["E99"]},
                        ]
                    },
                    "evidence": [
                        {"id": access, "quote": "502 420"},
                        {"id": errors, "quote": "connect_failed 410"},
                        {"id": ports, "quote": "port 80"},
                        # Not in any evidence: removed by the citation check.
                        {"id": access, "quote": "503 999"},
                    ],
                },
                ensure_ascii=False,
            )
        )

    model = Model(conclude)
    task, _ = run_alert(
        event_for("Nginx: High error rate (5xx > 5%)", "71003", clock), model
    )
    calls = dict(ssh_calls(ssh))
    access = calls["ssh_diagnose_nginx_access"]
    # The access log window is the alert moment −15 min up to now (the alert
    # was 10 minutes ago), not "the last 30 minutes".
    assert access["since"] == clock - 900
    assert clock + 600 <= access["until"] <= clock + 900
    assert "ssh_diagnose_nginx" in calls and "ssh_diagnose_service_map" in calls
    report = task["report"]
    assert summary_of(task)["platform-nginx"]
    assert [i["quote"] for i in report["citations"]["invalid"]] == ["503 999"]
    # The fact citing a non-existent id is demoted, not reported as confirmed.
    assert report["facts"]["confirmed"] == 2 and report["facts"]["demoted"] == 1
    assert "无有效引用，已降为推断" in report["answer"]


def test_nginx_access_window_uses_the_alert_time(monkeypatch):
    """Guard for the arithmetic above: until is min(now, alert + 15 min)."""
    clock = int(time.time()) - 3600
    zbx = Zabbix(
        LINUX_HOST, [item("401", "nginx.requests.5xx.rate", 1)], [], [], {}, {}
    )
    ssh = SSH({})
    rig(monkeypatch, zbx, ssh)
    model = Model(lambda request: answer('{"cause": "x"}'))
    run_alert(event_for("Nginx: High error rate", "71013", clock), model)
    access = dict(ssh_calls(ssh))["ssh_diagnose_nginx_access"]
    assert (access["since"], access["until"]) == (clock - 900, clock + 900)


# --- 4. Java service restarted with risky start parameters --------------------------


def test_java_restart_alert_inspects_jvm_parameters_and_the_units_history(
    monkeypatch,
):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("501", 'systemd.unit.info["billing-api.service",NRestarts]', 5, "3")],
        [],
        [],
        {"501": step(clock, 0, 5)},
        {},
    )
    ssh = SSH(
        {
            "ssh_diagnose_java": {
                "status": "success",
                "summary": {
                    "processes": [
                        {
                            "pid": 5150,
                            "application": "billing-api",
                            "elapsed_seconds": 120,
                            "heap": {"xmx": "8g", "xmx_MiB": 8192},
                            "cgroup_memory_limit_bytes": 6442450944,
                        }
                    ]
                },
                "findings": [
                    finding("heap_exceeds_cgroup", "8192 MiB > 6144 MiB"),
                    finding("recent_start", 120),
                ],
            },
            "ssh_diagnose_service_detail": {
                "status": "success",
                "summary": {"unit": {"restarts": 5, "result": "oom-kill"}},
                "findings": [finding("restart_loop", 5, "critical")],
            },
        }
    )
    rig(monkeypatch, zbx, ssh)
    detail = {
        "provider": "ssh_mcp",
        "name": "ssh_diagnose_service_detail",
        "arguments": {"host_id": 7, "service": "billing-api.service"},
    }

    def investigate(request):
        assert opening(request)["service"] == "billing-api.service"
        return answer("", [Call("d1", "call_mcp_tool", detail)])

    def conclude(request):
        unit = output_of(request, "d1")["evidence_id"]
        jvm = prefetched(request, "ssh_diagnose_java")[0]
        return answer(
            json.dumps(
                {
                    "cause": f"-Xmx 8g 超过容器限制（{jvm}），被 OOM 重启 5 次（{unit}）。",
                    "action": ["把 -Xmx 降到容器限制的 75% 以内"],
                    "analysis": "",
                    "evidence": [
                        {"id": jvm, "quote": "xmx_MiB 8192"},
                        {"id": unit, "quote": "restarts 5"},
                    ],
                },
                ensure_ascii=False,
            )
        )

    model = Model(investigate, conclude)
    task, _ = run_alert(
        event_for("Java application billing-api restarted", "71004", clock), model
    )
    assert task["diagnostic_type"] == "java"
    names = [name for name, _ in ssh_calls(ssh)]
    assert "ssh_diagnose_java" in names and "ssh_diagnose_service_detail" in names
    assert task["report"]["citations"]["confidence"] in ("高", "中")
    assert summary_of(task)["platform-java"]


# --- 5. systemd service fails to start -----------------------------------------------


def test_failed_service_prefetches_the_unit_named_by_the_trigger(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("601", 'systemd.unit.info["app-worker.service",ActiveState]', 0, "3")],
        [],
        [],
        {"601": step(clock, 1, 0)},
        {},
    )
    ssh = SSH(
        {
            "ssh_diagnose_service_detail": {
                "status": "success",
                "summary": {
                    "unit": {
                        "active": "failed",
                        "result": "exit-code",
                        "exit_status": 203,
                    }
                },
                "findings": [finding("service_failed", "failed", "critical")],
            },
            "ssh_diagnose_failed_services": {
                "status": "success",
                "summary": {"failed_services": ["app-worker.service"]},
                "findings": [finding("failed_service_count", 1)],
            },
        }
    )
    rig(monkeypatch, zbx, ssh)
    model = Model(lambda request: answer('{"cause": "启动命令无法执行"}'))
    task, _ = run_alert(
        event_for("Service app-worker.service is not running", "71005", clock), model
    )
    calls = dict(ssh_calls(ssh))
    assert task["diagnostic_type"] == "service"
    assert calls["ssh_diagnose_service_detail"]["service"] == "app-worker.service"
    assert "ssh_diagnose_failed_services" in calls
    assert summary_of(task)["platform-service"]


# --- 6. System log: OOM and disk I/O errors ------------------------------------------


def test_io_error_alert_reads_system_logs_for_the_alert_window(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("701", "vfs.dev.util[sdb]", 99.0)],
        [item("702", "vfs.dev.read.await[sdb]", 850.0)],
        [],
        {"701": step(clock, 20.0, 99.0), "702": step(clock, 5.0, 850.0)},
        {"701": (1.0, 18.0, 60.0)},
    )
    ssh = SSH(
        {
            "ssh_diagnose_syslog": {
                "status": "success",
                "summary": {
                    "matched": {
                        "io_error": [
                            "kernel: blk_update_request: I/O error, dev sdb, sector 2048"
                        ]
                    }
                },
                "findings": [finding("log_io_error", 1, "critical")],
            }
        }
    )
    rig(monkeypatch, zbx, ssh)
    model = Model(lambda request: answer('{"cause": "sdb 硬件 I/O 错误"}'))
    task, _ = run_alert(
        event_for("Disk sdb: I/O error rate is high", "71006", clock), model
    )
    calls = dict(ssh_calls(ssh))
    assert task["diagnostic_type"] == "io"
    assert calls["ssh_diagnose_syslog"]["since"] == clock - 900
    assert calls["ssh_collect"]["actions"] == ["io", "cpu", "pressure", "processes"]
    # The related items of the same disk lead the history query.
    related = [q for name, q in zbx.calls if name == "item_get" and "search" in q]
    assert any(q["search"]["key_"] == ["sdb"] for q in related)
    assert summary_of(task)["platform-syslog"]


# --- 7. Windows host: Zabbix only ---------------------------------------------------


def test_windows_host_uses_zabbix_only_and_never_connects_ssh(monkeypatch):
    clock = alert_clock()
    host = {
        **LINUX_HOST,
        "parentTemplates": [{"templateid": "2", "name": "Windows by Zabbix agent"}],
    }
    zbx = Zabbix(
        host,
        [item("801", "system.cpu.util", 97.0)],
        [
            item("802", r'perf_counter_en["\System\Processor Queue Length"]', 14.0),
            item("803", "system.cpu.num", 4, "3"),
        ],
        [],
        {"801": step(clock, 40.0, 97.0), "802": step(clock, 1.0, 14.0)},
        {"801": (10.0, 35.0, 80.0)},
    )
    rig(monkeypatch, zbx, ssh_server=None)
    model = Model(lambda request: answer('{"cause": "CPU 争抢"}'))
    task, _ = run_alert(
        event_for("Windows: High CPU utilization (over 90% for 5m)", "71007", clock),
        model,
    )
    caps = task["report"]["capabilities"]
    assert caps["device_type"] == "windows" and caps["diagnostic_path"] == "zabbix-only"
    assert caps["ssh_mcp"]["status"] == "not_applicable"
    histories = [q for name, q in zbx.calls if name == "history_get"]
    assert any("802" in q["itemids"] for q in histories)
    applied = summary_of(task)
    assert applied["platform-windows"] and not applied["platform-linux"]
    # The task page and the detailed export show the same split of the snapshot.
    from tests.test_platform import client_for

    url = "/api/v1/platform/tasks/" + task["task_id"]
    shown = client_for().get(url).json()["skills"]
    assert {row["name"]: row["applied"] for row in shown} == applied
    exported = client_for().get(url + "/detailed-report").text
    assert exported.count("（已提供给模型）") == sum(applied.values())
    assert exported.count("（本次不适用，未发送给模型）") == len(applied) - sum(
        applied.values()
    )
    assert task["status"] == "success"
    card = worker.card_summary(worker_info(task))
    assert "仅 Zabbix 监控数据（Windows 不做 SSH 诊断）" in card


def worker_info(task):
    report = task["report"]
    return {
        "cause": "结论",
        "action": "建议",
        "_diagnostic_status": task["status"],
        "_evidence": (report.get("citations") or {}).get("valid", []),
        "_confidence": (report.get("citations") or {}).get("confidence"),
        "_capabilities": report["capabilities"],
    }


# --- 8. Network device: interface down ----------------------------------------------


def test_network_interface_alert_reads_the_same_interface_items(monkeypatch):
    clock = alert_clock()
    host = {
        "hostid": "20202",
        "host": "core-sw-01",
        "name": "core-sw-01",
        "status": "0",
        "parentTemplates": [{"templateid": "3", "name": "Huawei VRP by SNMP"}],
        "interfaces": [{"type": "2", "ip": "10.0.0.2", "main": "1"}],
    }
    zbx = Zabbix(
        host,
        [item("901", "net.if.status[ifOperStatus.10101]", 2, "3")],
        [
            item("902", "net.if.in.errors[ifInErrors.10101]", 3812.0),
            item("903", "net.if.in[ifHCInOctets.10101]", 1.2e9),
            item("904", "net.if.in.errors[ifInErrors.10102]", 0.0),
        ],
        [
            {"eventid": str(i), "clock": str(clock - i * 600), "value": "1"}
            for i in range(4)
        ],
        {"901": step(clock, 1, 2), "902": step(clock, 10.0, 3812.0)},
        {"902": (0.0, 5.0, 20.0)},
    )
    rig(monkeypatch, zbx, ssh_server=None)
    model = Model(lambda request: answer('{"cause": "链路物理故障"}'))
    task, _ = run_alert(
        event_for("Interface GE0/0/1(): Link down", "71008", clock, host_id="20202"),
        model,
    )
    caps = task["report"]["capabilities"]
    assert caps["device_type"] == "network" and caps["diagnostic_path"] == "zabbix-only"
    assert task["diagnostic_type"] == "network"
    related = [q for name, q in zbx.calls if name == "item_get" and "search" in q]
    assert any(q["search"]["key_"] == [".10101]"] for q in related)
    history_ids = [
        i for name, q in zbx.calls if name == "history_get" for i in q["itemids"]
    ]
    # The trigger item and the same interface's counters; not port 10102.
    assert {"901", "902", "903"} <= set(history_ids) and "904" not in history_ids
    signals = {s["metric"] for s in opening(model.requests[0])["evidence"]["signals"]}
    assert "recurrence" in signals
    applied = summary_of(task)
    assert applied["platform-network"] and not applied["platform-linux"]


# --- 9. Linux host not yet registered in SSH MCP -------------------------------------


def test_linux_host_without_ssh_asset_degrades_to_zabbix_and_says_why(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("201", "system.cpu.load[all,avg5]", 9.0)],
        [item("202", "system.cpu.util", 92.0), item("204", "system.cpu.num", 4, "3")],
        [],
        {"201": step(clock, 2.0, 9.0), "202": step(clock, 30.0, 92.0)},
        {"201": (1.0, 2.0, 4.0)},
    )
    ssh = SSH(
        {},
        resolve={
            "status": "failed",
            "error": "映射不存在或存在重复关联，请由管理员修正",
            "error_code": "mapping_unresolved",
        },
    )
    rig(monkeypatch, zbx, ssh)
    model = Model(lambda request: answer('{"cause": "CPU 计算繁忙"}'))
    task, _ = run_alert(
        event_for("Linux: Load average is too high", "71009", clock), model
    )
    report = task["report"]
    caps = report["capabilities"]
    assert caps["diagnostic_path"] == "zabbix-only"
    assert caps["ssh_mcp"]["status"] == "unavailable"
    assert caps["ssh_mcp"]["error_code"] == "mapping_unresolved"
    assert [name for name, _ in ssh_calls(ssh)] == ["ssh_resolve_host"]
    assert "能力说明：SSH MCP不可用：映射不存在" in report["answer"]
    # No SSH asset is a stated limitation of the evidence, not a failed task.
    assert task["status"] == "success"
    card = worker.card_summary(worker_info(task))
    assert "仅 Zabbix 监控数据（映射不存在" in card


def test_model_gets_no_ssh_tools_once_the_target_has_no_ssh_asset(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST, [item("201", "system.cpu.load[all,avg5]", 9.0)], [], [], {}, {}
    )
    ssh = SSH(
        {},
        resolve={
            "status": "failed",
            "error": "映射不存在或存在重复关联，请由管理员修正",
            "error_code": "mapping_unresolved",
        },
    )
    rig(monkeypatch, zbx, ssh)
    # Seen in production (v1.3.0): the model then tried the host's public IP,
    # SSH MCP refused it and the failed call turned the task partial.
    by_ip = {
        "provider": "ssh_mcp",
        "name": "ssh_resolve_target",
        "arguments": {"address": "203.0.113.7"},
    }
    model = Model(
        lambda request: answer("", [Call("r1", "call_mcp_tool", by_ip)]),
        lambda request: answer('{"cause": "仅凭 Zabbix"}'),
    )
    task, _ = run_alert(
        event_for("Linux: Load average is too high", "71011", clock), model
    )
    enums = [
        tool["parameters"]["properties"]["provider"]["enum"]
        for tool in model.requests[0]["tools"]
        if "provider" in tool["parameters"]["properties"]
    ]
    assert enums == [["zabbix_mcp"], ["zabbix_mcp"]]
    assert "SSH 实时诊断不可用" in output_of(model.requests[1], "r1")["error"]
    assert [name for name, _ in ssh_calls(ssh)] == ["ssh_resolve_host"]
    assert task["status"] == "success"
    assert task["report"]["coverage"]["skipped"] == [
        {
            "tool": "ssh_resolve_target",
            "reason": "目标主机的 SSH 实时诊断不可用，未调用",
        }
    ]


def test_disabled_ssh_mcp_is_reported_once_and_not_retried(monkeypatch):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST, [item("201", "system.cpu.load[all,avg5]", 9)], [], [], {}, {}
    )
    rig(monkeypatch, zbx, SSH({}), ssh_enabled=False)
    resolve = {
        "provider": "ssh_mcp",
        "name": "ssh_resolve_host",
        "arguments": {"zabbix_hostid": "10101"},
    }
    model = Model(
        lambda request: answer("", [Call("r1", "call_mcp_tool", resolve)]),
        lambda request: answer('{"cause": "仅凭 Zabbix"}'),
    )
    task, _ = run_alert(event_for("Linux: Load high", "71019", clock), model)
    caps = task["report"]["capabilities"]
    assert caps["ssh_mcp"]["status"] == "disabled"
    assert caps["diagnostic_path"] == "zabbix-only"
    assert "SSH MCP 未启用" in output_of(model.requests[1], "r1").get("error", "")


# --- 10. Some MCP tools fail; the analysis continues ---------------------------------


def test_failed_and_busy_tools_are_retried_or_recorded_and_analysis_continues(
    monkeypatch,
):
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("301", "vm.memory.utilization", 95.0)],
        [],
        [],
        {"301": step(clock, 70.0, 95.0)},
        {"301": (50.0, 68.0, 80.0)},
    )
    attempts = {"collect": 0}

    def collect_result(name):
        return {
            "status": "success",
            "summary": {
                "metrics": [{"metric": "memory_available_percent", "value": 4.4}]
            },
            "findings": [],
        }

    ssh = SSH(
        {
            "ssh_diagnose_memory": collect_result("memory"),
            "ssh_diagnose_java": {
                "status": "failed",
                "error": "SSH 诊断执行超时（本动作上限 20 秒）",
                "error_code": "timeout",
            },
            "ssh_diagnose_oom": {
                "status": "success",
                "summary": {"matched": {"oom": ["Killed process 991 (python3)"]}},
                "findings": [finding("oom_matches", 1, "critical")],
            },
        }
    )
    original = ssh.call_tool

    async def busy_first(name, args):
        if name == "ssh_collect":
            attempts["collect"] += 1
            if attempts["collect"] == 1:
                ssh.calls.append((name, dict(args)))
                return reply(
                    {
                        "host_id": args["host_id"],
                        "action": "collect",
                        "status": "failed",
                        "error": "SSH 诊断繁忙：等待名额或同主机任务超时，请稍后重试",
                        "error_code": "busy",
                    }
                )
        return await original(name, args)

    ssh.call_tool = busy_first
    rig(monkeypatch, zbx, ssh)
    oom = {
        "provider": "ssh_mcp",
        "name": "ssh_diagnose_oom",
        "arguments": {"host_id": 7, "minutes": 60},
    }
    history_args = None

    def weak(request):
        nonlocal history_args
        first = opening(request)
        assert first["coverage"]["failed"][0]["tool"] == "ssh_diagnose_java"
        history = next(
            p for p in first["evidence"]["prefetched"] if p["tool"] == "history_get"
        )
        history_args = history["arguments"]
        # Only one citation: the platform asks for more evidence first.
        return answer(
            json.dumps(
                {
                    "cause": "内存不足",
                    "evidence": [
                        {
                            "id": history["result"]["evidence_id"],
                            "quote": "after avg 95",
                        }
                    ],
                },
                ensure_ascii=False,
            )
        )

    def follow(request):
        assert "证据不足" in request["input"][-1]["content"]
        return answer(
            "",
            [
                Call("o1", "call_mcp_tool", oom),
                # The same Zabbix query again: answered from the task cache.
                Call(
                    "h1",
                    "call_mcp_tool",
                    {
                        "provider": "zabbix_mcp",
                        "name": "history_get",
                        "arguments": history_args,
                    },
                ),
            ],
        )

    def conclude(request):
        oom_id = output_of(request, "o1")["evidence_id"]
        cached = output_of(request, "h1")
        assert cached["cached"] is True
        return answer(
            json.dumps(
                {
                    "cause": f"python3（991）被 OOM 终止（{oom_id}）。",
                    "evidence": [
                        {"id": oom_id, "quote": "Killed process 991"},
                        {"id": cached["evidence_id"], "quote": "after avg 95"},
                    ],
                },
                ensure_ascii=False,
            )
        )

    model = Model(weak, follow, conclude)
    task, _ = run_alert(
        event_for("Linux: High memory utilization", "71010", clock), model
    )
    # The busy collect session was retried once and then succeeded.
    assert attempts["collect"] == 2
    report = task["report"]
    assert any(
        item["tool"] == "ssh_diagnose_java" for item in report["coverage"]["failed"]
    )
    assert "ssh_collect" in report["coverage"]["collected"]
    # Only real MCP calls ran: the cached history query did not reach Zabbix.
    assert sum(1 for name, _ in zbx.calls if name == "history_get") == len(
        [
            p
            for p in opening(model.requests[0])["evidence"]["prefetched"]
            if p["tool"] == "history_get"
        ]
    )
    assert len(report["citations"]["valid"]) == 2
    # A failed tool is a stated gap: the report is partial, never "normal".
    assert task["status"] == "partial"
    assert any("ssh_diagnose_java" in item for item in report["limitations"])
    assert "平台要求模型补充证据后再总结（1 次）" in report["budget"]["limits_hit"]


# --- 11. A check the host cannot run (PSI off) is a capability, not a gap -------------

NO_PSI = {
    "status": "partial",
    "exit_code": 69,
    "summary": {"action": "pressure", "metrics": []},
    "findings": [
        {
            "level": "info",
            "metric": "collection_coverage",
            "value": ["kernel-psi"],
            "threshold": "complete",
            "hint": "采集未完整完成",
        }
    ],
}


def test_host_without_psi_is_reported_as_a_capability_not_a_diagnostic_gap(
    monkeypatch,
):
    # Rocky / RHEL 9 boot with PSI off: every CPU alert's collection would
    # otherwise mark the whole analysis "partial".
    clock = alert_clock()
    zbx = Zabbix(
        LINUX_HOST,
        [item("201", "system.cpu.load[all,avg5]", 9.4)],
        [item("202", "system.cpu.util", 35.0)],
        [],
        {"201": step(clock, 2.0, 9.0), "202": lambda now: 35.0},
        {"201": (1.0, 2.0, 3.0)},
    )
    ssh = SSH({"ssh_diagnose_pressure": NO_PSI})
    rig(monkeypatch, zbx, ssh)

    def conclude(request):
        cpu = prefetched(request, "ssh_collect")[0]
        history = prefetched(request, "history_get")[0]
        return answer(
            json.dumps(
                {
                    "cause": f"负载升高（{history}），主机未启用 PSI（{cpu}）。",
                    "action": ["核对高负载时段的任务"],
                    "analysis": "PSI 缺失，以运行队列与 D 状态进程代替。",
                    "evidence": [
                        {"id": history, "quote": "after avg 9"},
                        {"id": cpu, "quote": "kernel-psi"},
                    ],
                },
                ensure_ascii=False,
            )
        )

    model = Model(conclude)
    task, _ = run_alert(
        event_for("Linux: Load average is too high", "71011", clock), model
    )
    report = task["report"]
    assert ssh_calls(ssh)[1][1]["actions"] == ["cpu", "processes", "pressure"]
    # Not a gap: the analysis is complete for what this host can provide.
    assert task["status"] == "success" and report["limitations"] == []
    assert report["coverage"]["failed"] == []
    assert report["coverage"]["unavailable"] == [
        {"tool": "ssh_collect", "reason": "主机不支持：kernel-psi"}
    ]
    assert "ssh_collect" in report["coverage"]["collected"]
    assert report["capabilities"]["host_limits"] == [
        {"tool": "ssh_collect/pressure", "missing": "kernel-psi"}
    ]
    # Said in the report scope, and given to the model with the prefetch.
    assert (
        "主机不支持的采集项：内核未启用 PSI（Rocky/RHEL 9 需启动参数 psi=1）"
        "（ssh_collect/pressure）" in report["answer"]
    )
    assert opening(model.requests[0])["capabilities"]["host_limits"]


@pytest.mark.parametrize(
    "outcome",
    [
        # Timed out, truncated, another exit code, a step that never reported
        # back, or no capability named: still evidence the task did not get.
        {"data": {**NO_PSI, "timed_out": True}},
        {"data": {**NO_PSI, "truncated": True}},
        {"data": {**NO_PSI, "incomplete_reason": "stderr"}},
        {"data": {**NO_PSI, "exit_code": 2}},
        {"data": {**NO_PSI, "findings": []}},
        {
            "data": {
                "status": "partial",
                "summary": {
                    "steps": [
                        {**NO_PSI, "action": "pressure"},
                        {"action": "cpu", "status": "partial", "findings": []},
                    ]
                },
            }
        },
        {"data": {"status": "success", "summary": {}}},
        {"data": {"status": "failed", "error_code": "timeout"}},
    ],
)
def test_only_missing_host_prerequisites_are_host_limits(outcome):
    from app.skill_runtime import host_limits

    assert host_limits(outcome) is None


def test_host_limits_name_the_step_and_capability():
    from app.skill_runtime import host_limits

    assert host_limits({"data": NO_PSI}) == [("", "kernel-psi")]
    collected = {
        "data": {
            "status": "partial",
            "summary": {
                "steps": [
                    {"action": "cpu", "status": "success", "exit_code": 0},
                    {**NO_PSI, "action": "pressure"},
                ]
            },
        }
    }
    assert host_limits(collected) == [("pressure", "kernel-psi")]


def test_card_shows_checked_evidence_and_sources_without_evidence_ids():
    info = {
        "cause": "负载高由 D 状态任务造成（E3）。",
        "action": ["排查 sdb 写入"],
        "analysis": "PSI io 偏高（E3），CPU 空闲 71%（E2）。",
        "_evidence": [
            {
                "id": "E3",
                "quote": "psi_io_some_avg10 48.2",
                "provider": "ssh_mcp",
                "tool": "ssh_collect",
            },
            {
                "id": "E5",
                "quote": "after avg 12",
                "provider": "zabbix_mcp",
                "tool": "history_get",
            },
        ],
        "_confidence": "高",
        "_capabilities": {
            "device_type": "linux",
            "diagnostic_path": "zabbix+ssh",
            "ssh_mcp": {"status": "used"},
        },
    }
    card = worker.card_summary(info)
    assert "**核心证据**  Zabbix 历史 + SSH 实时（Linux） · 依据可信度 高" in card
    assert "· SSH 实时采集：psi_io_some_avg10 48.2" in card
    assert "· Zabbix 监控历史：after avg 12" in card
    assert not re.search(r"\bE\d+\b", card)
    assert len(card) <= 1100
