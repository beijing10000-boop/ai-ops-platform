"""Optional stdio adapter for a trusted local service account; no HTTP listener."""

import time
from mcp.server.fastmcp import FastMCP
from .inventory import asset_page, get_asset
from .diagnostics.playbooks import PLAYBOOKS
from .diagnostics.ssh import execute
from .orchestrator import tasks

mcp = FastMCP(
    "Zabbix AI Ops Linux diagnostics",
    instructions="Registered Linux assets only. No arbitrary addresses, commands or file operations.",
)


@mcp.tool()
def list_linux_hosts(page: int = 1):
    """List enabled registered Linux asset IDs and display names, at most 100 per page."""
    if type(page) is not int or not 1 <= page <= 10000:
        raise ValueError("invalid page")
    result = asset_page(page, 100, device_type="linux")
    return {
        "items": [
            {"id": r["id"], "name": r["name"], "zabbix_hostid": r["zabbix_hostid"]}
            for r in result["items"]
            if r["enabled"]
        ],
        "total": result["total"],
    }


@mcp.tool()
def diagnose_linux_host(
    host_id: int,
    diagnostic_type: str,
    time_window: int = 30,
    service: str | None = None,
):
    """Run a fixed diagnostic playbook on a registered Linux asset; no shell input."""
    if diagnostic_type not in PLAYBOOKS:
        raise ValueError("unsupported diagnostic type")
    asset = get_asset(host_id)
    if not asset or not asset["enabled"] or asset["device_type"] != "linux":
        raise ValueError("asset unavailable")
    from .diagnostics.actions import build

    actions = list(PLAYBOOKS[diagnostic_type]["actions"])
    if diagnostic_type=='disk' and asset['diagnostic_paths']:
        # Directory parameters always come from the registered asset, never free-form MCP input.
        actions.extend(['directory']*len(asset['diagnostic_paths']))
    path_iter=iter(asset['diagnostic_paths'])
    plan=[(action,next(path_iter) if action=='directory' else service if action in {'logs','service'} else None) for action in actions]
    for action,parameter in plan:
        build(action, parameter, time_window)
    task, _ = tasks.create(
        {"time_window": time_window},
        source="mcp_stdio",
        actor="trusted-local-service",
        kind="ssh",
        asset_id=host_id,
        diagnostic_type=diagnostic_type,
    )
    tid = task["task_id"]
    tasks.start(tid)
    began = time.monotonic()
    results = []
    try:
        for action,parameter in plan:
            result = execute(
                host_id,
                action,
                parameter,
                time_window,
                lambda: tasks.cancelled(tid),
            )
            tasks.evidence(tid, "linux_ssh", action, result, result["duration_ms"])
            results.append(result)
        tasks.finish(
            tid,
            {"results": results},
            status="partial"
            if any(r["status"] != "success" for r in results)
            else "success",
            duration_ms=int((time.monotonic() - began) * 1000),
        )
        return {"task_id": tid, "trace_id": task["trace_id"], "results": results}
    except Exception as exc:
        tasks.finish(
            tid,
            {"message": str(exc)[:200]},
            status="failed",
            error_type=type(exc).__name__,
        )
        raise


if __name__ == "__main__":
    mcp.run(transport="stdio")
