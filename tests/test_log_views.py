"""Model views of large log replies: the least needed sections go first and
the fixed breakdowns (timing, 5xx origins, totals) stay whole, so the Nginx
topic and report reach the model with what a diagnosis needs."""

import json

from app.skill_context import model_view

STAGES = ("connect", "header", "upstream", "nginx", "request")


def nginx_summary(sites=1, routes=10):
    """A log_nginx_summary reply shaped like the log platform's (v0.7)."""
    route = lambda i: {  # noqa: E731
        "site": f"site{i % sites}.example.com",
        "method": "GET",
        "route": f"/api/v1/resource-{i}/{{id}}/detail",
        "c": 1000 - i,
        "s5xx": 10 - i % 10,
        "s4xx": 3,
        "s4xx_noise": 0,
        "p95": 0.25,
        "upstream": "10.0.0.5:8080",
    }
    return {
        "window": {"start": "2026-11-03 10:00:00", "end": "2026-11-03 11:00:00"},
        "totals": {
            "requests": 30000,
            "s5xx": 400,
            "s4xx": 6000,
            "s4xx_noise": 5500,
            "p50": 0.01,
            "p95": 1.7,
            "p99": 30.1,
            "clients": 270,
            "sites": sites,
            "unnamed": 0,
            "bytes": 123456789,
            "retried": 0,
            "websockets": 200,
        },
        "timing": [
            {"stage": s, "name": s, "n": 25000, "p50": 0.01, "p95": 0.5, "p99": 2.0}
            for s in STAGES
        ],
        "request_size": {
            "n": 30000,
            "max": 10485760,
            "p50": 512,
            "p95": 2048,
            "p99": 4096,
        },
        "keepalive": {"first": 1000, "reused": 29000},
        "statuses": [
            {"status": s, "c": 100}
            for s in (
                200,
                401,
                301,
                405,
                404,
                304,
                503,
                101,
                201,
                302,
                500,
                204,
                499,
                202,
                403,
            )
        ],
        "sites": [
            {
                "site": f"site{i}.example.com",
                "c": 100,
                "s5xx": 1,
                "s4xx": 1,
                "s4xx_noise": 0,
                "p95": 0.1,
                "clients": 3,
                "bytes": 1000,
            }
            for i in range(sites)
        ],
        "sites_truncated": False,
        "error_routes": [route(i) for i in range(routes)],
        "slow_routes": [route(i) for i in range(routes)],
        "upstreams": [
            {
                "upstream": f"10.0.0.{i}:8080",
                "c": 1000,
                "s5xx": 10,
                "switched": 0,
                "p95": 1.0,
                "header_p95": 0.9,
            }
            for i in range(routes)
        ],
        "upstream_errors": [
            {
                "name": "上游超时",
                "c": 5,
                "hosts": 1,
                "first": "2026-11-03 10:01:00",
                "last": "2026-11-03 10:59:00",
                "sample": "upstream timed out (110: Connection timed out) while reading response header from upstream"
                * 2,
            }
        ],
        "step": 60,
        "trend": [
            {"t": f"2026-11-03 10:{m:02d}:00", "requests": 500, "s5xx": 7, "p95": 1.5}
            for m in range(60)
        ],
        "servers": [
            {
                "host": f"web{i}",
                "host_ip": f"10.0.0.{i}",
                "c": 100,
                "s5xx": 1,
                "s4xx": 1,
                "s4xx_noise": 0,
                "p95": 0.2,
                "clients": 3,
                "sites": 1,
                "bytes": 1000,
            }
            for i in range(4)
        ],
        "servers_truncated": False,
        "s5xx_origins": [
            {
                "origin": "upstream",
                "name": "后端返回",
                "c": 300,
                "statuses": [{"status": 503, "c": 200}, {"status": 500, "c": 100}],
            },
            {
                "origin": "timeout",
                "name": "等后端超时",
                "c": 50,
                "statuses": [{"status": 504, "c": 50}],
            },
            {
                "origin": "connect",
                "name": "未收到后端响应",
                "c": 30,
                "statuses": [{"status": 502, "c": 30}],
            },
            {
                "origin": "nginx",
                "name": "Nginx 自身（未转发）",
                "c": 15,
                "statuses": [{"status": 503, "c": 15}],
            },
            {
                "origin": "unknown",
                "name": "无法区分",
                "c": 5,
                "statuses": [{"status": 502, "c": 5}],
            },
        ],
        "protocols": {
            "scheme": [{"value": "https", "c": 29000}],
            "http": [{"value": "HTTP/1.1", "c": 30000}],
            "tls": [{"value": "TLSv1.3", "c": 29000}],
        },
        "clients": [
            {
                "client": f"10.9.0.{i}",
                "c": 100,
                "s5xx": 1,
                "s4xx": 1,
                "s4xx_noise": 0,
                "bytes": 1000,
            }
            for i in range(10)
        ],
        "referers": [
            {"referer": f"ref{i}.example.org", "c": 10, "sites": 1} for i in range(10)
        ],
        "largest_routes": [route(i) for i in range(routes)],
        "heaviest_routes": [route(i) for i in range(routes)],
        "noise": [
            {
                "rule": "jumpserver_login_expired",
                "name": "JumpServer 登录过期页面轮询",
                "note": "页面一直开着就一直返回 401",
                "c": 5500,
                "clients": 14,
                "sites": 2,
                "sources": [],
                "sources_truncated": False,
            }
        ],
        "status": "success",
    }


def wrapped(data):
    return {"is_error": False, "status": "success", "data": data}


def test_the_nginx_topic_keeps_every_stage_and_origin_at_every_profile():
    for sites, routes in ((1, 10), (20, 10)):
        outcome = wrapped(nginx_summary(sites, routes))
        assert len(json.dumps(outcome, ensure_ascii=False)) > 9000
        for limit in (2500, 4000, 6000):
            view = model_view("logs", "log_nginx_summary", outcome, max_chars=limit)
            assert len(json.dumps(view, ensure_ascii=False)) <= limit, (sites, limit)
            data = view["data"]
            assert [s["stage"] for s in data["timing"]] == list(STAGES), limit
            assert (
                len(data["s5xx_origins"]) == 5 and data["totals"]["requests"] == 30000
            )
            # What was left out is named, least needed first.
            assert data["omitted_sections"][:3] == [
                "referers",
                "largest_routes",
                "heaviest_routes",
            ]
            assert "view_note" in view


def test_the_nginx_report_keeps_its_conclusions_first():
    findings = [
        {
            "key": f"k{i}",
            "level": "warning",
            "level_name": "需关注",
            "title": f"发现 {i}",
            "detail": "说明" * 30,
            "evidence": [{"name": "5xx", "value": 400, "baseline": 10, "unit": "次"}],
            "next_steps": ["查看后端日志"],
        }
        for i in range(6)
    ]
    report = {
        "window": {"start": "a", "end": "b"},
        "baseline_window": {"start": "c", "end": "d", "mode": "previous"},
        "health": {
            "level": "attention",
            "name": "需关注",
            "summary": "5xx 错误率 1.1%",
        },
        "findings": findings,
        "overview": {"requests": 30000, "s5xx": 400, "s5xx_rate": 0.0133, "p95": 1.7},
        "baseline": {"requests": 31000, "s5xx": 10, "s5xx_rate": 0.0003, "p95": 1.6},
        "references": {
            m: {"requests": 1, "s5xx_rate": 0.1}
            for m in ("previous", "yesterday", "last_week")
        },
        "codes": [
            {
                "status": s,
                "name": "x",
                "c": 100,
                "share": 0.01,
                "noise": 0,
                "baseline": 90,
                "top": {"route": [{"value": "GET /x" * 10, "c": 1}]},
            }
            for s in (401, 404, 503, 500, 502, 499)
        ],
        "timing": [
            {"stage": s, "n": 1, "p50": 0.1, "p95": 0.2, "p99": 0.3} for s in STAGES
        ],
        "s5xx_origins": nginx_summary()["s5xx_origins"],
        "sites": [{"site": f"s{i}", "c": 1} for i in range(5)],
        "servers": [{"host": f"h{i}", "c": 1} for i in range(5)],
        "upstreams": [{"upstream": f"u{i}", "c": 1} for i in range(5)],
        "changes": {"error_routes": [{"route": "/x" * 40}] * 5},
        "slow_requests": [{"ts": "t", "route": "/y" * 40}] * 3,
        "error_log": {"samples": [{"message": "m" * 240}] * 4},
        "impact": {"sites_5xx": 3},
        "timeline": [{"t": "t", "event": "e" * 40}] * 5,
        "user_agents": [{"agent": "a" * 200}] * 3,
        "coverage": {"gaps": ["缺口"], "notes": ["口径" * 20] * 3},
    }
    outcome = wrapped(report)
    for limit in (2500, 4000, 6000):
        view = model_view("logs", "log_nginx_report", outcome, max_chars=limit)
        assert len(json.dumps(view, ensure_ascii=False)) <= limit, limit
        data = view["data"]
        assert data["health"]["name"] == "需关注" and data["findings"]
        assert data["overview"]["requests"] == 30000
        assert [s["stage"] for s in data["timing"]] == list(STAGES)
        assert (
            "user_agents" not in data and data["omitted_sections"][0] == "user_agents"
        )
    # Enough room: the codes and the baseline are there too.
    roomy = model_view("logs", "log_nginx_report", outcome, max_chars=6000)["data"]
    assert roomy["baseline"]["s5xx"] == 10 and roomy["codes"]


def test_a_small_log_reply_is_left_as_it_is():
    small = wrapped({"totals": {"requests": 1}, "timing": []})
    assert model_view("logs", "log_nginx_summary", small, max_chars=4000) == small
