import pytest

from app.diagnostics.targets import (
    question_target,
    directory_request,
    directory_children,
)


def test_explicit_target_selectors_and_ambiguous_requests():
    assert question_target("看下172.20.2.101这台服务器") == ("ip", "172.20.2.101")
    assert question_target("Host ID：11600的磁盘") == ("hostid", "11600")
    assert question_target("一般咨询") is None
    with pytest.raises(ValueError, match="多个"):
        question_target("比较172.20.2.101与172.20.2.102")


def test_directory_descendants_cannot_escape_requested_root_or_jump_levels():
    assert directory_request("/data目录占用，列出五层") == {"root": "/data", "depth": 5}
    with pytest.raises(ValueError):
        directory_request("/data/../../var目录占用")
    payload = {
        "data": {
            "top_directories": [
                {"directory": path, "bytes": 1}
                for path in (
                    "/data/app",
                    "/var/log",
                    "/data/../var",
                    "/data/a/b",
                    "/database",
                )
            ]
        }
    }
    assert directory_children(payload, "/data") == ["/data/app"]
