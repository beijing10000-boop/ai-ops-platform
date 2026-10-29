import pytest

from app.diagnostics.targets import (
    question_target,
    directory_request,
)


def test_explicit_target_selectors_and_ambiguous_requests():
    assert question_target("看下198.51.100.21这台服务器") == ("ip", "198.51.100.21")
    assert question_target("Host ID：11600的磁盘") == ("hostid", "11600")
    assert question_target("一般咨询") is None
    with pytest.raises(ValueError, match="多个"):
        question_target("比较198.51.100.21与198.51.100.22")


def test_directory_request_validates_root_and_levels():
    assert directory_request("/data目录占用，列出五层") == {"root": "/data", "depth": 5}
    with pytest.raises(ValueError):
        directory_request("/data/../../var目录占用")
