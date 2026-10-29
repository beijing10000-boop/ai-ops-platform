"""Parse user selectors; only a unique, exact Zabbix result can establish a target."""

import ipaddress
import re


def question_target(question):
    ids = set(
        re.findall(
            r"(?:host\s*id|主机\s*ID)\s*[:：=]?\s*([0-9]{1,32})(?![0-9])",
            question,
            re.I,
        )
    )
    addresses = set()
    for value in re.findall(
        r"(?<![A-Za-z0-9_.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.])", question
    ):
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    if len(ids) > 1 or len(addresses) > 1 or ids and addresses:
        raise ValueError(
            "本轮包含多个主机标识，请一次指定一个 Host ID 或 IP；未建立 SSH 关联"
        )
    if ids:
        return "hostid", ids.pop()
    if addresses:
        return "ip", addresses.pop()
    return None


def validate_directory(root):
    if not isinstance(root, str) or len(root) > 120:
        raise ValueError("目录路径长度不正确")
    if root != "/" and not re.fullmatch(
        r"/(?:data|var|opt|home|root|tmp|usr)(?:/[A-Za-z0-9._-]+){0,6}", root
    ):
        raise ValueError("目录须位于 SSH MCP 支持的根路径下")
    if any(part in {".", ".."} for part in root.split("/")):
        raise ValueError("目录路径禁止跳转")
    return root


def directory_request(question):
    if not re.search(r"目录|文件夹|directory|\bdu\b", question, re.I):
        return None
    path = re.search(r"/(?:[A-Za-z0-9._-]+/?)*", question)
    if not path:
        return None
    root = validate_directory(path[0].rstrip("/") or "/")
    depth = re.search(r"([0-9]+|[一二三四五])\s*层", question)
    digits = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5}
    levels = (digits.get(depth[1]) or int(depth[1])) if depth else 1
    if not 1 <= levels <= 5:
        raise ValueError("目录分析支持 1–5 层；请缩小范围后重试")
    return {"root": root, "depth": levels}
