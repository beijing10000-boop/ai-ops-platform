"""The real SSH MCP and log MCP services, started for the joint tests.

Each provider runs from its own checkout in its own Python environment (a
separate process with its own dependencies) and a throwaway data directory.
It is initialised through its own /api/v1/setup and configured through its
own admin API, with a Web session row written the way the provider's tests
write one. Nothing here talks to a real deployment.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

ADMIN = "ou_joint_admin"
APP_ID = "cli_1234567890abcdef"
# Hosts the SSH MCP knows, by Zabbix Host ID.
READY, WINDOWS, NOT_READY, UNKNOWN = "10101", "10102", "10103", "10199"
TEMPLATES = Path(__file__).resolve().parents[2] / "app" / "skill_templates"

# Per provider: ASGI app, SQLite file, session cookie, setup field for admins.
KINDS = {
    "ssh": ("sshmcp.main:app", "ssh-mcp.sqlite3", "ssh_mcp_web_session",
            "feishu_admin_open_ids"),
    "log": ("logmcp.main:app", "logmcp.sqlite3", "logmcp_session",
            "admin_open_ids"),
}  # fmt: skip


@dataclass
class Provider:
    kind: str
    base: str
    data_dir: Path
    process: subprocess.Popen
    admin: httpx.Client
    log_path: Path

    @property
    def mcp_url(self):
        return self.base + "/mcp"

    def output(self):
        return self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    def stop(self):
        self.admin.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start(kind, repo, python, env=None, timeout=240):
    module, db_name, cookie, admins_field = KINDS[kind]
    data = Path(tempfile.mkdtemp(prefix=f"aiops-joint-{kind}-"))
    log_path = data.with_suffix(".log")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [python, "-m", "uvicorn", module, "--host", "127.0.0.1"]
        + ["--port", str(port), "--log-level", "warning"],
        cwd=repo,
        env={**os.environ, "DATA_DIR": str(data), "PYTHONUTF8": "1", **(env or {})},
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    log.close()
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            raise RuntimeError(
                f"{kind} provider exited: {log_path.read_text(errors='replace')[-2000:]}"
            )
        try:
            # Serving is enough: the log service's /healthz stays 503 while
            # its store is down, which some tests want on purpose.
            if httpx.get(base + "/api/v1/setup/status", timeout=3).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            process.kill()
            raise RuntimeError(f"{kind} provider did not become healthy")
        time.sleep(0.5)
    setup = httpx.post(
        base + "/api/v1/setup",
        json={
            "bootstrap_token": (data / "bootstrap.token").read_text().strip(),
            "web_protocol": "http",
            "web_public_host": f"127.0.0.1:{port}",
            "lark_app_id": APP_ID,
            "lark_app_secret": "joint-app-secret",
            admins_field: ADMIN,
        },
        timeout=30,
    )
    setup.raise_for_status()
    raw, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(16)
    with sqlite3.connect(data / db_name) as c:
        c.execute(
            "INSERT INTO web_sessions(token_hash,open_id,name,csrf,expires) VALUES (?,?,?,?,?)",
            (
                hashlib.sha256(raw.encode()).hexdigest(),
                ADMIN,
                "联调管理员",
                csrf,
                int(time.time()) + 3600,
            ),
        )
    admin = httpx.Client(
        base_url=base + "/api/v1",
        cookies={cookie: raw},
        headers={"X-CSRF-Token": csrf},
        timeout=60,
    )
    return Provider(kind, base, data, process, admin, log_path)


def warm_up_logs(url, token):
    """One generous first MCP round trip: a cold service on a loaded test box
    can take longer than the platform's 30 s call budget."""
    from app.integrations import log_mcp

    values = {"log_mcp_url": url, "log_mcp_token": token}

    async def run():
        async with log_mcp.connect(values.get, timeout=120) as session:
            await session.list_tools()
            await session.call_tool("log_list_tool_catalog", {})

    asyncio.run(run())


def created(response):
    if response.status_code >= 400:
        raise AssertionError(
            f"{response.request.url} → {response.status_code} {response.text}"
        )
    return response.json()


def private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def host_public_key():
    return (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        .decode()
    )


def skill_tools(prefix, not_tools=()):
    """Tool names the bundled platform Skills use, with the files naming them:
    prefetch lists in the frontmatter, and `<prefix>…` words in the Skill
    bodies and references (minus field names such as evidence.log_target)."""
    key = {"ssh_": "ssh", "log_": "logs"}[prefix]
    found = {}
    for path in sorted(TEMPLATES.glob("platform-*/**/*.md")):
        text = path.read_text(encoding="utf-8")
        where = path.relative_to(TEMPLATES).as_posix()
        if text.startswith("---"):
            meta = yaml.safe_load(text.split("---", 2)[1]) or {}
            for rule in meta.get("prefetch") or []:
                for name in rule.get(key) or []:
                    found.setdefault(name, set()).add(where + " (prefetch)")
        for name in re.findall(r"(?<![\w.])" + prefix + r"[a-z][a-z_]*[a-z]\b", text):
            if name not in not_tools:
                found.setdefault(name, set()).add(where)
    return found


def closed_port():
    """A local port nothing listens on: the SSH connection is refused at once."""
    return free_port()


def local_private_ip():
    """This machine's RFC 1918 address; SSH MCP only registers such targets."""
    if os.environ.get("AIOPS_JOINT_SSH_ADDRESS"):
        return os.environ["AIOPS_JOINT_SSH_ADDRESS"]
    candidates = []
    for probe in ("10.255.255.255", "172.31.255.255", "192.168.255.255"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.connect((probe, 9))
                candidates.append(sock.getsockname()[0])
            except OSError:
                pass
    candidates += socket.gethostbyname_ex(socket.gethostname())[2]
    for value in candidates:
        address = ipaddress.ip_address(value)
        if any(
            address in ipaddress.ip_network(n)
            for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ):
            return value
    raise RuntimeError("找不到本机内网地址；请设置 AIOPS_JOINT_SSH_ADDRESS")
