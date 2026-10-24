"""Real local SSH handshake fixtures; these are not production-host validation."""

import io
import ipaddress
import socket
import select
import subprocess
import threading
import time

import paramiko
import pytest
from app import main, inventory
from app.diagnostics.ssh import execute, DiagnosticError, lease


class FixtureSSH(paramiko.ServerInterface):
    def __init__(self, key, username):
        self.key = key
        self.username = username
        self.command = None
        self.auth_attempts = 0
        self.ready = threading.Event()

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        self.auth_attempts += 1
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == self.username and key == self.key
            else paramiko.AUTH_FAILED
        )

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode()
        self.ready.set()
        return True


@pytest.fixture
def target(monkeypatch, tmp_path, request):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    # Loopback is permitted only in this isolated protocol fixture; production validation remains private-IP only.
    monkeypatch.setattr(
        inventory,
        "NETWORKS",
        inventory.NETWORKS + (ipaddress.ip_network("127.0.0.0/8"),),
    )
    host_key = paramiko.RSAKey.generate(2048)
    user_key = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    user_key.write_private_key(buf)
    cred = inventory.save_credential("fixture", buf.getvalue(), "", "test")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    username = getattr(request, "param", "ai-diagnostic")
    fixture = FixtureSSH(user_key, username)
    stopped = threading.Event()
    output = {"text": "AIOPS_SSH_OK\n1001\nLinux\n", "hang": False}
    transports = []

    def serve():
        while not stopped.is_set():
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            transport = paramiko.Transport(sock)
            transports.append(transport)
            try:
                transport.add_server_key(host_key)
                transport.start_server(server=fixture)
                channel = transport.accept(5)
                if channel and fixture.ready.wait(5):
                    if output["hang"]:
                        stopped.wait(6)
                    else:
                        channel.sendall(output["text"].encode())
                        channel.send_exit_status(0)
                        channel.close()
            except (paramiko.SSHException, EOFError, OSError):
                pass
            finally:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    asset = inventory.save_asset(
        inventory.AssetInput(
            name="fixture",
            device_type="linux",
            username=username,
            address="127.0.0.1",
            ssh_port=listener.getsockname()[1],
            credential_id=cred["id"],
            host_key=host_key.get_name() + " " + host_key.get_base64(),
        ),
        "test",
    )
    yield asset, fixture, output
    stopped.set()
    listener.close()
    for transport in transports:
        transport.close()
    thread.join(2)


def test_real_ssh_transport_uses_fixed_action_and_pinned_key(target):
    asset, server, _ = target
    result = execute(asset["id"], "connection")
    assert result["status"] == "success" and "AIOPS_SSH_OK" in result["output"]
    assert "id -u" in server.command
    assert "python" not in server.command and "sudo" not in server.command


def test_real_ssh_identity_mismatch_is_rejected(target):
    asset, server, _ = target
    wrong = paramiko.RSAKey.generate(2048)
    with main.connection() as db:
        db.execute(
            "UPDATE assets SET host_key=? WHERE id=?",
            (wrong.get_name() + " " + wrong.get_base64(), asset["id"]),
        )
    with pytest.raises(DiagnosticError, match="公钥"):
        execute(asset["id"], "connection")
    assert server.command is None


def test_ssh_output_is_bounded_and_sensitive_values_redacted(target):
    asset, _, output = target
    output["text"] = "password=secretvalue\n" + "x" * 50000
    result = execute(asset["id"], "connection")
    assert result["truncated"] is True and result["status"] == "partial"
    assert "secretvalue" not in result["output"] and len(result["output"]) <= 32768


def test_ssh_timeout_closes_real_transport(target):
    asset, _, output = target
    output["hang"] = True
    with main.connection() as db:
        db.execute("INSERT OR REPLACE INTO settings VALUES ('ssh_timeout','3',0)")
    began = time.monotonic()
    with pytest.raises(DiagnosticError):
        execute(asset["id"], "connection")
    assert time.monotonic() - began < 8


def test_per_host_cross_process_lease_rejects_conflicting_checks(target):
    asset, _, _ = target
    with lease(asset["id"]):
        with pytest.raises(DiagnosticError, match="已有诊断"):
            with lease(asset["id"]):
                pass
    with lease(asset["id"]):
        pass


def test_mode_b_refuses_an_unverified_gateway_response(target):
    asset, _, _ = target
    with main.connection() as db:
        db.execute(
            "UPDATE assets SET diagnostic_mode='privileged',privileged_approved=1 WHERE id=?",
            (asset["id"],),
        )
    with pytest.raises(DiagnosticError, match="网关标识"):
        execute(asset["id"], "connection")


@pytest.mark.parametrize("target", ["root", "root-alias"], indirect=True)
def test_standard_ssh_accepts_root_and_uid_zero(target):
    asset, server, output = target
    output["text"] = "AIOPS_SSH_OK\n0\nLinux\n"
    result = execute(asset["id"], "connection")
    assert result["status"] == "success"
    assert result["mode"] == "standard"
    assert result["output"].splitlines()[:2] == ["AIOPS_SSH_OK", "0"]
    # Run the transmitted fixed snippet with UID 0 simulated; no root privileges
    # or production target are needed to exercise the former runtime guard.
    completed = subprocess.run(
        ["/bin/sh", "-c", "id() { printf '0\\n'; }; " + server.command],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    assert completed.stdout.splitlines()[:2] == ["AIOPS_SSH_OK", "0"]


def test_fetch_real_host_key_without_target_authentication(target):
    from app.diagnostics.host_keys import fetch_key

    asset, server, _ = target
    expected = asset["host_key"]
    fetched = fetch_key({**asset, "host_key": "", "credential_id": None})
    assert fetched == expected
    assert inventory.fingerprint(fetched).startswith("SHA256:")
    assert server.auth_attempts == 0 and server.command is None


@pytest.mark.parametrize("mismatch", [False, True])
def test_fetch_through_real_pinned_ssh_jump_without_target_auth(target, mismatch):
    from app.diagnostics.host_keys import fetch_key

    asset, target_server, _ = target
    jump_key = paramiko.RSAKey.generate(2048)
    configured = paramiko.RSAKey.generate(2048) if mismatch else jump_key
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(3)
    stop = threading.Event()
    resources = [listener]
    forwarded = []

    class JumpSSH(FixtureSSH):
        def check_channel_direct_tcpip_request(self, chanid, origin, destination):
            forwarded.append(destination)
            return paramiko.OPEN_SUCCEEDED

    jump_server = JumpSSH(target_server.key, "diag-proxy")

    def serve():
        try:
            sock, _ = listener.accept()
            transport = paramiko.Transport(sock)
            resources.append(transport)
            transport.add_server_key(jump_key)
            transport.start_server(server=jump_server)
            channel = transport.accept(3)
            if channel is None:
                return
            upstream = socket.create_connection(forwarded[0], timeout=3)
            resources.extend([channel, upstream])
            while not stop.is_set():
                ready, _, _ = select.select([channel, upstream], [], [], 0.1)
                for source in ready:
                    data = source.recv(32768)
                    if not data:
                        return
                    (upstream if source is channel else channel).sendall(data)
        except (paramiko.SSHException, EOFError, OSError, ValueError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with main.connection() as db:
        proxy_id = db.execute(
            "INSERT INTO ssh_proxies(name,address,port,username,host_key,credential_id) VALUES (?,?,?,?,?,?)",
            ("fixture jump", "127.0.0.1", listener.getsockname()[1], "diag-proxy",
             configured.get_name() + " " + configured.get_base64(), asset["credential_id"]),
        ).lastrowid
    try:
        candidate = {**asset, "proxy_id": proxy_id, "host_key": "", "credential_id": None}
        if mismatch:
            with pytest.raises(ValueError, match="跳板主机公钥不匹配"):
                fetch_key(candidate)
            assert forwarded == [] and jump_server.auth_attempts == 0
        else:
            assert fetch_key(candidate) == asset["host_key"]
            assert forwarded == [(asset["address"], asset["ssh_port"])]
            assert jump_server.auth_attempts > 0
        assert target_server.auth_attempts == 0 and target_server.command is None
    finally:
        stop.set()
        for resource in reversed(resources):
            resource.close()
        thread.join(3)


def test_host_key_probe_deadline_closes_unresponsive_handshake(target, monkeypatch):
    from app.diagnostics import host_keys

    asset, _, _ = target
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    stop = threading.Event()

    def silent():
        try:
            sock, _ = listener.accept()
            with sock:
                stop.wait(2)
        except OSError:
            pass

    thread = threading.Thread(target=silent, daemon=True)
    thread.start()
    monkeypatch.setattr(host_keys, "PROBE_SECONDS", 0.2)
    began = time.monotonic()
    try:
        with pytest.raises(ValueError, match="超时"):
            host_keys.fetch_key({**asset, "ssh_port": listener.getsockname()[1]})
        assert time.monotonic() - began < 2
    finally:
        stop.set()
        listener.close()
        thread.join(2)
