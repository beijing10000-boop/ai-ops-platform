"""Fetch an untrusted SSH host key without authenticating to the target."""

import socket
import threading
from contextlib import suppress

import paramiko

from .. import inventory
from ..main import connection
from .ssh import _connect

PROBE_SECONDS = 15


def fetch_key(asset):
    destination = inventory.address(asset["address"])
    jump = None
    stream = None
    transport = None
    expired = threading.Event()

    def close():
        for resource in (transport, stream, jump):
            if resource is not None:
                with suppress(Exception):
                    resource.close()

    def expire():
        expired.set()
        close()

    timer = threading.Timer(PROBE_SECONDS, expire)
    timer.daemon = True
    timer.start()
    try:
        if asset["proxy_id"]:
            with connection() as db:
                cur = db.execute(
                    "SELECT * FROM ssh_proxies WHERE id=?", (asset["proxy_id"],)
                )
                proxy = inventory.row_dict(cur.fetchone(), cur)
            if not proxy or not proxy["host_key"]:
                raise ValueError("请先核验并登记跳板主机公钥")
            jump = paramiko.SSHClient()
            _connect(
                jump, proxy["address"], proxy["port"], proxy["username"],
                proxy["host_key"], inventory.credential_key(proxy["credential_id"]),
            )
            stream = jump.get_transport().open_channel(
                "direct-tcpip", (destination, asset["ssh_port"]), ("127.0.0.1", 0),
                timeout=5,
            )
        else:
            stream = socket.create_connection((destination, asset["ssh_port"]), timeout=5)
        if expired.is_set():
            raise TimeoutError("获取 SSH 主机公钥超时")
        transport = paramiko.Transport(stream)
        options = transport.get_security_options()
        supported = (
            "ssh-ed25519", "ecdsa-sha2-nistp256",
            "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
        )
        preferred = (asset["host_key"].split() or [""])[0]
        options.key_types = tuple(sorted(
            (name for name in supported if name in options.key_types),
            key=lambda name: not (
                name == preferred
                or preferred == "ssh-rsa" and name.startswith("rsa-sha2-")
            ),
        ))
        transport.start_client(timeout=5)
        if expired.is_set():
            raise TimeoutError("获取 SSH 主机公钥超时")
        key = transport.get_remote_server_key()
        return inventory.host_key(key.get_name() + " " + key.get_base64())
    except paramiko.BadHostKeyException:
        raise ValueError("跳板主机公钥不匹配，请先独立核验") from None
    except paramiko.AuthenticationException:
        raise ValueError("跳板认证失败，请检查跳板账号和密钥") from None
    except (paramiko.SSHException, OSError, EOFError):
        raise ValueError("SSH 握手失败或超时，请检查地址、端口及跳板") from None
    finally:
        timer.cancel()
        timer.join()
        close()
