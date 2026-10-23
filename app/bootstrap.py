"""Persistent encryption/bootstrap secrets; application settings stay in Web."""

import os
import stat
from pathlib import Path


def persistent_secret(path, factory):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise RuntimeError("主密钥文件不能是符号链接")
    if not path.exists():
        import tempfile

        fd, temporary = tempfile.mkstemp(prefix=".secret-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(factory())
                target.flush()
                os.fsync(target.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("主密钥或初始化凭据文件权限必须为 0600")
    return path.read_bytes().strip()


if __name__ == "__main__":
    import secrets
    from .main import DATA_DIR, cipher, connection, ADMIN_TOKEN

    cipher()
    with connection():
        pass
    if not ADMIN_TOKEN:
        persistent_secret(
            DATA_DIR / "bootstrap.token", lambda: secrets.token_urlsafe(48).encode()
        )
    print("持久化密钥与初始化凭据已准备完成；敏感值不写入日志。")
