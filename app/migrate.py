"""Offline, explicit migration. Source databases are opened read-only."""

import argparse
import json
import os
import sqlite3
import stat
import uuid
from pathlib import Path
from cryptography.fernet import Fernet


def read_key(path):
    path = Path(path)
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("密钥文件必须是权限为 0600 的普通文件")
    value = path.read_bytes().strip()
    Fernet(value)
    return value


def readonly(path):
    path = Path(path).resolve(strict=True)
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)


def backup(source, destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with readonly(source) as src, sqlite3.connect(destination) as dst:
            src.backup(dst)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


def import_zabbix(source, source_key_file, destination, target_key):
    """Copy a consistent snapshot; reencrypt settings; never overwrite an instance."""
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    if destination.exists() or source == destination:
        raise ValueError("目标必须为新的数据库文件，不能覆盖原实例")
    old = Fernet(read_key(source_key_file))
    new = Fernet(target_key)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = destination.with_name(destination.name + ".migration-" + uuid.uuid4().hex)
    try:
        backup(source, temp)
        with sqlite3.connect(temp) as db:
            for key, value in db.execute(
                "SELECT key,value FROM settings WHERE secret=1"
            ).fetchall():
                db.execute(
                    "UPDATE settings SET value=? WHERE key=?",
                    (new.encrypt(old.decrypt(value.encode())).decode(), key),
                )
            for table in ("admin_sessions", "oauth_states"):
                if db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name=?", (table,)
                ).fetchone():
                    db.execute("DELETE FROM " + table)
            # Existing unified databases may hold further encrypted records; importing those with this legacy-only tool is refused.
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='diagnostic_tasks'"
            ).fetchone():
                raise ValueError(
                    "该源已是新平台数据库；请使用原密钥整体恢复备份，而非旧版导入工具"
                )
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("数据库完整性检查失败")
        os.link(temp, destination)  # fail if another process created destination
    finally:
        temp.unlink(missing_ok=True)
    return {
        "database": str(destination),
        "source_unchanged": True,
        "sessions_revoked": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--source", required=True)
    b.add_argument("--destination", required=True)
    z = sub.add_parser("import-zabbix")
    z.add_argument("--source", required=True)
    z.add_argument("--source-key-file", required=True)
    z.add_argument("--destination", required=True)
    z.add_argument("--target-key-file", required=True)
    args = parser.parse_args()
    try:
        if args.command == "backup":
            result = {"backup": str(backup(args.source, args.destination))}
        elif args.command == "import-zabbix":
            result = import_zabbix(
                args.source,
                args.source_key_file,
                args.destination,
                read_key(args.target_key_file),
            )
        print(json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        # Decryption exceptions and invalid content must not echo credential fields.
        parser.exit(
            1,
            "迁移未完成："
            + type(exc).__name__
            + "。请保留原数据库和密钥，并查看迁移文档。\n",
        )


if __name__ == "__main__":
    main()
