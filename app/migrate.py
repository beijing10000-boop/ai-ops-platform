"""Offline, explicit migration. Source databases are opened read-only."""

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
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


def import_linux(source, key_file):
    from .main import connection, cipher
    from .security.redact import redact, redact_data

    source = Path(source).resolve(strict=True)
    old = Fernet(read_key(key_file))
    with readonly(source) as legacy:
        legacy.row_factory = sqlite3.Row
        tables = {
            r[0]
            for r in legacy.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if not {"app_settings", "hosts", "host_groups", "proxies"} <= tables:
            raise ValueError("不是受支持的 Linux 旧数据库")
        # Hash a stable read snapshot, rather than the live SQLite main file while WAL is active.
        snapshot = sqlite3.connect(":memory:")
        legacy.backup(snapshot)
    snapshot.row_factory = sqlite3.Row
    try:
        dump = "\n".join(snapshot.iterdump()).encode()
        source_hash = hashlib.sha256(dump).hexdigest()

        def dec(value):
            return (
                old.decrypt(
                    value.encode() if isinstance(value, str) else value
                ).decode()
                if value
                else ""
            )

        settings = {
            r["key"]: dec(r["value"])
            for r in snapshot.execute("SELECT * FROM app_settings")
        }
        hosts = [dict(r) for r in snapshot.execute("SELECT * FROM hosts")]
        groups = [dict(r) for r in snapshot.execute("SELECT * FROM host_groups")]
        proxies = [dict(r) for r in snapshot.execute("SELECT * FROM proxies")]
        for p in proxies:
            p["private_key"] = dec(p.get("private_key"))
            p["passphrase"] = dec(p.get("passphrase"))
        runs = (
            [dict(r) for r in snapshot.execute("SELECT * FROM diagnostic_runs")]
            if "diagnostic_runs" in tables
            else []
        )
        for r in runs:
            r["result"] = redact_data(json.loads(dec(r["result"])))
        audits = (
            [dict(r) for r in snapshot.execute("SELECT * FROM audit")]
            if "audit" in tables
            else []
        )
    finally:
        snapshot.close()

    def enc(text):
        return cipher().encrypt(str(text).encode()).decode()

    def enc_json(value):
        return enc(json.dumps(value, ensure_ascii=False))

    # Decryption is completed before changing target state; errors roll back the entire import.
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute(
            "SELECT 1 FROM migration_imports WHERE source_hash=?", (source_hash,)
        ).fetchone():
            return {"already_imported": True, "source_hash": source_hash}
        group_map = {}
        proxy_map = {}
        host_map = {}
        credential_id = None
        if settings.get("ssh_private_key"):
            credential_id = db.execute(
                "INSERT INTO ssh_credentials(name,private_key,passphrase) VALUES (?,?,?)",
                (
                    "Imported Linux " + source_hash[:8],
                    enc(settings["ssh_private_key"]),
                    enc(settings.get("ssh_key_passphrase", "")),
                ),
            ).lastrowid
        for g in groups:
            db.execute(
                "INSERT OR IGNORE INTO asset_groups(name) VALUES (?)", (g["name"],)
            )
            group_map[g["id"]] = db.execute(
                "SELECT id FROM asset_groups WHERE name=?", (g["name"],)
            ).fetchone()[0]
        for p in proxies:
            if (
                not p.get("address")
                or not p.get("host_key")
                or not p.get("private_key")
            ):
                continue
            cid = db.execute(
                "INSERT INTO ssh_credentials(name,private_key,passphrase) VALUES (?,?,?)",
                (
                    "Imported proxy " + str(p["id"]) + " " + source_hash[:8],
                    enc(p["private_key"]),
                    enc(p.get("passphrase", "")),
                ),
            ).lastrowid
            proxy_map[p["id"]] = db.execute(
                "INSERT INTO ssh_proxies(name,address,port,username,host_key,credential_id) VALUES (?,?,?,?,?,?)",
                (
                    p["name"] + " [import " + source_hash[:8] + "]",
                    p["address"],
                    p.get("ssh_port", 22),
                    p.get("username", "diag-proxy"),
                    p["host_key"],
                    cid,
                ),
            ).lastrowid
        for h in hosts:
            # Legacy root gateways must be reapproved. No IP/name-based Zabbix binding is guessed.
            aid = db.execute(
                "INSERT INTO assets(name,device_type,address,ssh_port,username,host_key,credential_id,proxy_id,diagnostic_mode,privileged_approved,enabled) VALUES (?,'linux',?,?,'root',?,?,?,'privileged',0,0)",
                (
                    h["name"],
                    h["address"],
                    h.get("ssh_port", 22),
                    h.get("host_key", ""),
                    credential_id,
                    proxy_map.get(h.get("proxy_id")),
                ),
            ).lastrowid
            host_map[h["id"]] = aid
            if h.get("group_id") in group_map:
                db.execute(
                    "INSERT INTO asset_group_members VALUES (?,?)",
                    (aid, group_map[h["group_id"]]),
                )
        mapping = {
            "feishu_app_id": "lark_app_id",
            "feishu_app_secret": "lark_app_secret",
            "admin_open_id": "feishu_admin_open_ids",
        }
        for old_name, new_name in mapping.items():
            if not settings.get(old_name):
                continue
            if db.execute(
                "SELECT 1 FROM settings WHERE key=? AND value!=''", (new_name,)
            ).fetchone():
                continue
            secret = new_name == "lark_app_secret"
            db.execute(
                "INSERT INTO settings(key,value,secret) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,secret=excluded.secret",
                (
                    new_name,
                    enc(settings[old_name]) if secret else settings[old_name],
                    int(secret),
                ),
            )
        for r in runs:
            tid = uuid.uuid4().hex
            trace = uuid.uuid4().hex
            stamp = datetime.fromtimestamp(r["time"], timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            status = (
                "success"
                if r["status"] == "success"
                else "partial"
                if r["status"] == "warning"
                else "failed"
            )
            db.execute(
                "INSERT INTO diagnostic_tasks(task_id,trace_id,kind,source,actor,asset_id,diagnostic_type,profile,status,stage,request,report,created_at,completed_at,duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tid,
                    trace,
                    "legacy",
                    "legacy_linux",
                    "legacy-import",
                    host_map.get(r["host_id"]),
                    r["action"],
                    "standard",
                    status,
                    status,
                    enc_json({"legacy_id": r["id"]}),
                    enc_json(r["result"]),
                    stamp,
                    stamp,
                    r["duration_ms"],
                ),
            )
            db.execute(
                "INSERT INTO diagnostic_evidence(task_id,trace_id,provider,tool,status,collected_at,duration_ms,payload) VALUES (?,?,?,?,?,?,?,?)",
                (
                    tid,
                    trace,
                    "legacy_linux",
                    r["action"],
                    status,
                    stamp,
                    r["duration_ms"],
                    enc_json(r["result"]),
                ),
            )
        for a in audits:
            stamp = datetime.fromtimestamp(a["time"], timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            db.execute(
                "INSERT INTO audit(action,key,actor,created_at) VALUES (?,?,?,?)",
                (
                    "legacy_linux",
                    redact(a["action"], 200),
                    a.get("actor", "legacy"),
                    stamp,
                ),
            )
        db.execute(
            "INSERT INTO migration_imports(source_hash,details) VALUES (?,?)",
            (
                source_hash,
                json.dumps(
                    {"hosts": len(hosts), "runs": len(runs), "audit": len(audits)}
                ),
            ),
        )
    return {
        "source_hash": source_hash,
        "hosts": len(hosts),
        "runs": len(runs),
        "audit": len(audits),
        "hosts_disabled_until_review": True,
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
    l = sub.add_parser("import-linux")
    l.add_argument("--source", required=True)
    l.add_argument("--source-key-file", required=True)
    l.add_argument("--offline-ack", action="store_true", required=True)
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
        else:
            from .main import DB

            snapshot = DB.with_name(
                DB.name
                + ".pre-linux-import-"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                + ".bak"
            )
            if DB.exists():
                backup(DB, snapshot)
            result = import_linux(args.source, args.source_key_file)
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
