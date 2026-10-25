import sqlite3
from cryptography.fernet import Fernet
import pytest
from app import migrate


def test_zabbix_snapshot_reencrypts_without_overwriting_source(tmp_path):
    source = tmp_path / "old.sqlite3"
    destination = tmp_path / "new.sqlite3"
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()
    old = Fernet(old_key)
    keyfile = tmp_path / "key"
    keyfile.write_bytes(old_key)
    keyfile.chmod(0o600)
    encrypted = old.encrypt(b"original-provider-secret").decode()
    with sqlite3.connect(source) as db:
        db.execute(
            "CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT,secret INTEGER)"
        )
        db.execute("INSERT INTO settings VALUES (?,?,1)", ("openai_api_key", encrypted))
        db.execute("CREATE TABLE admin_sessions(token_hash TEXT)")
        db.execute("INSERT INTO admin_sessions VALUES ('old-session')")
    migrate.import_zabbix(source, keyfile, destination, new_key)
    with sqlite3.connect(destination) as db:
        value = db.execute("SELECT value FROM settings").fetchone()[0]
        assert Fernet(new_key).decrypt(value.encode()) == b"original-provider-secret"
        assert db.execute("SELECT COUNT(*) FROM admin_sessions").fetchone()[0] == 0
    with sqlite3.connect(source) as db:
        assert db.execute("SELECT value FROM settings").fetchone()[0] == encrypted
    with pytest.raises(ValueError):
        migrate.import_zabbix(source, keyfile, destination, new_key)
    backup = tmp_path / "rollback.sqlite3"
    migrate.backup(source, backup)
    with sqlite3.connect(backup) as db:
        assert db.execute("SELECT value FROM settings").fetchone()[0] == encrypted


def test_initial_bootstrap_secrets_are_atomic_and_not_world_readable(tmp_path):
    from app.bootstrap import persistent_secret
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "master.key"
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: persistent_secret(path, Fernet.generate_key), range(20))
        )
    assert len(set(results)) == 1
    Fernet(results[0])
    assert path.stat().st_mode & 0o077 == 0
