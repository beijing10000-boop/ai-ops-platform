import json
import sqlite3
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import pytest
from app import main, migrate


@pytest.fixture
def legacy(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path / "target")
    monkeypatch.setattr(main, "DB", tmp_path / "target/app.sqlite3")
    monkeypatch.setattr(main, "MASTER_KEY", Fernet.generate_key().decode())
    source = tmp_path / "linux.db"
    key = Fernet.generate_key()
    f = Fernet(key)
    keyfile = tmp_path / "source-key"
    keyfile.write_bytes(key)
    keyfile.chmod(0o600)
    enc = lambda v: f.encrypt(v.encode())
    with sqlite3.connect(source) as db:
        db.executescript("""CREATE TABLE app_settings(key TEXT PRIMARY KEY,value BLOB);
        CREATE TABLE host_groups(id INTEGER PRIMARY KEY,name TEXT);
        CREATE TABLE proxies(id INTEGER PRIMARY KEY,name TEXT,address TEXT,ssh_port INTEGER,username TEXT,host_key TEXT,private_key BLOB,passphrase BLOB);
        CREATE TABLE hosts(id INTEGER PRIMARY KEY,name TEXT,address TEXT,ssh_port INTEGER,group_id INTEGER,proxy_id INTEGER,host_key TEXT);
        CREATE TABLE diagnostic_runs(id INTEGER PRIMARY KEY,host_id INTEGER,host_name TEXT,action TEXT,service TEXT,time INTEGER,duration_ms INTEGER,status TEXT,result BLOB);
        CREATE TABLE audit(id INTEGER PRIMARY KEY,time INTEGER,actor TEXT,action TEXT);""")
        db.executemany(
            "INSERT INTO app_settings VALUES (?,?)",
            [
                (k, enc(v))
                for k, v in {
                    "ssh_private_key": "legacy-private-test-material",
                    "ssh_key_passphrase": "legacy-passphrase",
                    "feishu_app_id": "cli_ABCDEFGH",
                    "feishu_app_secret": "legacy-app-secret",
                    "admin_open_id": "ou_legacy",
                }.items()
            ],
        )
        db.execute("INSERT INTO host_groups VALUES (1,'linux-group')")
        db.execute(
            "INSERT INTO hosts VALUES (1,'old-linux','172.20.1.10',22,1,NULL,'')"
        )
        db.execute(
            "INSERT INTO diagnostic_runs VALUES (1,1,?,'cpu',NULL,1700000000,20,'success',?)",
            (
                "old-linux",
                enc(
                    json.dumps({"output": "password=privatevalue", "status": "success"})
                ),
            ),
        )
        db.execute(
            "INSERT INTO audit VALUES (1,1700000000,'old-operator','diagnose:1:cpu')"
        )
    return source, keyfile


def test_linux_import_reencrypts_keeps_history_and_is_idempotent(legacy):
    source, keyfile = legacy
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    first = migrate.import_linux(source, keyfile)
    second = migrate.import_linux(source, keyfile)
    assert first["hosts"] == 1 and first["runs"] == 1 and second["already_imported"]
    with main.connection() as db:
        host = db.execute(
            "SELECT enabled,privileged_approved,zabbix_hostid,diagnostic_mode FROM assets"
        ).fetchone()
        assert host == (0, 0, None, "privileged")
        key = db.execute("SELECT private_key FROM ssh_credentials").fetchone()[0]
        assert (
            main.cipher().decrypt(key.encode()).decode()
            == "legacy-private-test-material"
        )
        with pytest.raises(InvalidToken):
            Fernet(keyfile.read_bytes()).decrypt(key.encode())
        report = db.execute("SELECT report FROM diagnostic_tasks").fetchone()[0]
        decoded = main.cipher().decrypt(report.encode()).decode()
        assert "privatevalue" not in decoded and "[REDACTED]" in decoded
        assert (
            db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='legacy_linux'"
            ).fetchone()[0]
            == 1
        )
        assert db.execute("SELECT COUNT(*) FROM ssh_credentials").fetchone()[0] == 1
    assert hashlib.sha256(source.read_bytes()).hexdigest() == checksum


def test_bad_source_key_does_not_modify_target(legacy, tmp_path):
    source, _ = legacy
    bad = tmp_path / "bad-key"
    bad.write_bytes(Fernet.generate_key())
    bad.chmod(0o600)
    with main.connection() as db:
        before = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    with pytest.raises(InvalidToken):
        migrate.import_linux(source, bad)
    with main.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == before


def test_mid_import_failure_rolls_back_all_rows(legacy, monkeypatch):
    source, keyfile = legacy
    original = main.cipher()
    calls = [0]

    class FailDuringImport:
        def encrypt(self, text):
            calls[0] += 1
            if calls[0] > 2:
                raise RuntimeError("simulated failure after credential writes")
            return original.encrypt(text)

    monkeypatch.setattr(main, "cipher", lambda: FailDuringImport())
    with pytest.raises(RuntimeError):
        migrate.import_linux(source, keyfile)
    with main.connection() as db:
        for table in ("assets", "asset_groups", "ssh_credentials", "migration_imports"):
            assert db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0


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


def test_long_nested_report_import_preserves_json_and_redacts_secrets(legacy):
    source, keyfile = legacy
    report = {
        "output": "x" * 120000,
        "nested": [
            {"password": "space quote \" and slash \\ secret"},
            {"text": "token=abc", "token_total": 15},
            {"private_key": "private material", "enabled": True, "missing": None},
        ],
    }
    encrypted = Fernet(keyfile.read_bytes()).encrypt(json.dumps(report).encode())
    with sqlite3.connect(source) as db:
        db.execute("UPDATE diagnostic_runs SET result=?", (encrypted,))
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    assert migrate.import_linux(source, keyfile)["runs"] == 1
    with main.connection() as db:
        value = db.execute("SELECT report FROM diagnostic_tasks").fetchone()[0]
    decoded = json.loads(main.cipher().decrypt(value.encode()))
    assert decoded["output"] == report["output"]
    assert decoded["nested"] == [
        {"password": "[REDACTED]"},
        {"text": "token=[REDACTED]", "token_total": 15},
        {"private_key": "[REDACTED]", "enabled": True, "missing": None},
    ]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == checksum
