"""Executed inside a fresh CI-only Compose stack; never against an existing volume."""

import os
import stat
import sys
from app.main import DATA_DIR, DB, connection, cipher, read_setting

assert os.getuid() == 10001, "Application must run without root"
assert stat.S_IMODE(DATA_DIR.stat().st_mode) == 0o700
assert stat.S_IMODE(DB.stat().st_mode) == 0o600
assert stat.S_IMODE((DATA_DIR / "master.key").stat().st_mode) == 0o600
assert stat.S_IMODE((DATA_DIR / "bootstrap.token").stat().st_mode) == 0o600
key = "ci_container_restart_probe"
value = "isolated-ci-fixture-value"
if sys.argv[1] == "write":
    with connection() as db:
        db.execute(
            "INSERT INTO settings VALUES (?,?,1)",
            (key, cipher().encrypt(value.encode()).decode()),
        )
    assert read_setting(key) == value
    print("Non-root container, file permissions and encrypted write: passed")
else:
    assert read_setting(key) == value
    with connection() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert (
            db.execute("SELECT MAX(version) FROM platform_migrations").fetchone()[0]
            == 2
        )
        db.execute("DELETE FROM settings WHERE key=?", (key,))
    print(
        "Encrypted configuration survives restart; database integrity and migration version: passed"
    )
