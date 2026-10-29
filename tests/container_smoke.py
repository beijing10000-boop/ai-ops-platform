"""Executed inside a fresh CI-only Compose stack; never against an existing volume."""

import os
import stat
import sys
from app.main import DATA_DIR, DB, connection, cipher, read_setting
from app import skill_store

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
    text = "---\nname: ci-persistent-skill\ndescription: Container persistence fixture\n---\nQuery registered SSH assets.\n"
    skill_store.save(
        {**skill_store.parse_document(text), "files": {"SKILL.md": text}},
        scopes=["qa"],
        providers=["ssh_mcp"],
        enabled=True,
        priority=100,
        actor="ci",
    )
    print("Non-root container, file permissions and encrypted write: passed")
else:
    assert read_setting(key) == value
    row = next(
        row for row in skill_store.rows(True) if row["name"] == "ci-persistent-skill"
    )
    assert (
        row["enabled"]
        and row["revision"] == 1
        and "Query registered SSH assets." in row["instructions"]
    )
    with connection() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert (
            db.execute("SELECT MAX(version) FROM platform_migrations").fetchone()[0]
            == 6
        )
        db.execute("DELETE FROM settings WHERE key=?", (key,))
        db.execute("DELETE FROM platform_skills WHERE id=?", (row["id"],))
    print(
        "Encrypted configuration survives restart; database integrity and migration version: passed"
    )
