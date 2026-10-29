"""Current platform schema and one-time removal of the retired local SSH backend."""


def _migrate_v4(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS platform_migrations(version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)"
    )
    if db.execute("SELECT 1 FROM platform_migrations WHERE version=4").fetchone():
        return
    existing = db.execute("SELECT 1 FROM sqlite_master WHERE name='assets'").fetchone()
    if existing:
        # DROP COLUMN keeps asset IDs, group membership and report foreign keys intact.
        columns = {r[1] for r in db.execute("PRAGMA table_info(assets)")}
        for column in (
            "ssh_port",
            "username",
            "host_key",
            "credential_id",
            "proxy_id",
            "diagnostic_mode",
            "privileged_approved",
            "diagnostic_paths",
            "last_test_status",
            "last_test_at",
        ):
            if column in columns:
                db.execute("ALTER TABLE assets DROP COLUMN " + column)
        for table in (
            "host_key_scan_items",
            "host_key_scans",
            "ssh_proxies",
            "ssh_credentials",
            "migration_imports",
        ):
            db.execute("DROP TABLE IF EXISTS " + table)
        db.execute(
            "DELETE FROM settings WHERE key IN ('ssh_concurrency','ssh_timeout')"
        )
        db.execute("DELETE FROM integration_health WHERE provider='linux_ssh'")
        db.execute(
            "UPDATE diagnostic_tasks SET status='failed',stage='retired',error_type='LocalSSHRemoved',completed_at=CURRENT_TIMESTAMP WHERE kind!='analysis' AND status IN ('queued','running')"
        )
    else:
        statements = [
            """CREATE TABLE assets(id INTEGER PRIMARY KEY, name TEXT NOT NULL, zabbix_hostid TEXT UNIQUE,
                device_type TEXT NOT NULL DEFAULT 'unknown', address TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                revision INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP)""",
            "CREATE INDEX ix_assets_type ON assets(device_type,enabled,id)",
            "CREATE INDEX ix_assets_name ON assets(name)",
            "CREATE TABLE asset_groups(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, zabbix_groupid TEXT UNIQUE)",
            "CREATE TABLE asset_group_members(asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE, group_id INTEGER REFERENCES asset_groups(id) ON DELETE CASCADE, PRIMARY KEY(asset_id,group_id))",
            "CREATE TABLE members(open_id TEXT PRIMARY KEY, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)",
            """CREATE TABLE diagnostic_tasks(task_id TEXT PRIMARY KEY, trace_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL, source TEXT NOT NULL, actor TEXT NOT NULL, event_id TEXT,
                asset_id INTEGER REFERENCES assets(id), diagnostic_type TEXT NOT NULL, profile TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued', stage TEXT NOT NULL DEFAULT 'queued',
                request TEXT NOT NULL, report TEXT, error_type TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
                attempt INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT, completed_at TEXT, duration_ms INTEGER, token_input INTEGER,
                token_output INTEGER, token_total INTEGER, tools INTEGER NOT NULL DEFAULT 0)""",
            "CREATE INDEX ix_tasks_created ON diagnostic_tasks(created_at DESC,task_id)",
            "CREATE INDEX ix_tasks_event ON diagnostic_tasks(event_id,status)",
            "CREATE UNIQUE INDEX ix_tasks_active_event ON diagnostic_tasks(event_id) WHERE event_id IS NOT NULL AND kind='analysis' AND status IN ('queued','running')",
            """CREATE TABLE diagnostic_evidence(id INTEGER PRIMARY KEY, task_id TEXT NOT NULL REFERENCES diagnostic_tasks(task_id),
                trace_id TEXT NOT NULL, provider TEXT NOT NULL, tool TEXT NOT NULL, status TEXT NOT NULL,
                collected_at TEXT DEFAULT CURRENT_TIMESTAMP, duration_ms INTEGER NOT NULL, payload TEXT NOT NULL)""",
            "CREATE INDEX ix_evidence_task ON diagnostic_evidence(task_id,id)",
            "CREATE TABLE integration_health(provider TEXT PRIMARY KEY, status TEXT NOT NULL, checked_at TEXT DEFAULT CURRENT_TIMESTAMP, detail TEXT NOT NULL)",
        ]
        for statement in statements:
            db.execute(statement)
    for name in ("actor", "trace_id"):
        if name not in {r[1] for r in db.execute("PRAGMA table_info(audit)")}:
            db.execute("ALTER TABLE audit ADD COLUMN " + name + " TEXT")
    db.execute(
        "CREATE TABLE IF NOT EXISTS feishu_event_messages(message_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,event_value TEXT NOT NULL,chat_id TEXT NOT NULL,kind TEXT NOT NULL)"
    )
    db.execute(
        "INSERT OR IGNORE INTO feishu_event_messages SELECT message_id,event_id,'1',chat_id,'problem' FROM alert_message_links"
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS ix_token_period ON ai_token_runs(created_at,source,model)"
    )
    db.execute("INSERT INTO platform_migrations(version) VALUES (4)")


def migrate(db):
    _migrate_v4(db)
    if not db.execute("SELECT 1 FROM platform_migrations WHERE version=5").fetchone():
        db.execute("""CREATE TABLE IF NOT EXISTS platform_skills(
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0, priority INTEGER NOT NULL DEFAULT 100,
            scopes TEXT NOT NULL, providers TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
            digest TEXT NOT NULL, bundle TEXT NOT NULL, updated_by TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        db.execute("INSERT INTO platform_migrations(version) VALUES (5)")
    if not db.execute("SELECT 1 FROM platform_migrations WHERE version=6").fetchone():
        db.execute("""CREATE TABLE IF NOT EXISTS model_interactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL REFERENCES diagnostic_tasks(task_id),
            round_number INTEGER NOT NULL,
            model TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            duration_ms INTEGER NOT NULL,
            token_input INTEGER, token_output INTEGER, token_total INTEGER,
            payload TEXT NOT NULL
        )""")
        db.execute(
            "CREATE INDEX IF NOT EXISTS ix_model_interactions_task ON model_interactions(task_id,id)"
        )
        db.execute("INSERT INTO platform_migrations(version) VALUES (6)")
    if not db.execute("SELECT 1 FROM platform_migrations WHERE version=7").fetchone():
        # Content-addressed, encrypted copies of text repeated across tasks and
        # rounds (Skill bundles, system instructions); rows reference the digest.
        db.execute("""CREATE TABLE IF NOT EXISTS shared_blobs(
            digest TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        db.execute(
            "CREATE TABLE IF NOT EXISTS maintenance(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        db.execute("INSERT INTO platform_migrations(version) VALUES (7)")
    if not db.execute("SELECT 1 FROM platform_migrations WHERE version=8").fetchone():
        # managed=1 marks the platform-maintained base Skill. Existing Skills keep
        # mode 'standalone' (they replace the base), so nothing loads twice.
        columns = {r[1] for r in db.execute("PRAGMA table_info(platform_skills)")}
        if "managed" not in columns:
            db.execute(
                "ALTER TABLE platform_skills ADD COLUMN managed INTEGER NOT NULL DEFAULT 0"
            )
        if "mode" not in columns:
            db.execute(
                "ALTER TABLE platform_skills ADD COLUMN mode TEXT NOT NULL DEFAULT 'standalone'"
            )
        db.execute("INSERT INTO platform_migrations(version) VALUES (8)")


def row_dict(row, cur):
    return dict(zip((x[0] for x in cur.description), row)) if row else None


def archived_asset(asset_id):
    """Historical report compatibility only; never used to select an execution target."""
    from .main import connection

    with connection() as db:
        cur = db.execute(
            "SELECT id,name,zabbix_hostid,device_type FROM assets WHERE id=?",
            (asset_id,),
        )
        return row_dict(cur.fetchone(), cur)
