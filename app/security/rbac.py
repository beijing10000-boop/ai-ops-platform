from fastapi import HTTPException, Request

ROLES = {
    "super_admin": {"*"},
    "ops_admin": {
        "overview.read",
        "diagnostics.run",
        "reports.read",
        "logs.read",
        "audit.read",
        "tools.read",
        "settings.manage",
        "alerts.manage",
    },
    "operator": {
        "overview.read",
        "diagnostics.run",
        "reports.read",
        "tools.read",
    },
    "auditor": {
        "overview.read",
        "reports.read",
        "audit.read",
        "tools.read",
    },
}


def role_for(open_id, db=None):
    """super_admin for the configured Feishu admins, else the role of an
    enabled member; None otherwise. Both reads share one connection, `db`
    when the caller has one open."""
    from ..main import connection, open_ids, setting_value

    # Legacy identity is only issued by the explicitly opt-in authenticator.
    if open_id == "legacy-admin":
        return "super_admin"
    if db is None:
        with connection() as db:
            return role_for(open_id, db)
    if open_id in open_ids(setting_value(db, "feishu_admin_open_ids")):
        return "super_admin"
    row = db.execute(
        "SELECT role FROM members WHERE open_id=? AND enabled=1", (open_id,)
    ).fetchone()
    return row[0] if row and row[0] in ROLES else None


def granted(role, permission):
    grants = ROLES.get(role, set())
    return "*" in grants or permission in grants


def permits(open_id, permission):
    return granted(role_for(open_id), permission)


def enforce(who, permission):
    """Raise 403 unless `who` holds `permission`. `who` is the identity
    authenticate() returned, whose role was read with the session (no second
    lookup), or a bare open_id, which is looked up."""
    if isinstance(who, str):
        role = role_for(who)
    else:
        role = who["role"] if who.get("role") else role_for(who["open_id"])
    if not granted(role, permission):
        raise HTTPException(403, "当前角色没有此操作权限")


def require(permission):
    def dependency(request: Request):
        from ..feishu_auth import authenticate

        identity = authenticate(request)
        enforce(identity, permission)
        return identity

    return dependency


def audit(actor, action, target="", trace_id=None):
    from ..main import connection

    with connection() as db:
        db.execute(
            "INSERT INTO audit(action,key,actor,trace_id) VALUES (?,?,?,?)",
            (action[:100], str(target)[:200], str(actor)[:160], trace_id),
        )
