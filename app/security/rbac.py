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


def role_for(open_id):
    from ..main import connection, read_setting

    if open_id in {
        x.strip() for x in read_setting("feishu_admin_open_ids").split(",") if x.strip()
    }:
        return "super_admin"
    # Legacy identity is only issued by the explicitly opt-in authenticator.
    if open_id == "legacy-admin":
        return "super_admin"
    with connection() as db:
        row = db.execute(
            "SELECT role FROM members WHERE open_id=? AND enabled=1", (open_id,)
        ).fetchone()
    return row[0] if row and row[0] in ROLES else None


def permits(open_id, permission):
    grants = ROLES.get(role_for(open_id), set())
    return "*" in grants or permission in grants


def enforce(open_id, permission):
    if not permits(open_id, permission):
        raise HTTPException(403, "当前角色没有此操作权限")


def require(permission):
    def dependency(request: Request):
        from ..feishu_auth import authenticate

        identity = authenticate(request)
        enforce(identity["open_id"], permission)
        return identity

    return dependency


def audit(actor, action, target="", trace_id=None):
    from ..main import connection

    with connection() as db:
        db.execute(
            "INSERT INTO audit(action,key,actor,trace_id) VALUES (?,?,?,?)",
            (action[:100], str(target)[:200], str(actor)[:160], trace_id),
        )
