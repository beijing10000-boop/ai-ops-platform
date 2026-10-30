"""Feishu OAuth login and server-side administrator sessions."""

import hashlib
import hmac
import logging
import os
import secrets
import time
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse

from .main import app, connection, open_ids, read_setting

log = logging.getLogger(__name__)
COOKIE = "zabbix_ai_session"
STATE_COOKIE = "zabbix_ai_oauth_state"
TTL = 8 * 3600


def _tables(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL)"
    )
    db.execute("""CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash TEXT PRIMARY KEY, open_id TEXT NOT NULL, name TEXT NOT NULL,
        csrf TEXT NOT NULL, expires INTEGER NOT NULL)""")


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _redirect_uri():
    """Resolve externally configured origin; default scheme HTTP, opt-in HTTPS."""
    scheme = (read_setting("web_protocol") or "http").lower()
    if scheme not in ("http", "https"):
        raise HTTPException(503, "访问协议必须为 http 或 https")
    host = read_setting("web_public_host").strip()
    if not host:
        raise HTTPException(503, "请在 Web 后台配置外部访问主机")
    # Host is administered via authenticated settings; block path, userinfo,
    # fragments and off-origin redirect tricks.
    parts = urlsplit(scheme + "://" + host)
    if (
        not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise HTTPException(503, "Web 外部地址格式无效（只允许主机名/IP和可选端口）")
    # Only the validated netloc reaches the callback URL.
    return scheme + "://" + parts.netloc + "/api/v1/auth/callback"


def _secure_cookie():
    return urlsplit(_redirect_uri()).scheme == "https"


def _credentials():
    app_id = read_setting("lark_app_id")
    secret = read_setting("lark_app_secret")
    if not app_id or not secret:
        raise HTTPException(503, "请先通过现有后台设置飞书应用 App ID 和 App Secret")
    return app_id, secret


def _admins():
    result = set(open_ids(read_setting("feishu_admin_open_ids")))
    with connection() as db:
        result.update(
            row[0] for row in db.execute("SELECT open_id FROM members WHERE enabled=1")
        )
    return result


@app.get("/api/v1/auth/login")
def feishu_login():
    if not _admins():
        raise HTTPException(503, "尚未配置 Web 管理员，请检查已迁移的飞书管理员名单")
    app_id, _ = _credentials()
    redirect = _redirect_uri()
    state = secrets.token_urlsafe(32)
    with connection() as db:
        _tables(db)
        db.execute("DELETE FROM oauth_states WHERE expires < ?", (int(time.time()),))
        db.execute(
            "INSERT INTO oauth_states VALUES (?,?)",
            (_hash(state), int(time.time()) + 300),
        )
    target = "https://open.feishu.cn/open-apis/authen/v1/index?" + urlencode(
        {"app_id": app_id, "redirect_uri": redirect, "state": state}
    )
    response = RedirectResponse(target, status_code=302)
    response.set_cookie(
        STATE_COOKIE,
        state,
        max_age=300,
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
        path="/api/v1/auth",
    )
    return response


@app.get("/api/v1/auth/callback")
async def feishu_callback(request: Request, code: str = "", state: str = ""):
    cookie_state = request.cookies.get(STATE_COOKIE, "")
    if (
        not code
        or not state
        or not cookie_state
        or not hmac.compare_digest(state, cookie_state)
    ):
        raise HTTPException(403, "飞书登录校验失败，请重新登录")
    with connection() as db:
        _tables(db)
        found = db.execute(
            "SELECT expires FROM oauth_states WHERE state_hash=?", (_hash(state),)
        ).fetchone()
        db.execute("DELETE FROM oauth_states WHERE state_hash=?", (_hash(state),))
        if not found or found[0] < int(time.time()):
            raise HTTPException(403, "授权已过期或使用过，请重新登录")
    app_id, secret = _credentials()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            app_token_resp = await client.post(
                "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
                json={"app_id": app_id, "app_secret": secret},
            )
            app_token_resp.raise_for_status()
            app_token_data = app_token_resp.json()
            if app_token_data.get("code") != 0:
                raise ValueError("app token rejected")
            exchange = await client.post(
                "https://open.feishu.cn/open-apis/authen/v1/access_token",
                headers={
                    "Authorization": "Bearer " + app_token_data["app_access_token"]
                },
                json={"grant_type": "authorization_code", "code": code},
            )
            exchange.raise_for_status()
            exchange_data = exchange.json()
            if exchange_data.get("code") != 0:
                raise ValueError("authorization code rejected")
            user_token = exchange_data["data"]["access_token"]
            info = await client.get(
                "https://open.feishu.cn/open-apis/authen/v1/user_info",
                headers={"Authorization": "Bearer " + user_token},
            )
            info.raise_for_status()
            user_data = info.json()
            if user_data.get("code") != 0:
                raise ValueError("userinfo rejected")
            profile = user_data["data"]
    except Exception as exc:
        log.warning("FEISHU_OAUTH_FAILED reason=%s", type(exc).__name__)
        raise HTTPException(502, "飞书身份验证失败，请检查应用权限和回调地址") from None
    open_id = profile.get("open_id", "")
    if not open_id or open_id not in _admins():
        log.warning("FEISHU_LOGIN_DENIED open_id_sha=%s", _hash(open_id)[:10])
        raise HTTPException(403, "当前飞书账号不是系统管理员")
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    with connection() as db:
        _tables(db)
        db.execute("DELETE FROM admin_sessions WHERE expires < ?", (int(time.time()),))
        db.execute(
            "INSERT INTO admin_sessions VALUES (?,?,?,?,?)",
            (
                _hash(token),
                open_id,
                str(profile.get("name") or "管理员")[:100],
                csrf,
                int(time.time()) + TTL,
            ),
        )
        db.execute(
            "INSERT INTO audit(action,key) VALUES (?,?)",
            ("feishu_login", _hash(open_id)[:12]),
        )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE,
        token,
        max_age=TTL,
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/api/v1/auth")
    return response


def authenticate(request: Request):
    raw = request.cookies.get(COOKIE, "")
    if raw:
        with connection() as db:
            _tables(db)
            row = db.execute(
                "SELECT open_id,name,csrf,expires FROM admin_sessions WHERE token_hash=?",
                (_hash(raw),),
            ).fetchone()
        if row and row[3] > int(time.time()) and row[0] in _admins():
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                if not hmac.compare_digest(
                    row[2], request.headers.get("x-csrf-token", "")
                ):
                    raise HTTPException(403, "CSRF token invalid")
            from .security.rbac import role_for, ROLES

            role = role_for(row[0])
            if not role:
                raise HTTPException(403, "账号已停用")
            return {
                "open_id": row[0],
                "name": row[1],
                "csrf": row[2],
                "role": role,
                "permissions": sorted(ROLES[role]),
            }
    # Optional migration-only escape hatch, off by default.
    if os.getenv("ALLOW_LEGACY_ADMIN_TOKEN", "false").lower() == "true":
        admin = os.getenv("ADMIN_API_TOKEN", "")
        supplied = request.headers.get("authorization", "")
        if admin and hmac.compare_digest(supplied, "Bearer " + admin):
            return {"open_id": "legacy-admin", "name": "Legacy Admin", "csrf": ""}
    raise HTTPException(401, "请先使用飞书账号登录")


@app.get("/api/v1/auth/me")
def me(request: Request):
    return authenticate(request)


@app.post("/api/v1/auth/logout")
def logout(request: Request):
    authenticate(request)
    raw = request.cookies.get(COOKIE, "")
    if raw:
        with connection() as db:
            db.execute("DELETE FROM admin_sessions WHERE token_hash=?", (_hash(raw),))
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE, path="/")
    return response
