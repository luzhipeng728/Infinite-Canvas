"""轻量级账号系统：sqlite 存用户 + HMAC 签名 cookie session。"""
import os
import time
import json
import hmac
import base64
import hashlib
import secrets
import sqlite3
import contextvars
from dataclasses import dataclass
from typing import Optional, List
from threading import Lock

from fastapi import HTTPException, Request, Response

USERS_DB_PATH: str = ""
SESSION_SECRET: str = ""
SESSION_COOKIE_NAME = "ic_session"
SESSION_TTL_SECONDS = 30 * 24 * 3600  # 30 天滑动过期
PBKDF2_ITER = 200_000

_db_lock = Lock()
current_user_ctx: contextvars.ContextVar[Optional["User"]] = contextvars.ContextVar(
    "ic_current_user", default=None
)


@dataclass
class User:
    id: str
    username: str
    is_admin: bool
    must_change_password: bool
    created_at: float


def _conn():
    conn = sqlite3.connect(USERS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init(db_path: str, secret: str):
    """模块初始化。db_path 是 sqlite 文件路径，secret 用来签 session。"""
    global USERS_DB_PATH, SESSION_SECRET
    USERS_DB_PATH = db_path
    SESSION_SECRET = secret
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _db_lock, _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )
            """
        )
        c.commit()


def bootstrap_admin(username: str = "admin", password: str = "admin123"):
    """没有任何用户时，创建默认 admin。"""
    with _db_lock, _conn() as c:
        cnt = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if cnt > 0:
            return None
        uid = secrets.token_hex(8)
        c.execute(
            "INSERT INTO users (id, username, password_hash, is_admin, must_change_password, created_at) VALUES (?, ?, ?, 1, 1, ?)",
            (uid, username, _hash_password(password), time.time()),
        )
        c.commit()
        print(f"[auth] bootstrap admin {username} / {password} (must-change on first login)")
        return uid


# ===== 密码 =====

def _hash_password(plain: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def _verify_password(plain: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, dk_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ===== CRUD =====

def _row_to_user(row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        is_admin=bool(row["is_admin"]),
        must_change_password=bool(row["must_change_password"]),
        created_at=float(row["created_at"]),
    )


def create_user(username: str, password: str, is_admin: bool = False, must_change_password: bool = True) -> User:
    username = (username or "").strip()
    if not username or len(username) > 64:
        raise HTTPException(status_code=400, detail="用户名长度 1-64")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="密码至少 6 位")
    uid = secrets.token_hex(8)
    try:
        with _db_lock, _conn() as c:
            c.execute(
                "INSERT INTO users (id, username, password_hash, is_admin, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, username, _hash_password(password), 1 if is_admin else 0, 1 if must_change_password else 0, time.time()),
            )
            c.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="用户名已存在")
    return get_user(uid)


def get_user(user_id: str) -> Optional[User]:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user(row) if row else None


def get_user_by_username(username: str) -> Optional[User]:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return _row_to_user(row) if row else None


def list_users() -> List[User]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
    return [_row_to_user(r) for r in rows]


def update_password(user_id: str, new_password: str, clear_must_change: bool = True):
    if not new_password or len(new_password) < 6:
        raise HTTPException(status_code=400, detail="密码至少 6 位")
    with _db_lock, _conn() as c:
        c.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
            (_hash_password(new_password), 0 if clear_must_change else 1, user_id),
        )
        c.commit()


def delete_user(user_id: str):
    with _db_lock, _conn() as c:
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        c.commit()


def authenticate(username: str, password: str) -> Optional[User]:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return None
    if not _verify_password(password, row["password_hash"]):
        return None
    return _row_to_user(row)


# ===== Session 签名 =====

def _sign(data: bytes) -> str:
    sig = hmac.new(SESSION_SECRET.encode(), data, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def make_session_token(user_id: str) -> str:
    payload = {"uid": user_id, "exp": int(time.time()) + SESSION_TTL_SECONDS}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{body}.{_sign(body.encode())}"


def read_session_token(token: str) -> Optional[str]:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(body.encode())):
        return None
    try:
        pad = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + pad))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload.get("uid")


def set_session_cookie(response: Response, user_id: str, secure: bool = False):
    token = make_session_token(user_id)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def clear_session_cookie(response: Response):
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


# ===== FastAPI 依赖 =====

def get_request_user(request: Request) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    uid = read_session_token(token) if token else None
    if not uid:
        return None
    return get_user(uid)


def require_user(request: Request) -> User:
    user = get_request_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="未登录")
    current_user_ctx.set(user)
    return user


def require_admin(request: Request) -> User:
    user = require_user(request)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


def current_user() -> User:
    u = current_user_ctx.get()
    if not u:
        raise HTTPException(status_code=401, detail="未登录（无用户上下文）")
    return u
