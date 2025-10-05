import hashlib
import secrets
import sqlite3
import time
from typing import Tuple

import bcrypt  # <-- NUEVO

from common.config import DB_PATH
from common.crypto import secure_compare

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY,
  salt     TEXT NOT NULL,
  pwd_hash TEXT NOT NULL,
  created  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  amount REAL NOT NULL,
  nonce TEXT NOT NULL,
  ts INTEGER NOT NULL,
  mac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces_seen(
  nonce TEXT PRIMARY KEY,
  ts INTEGER NOT NULL
);
"""


def conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    c = conn()
    with c:
        c.executescript(SCHEMA)
    c.close()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_password_sha256(plain: str, salt_hex: str) -> str:
    return _sha256_hex(bytes.fromhex(salt_hex) + plain.encode())


def hash_password_bcrypt(plain: str) -> str:
    # cost por defecto (~12). Ajusta si quieres.
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode("utf-8")


def _is_bcrypt(ph: str) -> bool:
    return ph.startswith("$2a$") or ph.startswith("$2b$") or ph.startswith("$2y$")


def seed_users():
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    (n,) = cur.fetchone()
    if n == 0:
        for uname, pwd in [("alice", "alice123"), ("bob", "bob123")]:
            # Usuarios seed YA en bcrypt
            salt = secrets.token_hex(16)
            pwd_hash = hash_password_bcrypt(pwd)
            cur.execute(
                "INSERT INTO users(username,salt,pwd_hash,created) VALUES (?,?,?,?)",
                (uname, salt, pwd_hash, int(time.time())),
            )
        c.commit()
    c.close()


def add_user(username: str, plain_password: str) -> Tuple[bool, str]:
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
    if cur.fetchone():
        c.close()
        return False, "Usuario ya existe"
    salt = secrets.token_hex(16)
    pwd_hash = hash_password_bcrypt(plain_password)  # <-- NUEVO por defecto
    with c:
        cur.execute(
            "INSERT INTO users(username,salt,pwd_hash,created) VALUES (?,?,?,?)",
            (username, salt, pwd_hash, int(time.time())),
        )
    c.close()
    return True, "Usuario registrado"


def verify_credentials(username: str, plain_password: str) -> bool:
    """Compat: acepta usuarios viejos (sha256+salt) y nuevos (bcrypt).
    Si valida con sha256, auto-migra a bcrypt."""
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT salt, pwd_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        c.close()
        return False
    salt, stored = row

    if _is_bcrypt(stored):
        ok = bcrypt.checkpw(plain_password.encode(), stored.encode("utf-8"))
        c.close()
        return ok

    # Legacy SHA-256 + salt (compat)
    calc = hash_password_sha256(plain_password, salt)
    ok = secure_compare(calc, stored)

    if ok:
        # auto-upgrade a bcrypt
        new_hash = hash_password_bcrypt(plain_password)
        with c:
            cur.execute(
                "UPDATE users SET pwd_hash=? WHERE username=?", (new_hash, username)
            )
    c.close()
    return ok


def nonce_seen(nonce: str) -> bool:
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT 1 FROM nonces_seen WHERE nonce=?", (nonce,))
    ok = cur.fetchone() is not None
    c.close()
    return ok


def store_nonce(nonce: str, ts: int):
    c = conn()
    with c:
        c.execute(
            "INSERT OR IGNORE INTO nonces_seen(nonce,ts) VALUES (?,?)", (nonce, ts)
        )
    c.close()


def add_tx(
    username: str, src: str, dst: str, amount: float, nonce: str, ts: int, mac: str
):
    c = conn()
    with c:
        c.execute(
            """INSERT INTO transactions(username,src,dst,amount,nonce,ts,mac)
               VALUES (?,?,?,?,?,?,?)""",
            (username, src, dst, amount, nonce, ts, mac),
        )
    c.close()
