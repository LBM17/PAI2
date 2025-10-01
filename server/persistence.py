import sqlite3, hashlib
from typing import Tuple
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


def hash_password(plain: str, salt_hex: str) -> str:
    return _sha256_hex(bytes.fromhex(salt_hex) + plain.encode())


def seed_users():
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    (n,) = cur.fetchone()
    if n == 0:
        import secrets, time

        for uname, pwd in [("alice", "alice123"), ("bob", "bob123")]:
            salt = secrets.token_hex(16)
            pwd_hash = hash_password(pwd, salt)
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
    import secrets, time

    salt = secrets.token_hex(16)
    pwd_hash = hash_password(plain_password, salt)
    with c:
        cur.execute(
            "INSERT INTO users(username,salt,pwd_hash,created) VALUES (?,?,?,?)",
            (username, salt, pwd_hash, int(time.time())),
        )
    c.close()
    return True, "Usuario registrado"


def verify_credentials(username: str, plain_password: str) -> bool:
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT salt, pwd_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    c.close()
    if not row:
        return False
    salt, stored = row
    calc = hash_password(plain_password, salt)
    return secure_compare(calc, stored)


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
