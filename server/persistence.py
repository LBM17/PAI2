# server/persistence.py
from __future__ import annotations

import sqlite3
from typing import List, Optional

import bcrypt

from common.config import DB_PATH

# ---------------------------------------------------------------------------
# Utilidad: conexión por operación (thread-safe para sqlite3 en modo básico)
# ---------------------------------------------------------------------------


def get_conn() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=10.0)  # antes sin timeout explícito
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    con.execute("PRAGMA busy_timeout = 5000;")  # espera hasta 5 s si hay bloqueo
    return con


# ---------------------------------------------------------------------------
# DDL (tablas base de PAI1 + nueva tabla messages para PAI2)
# ---------------------------------------------------------------------------

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_TRANSACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    amount REAL NOT NULL,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);
"""

CREATE_IDX_TX_USER_TS = """
CREATE INDEX IF NOT EXISTS idx_transactions_user_ts
ON transactions(username, ts);
"""

CREATE_NONCES_TABLE = """
CREATE TABLE IF NOT EXISTS nonces_seen (
    nonce TEXT PRIMARY KEY,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

# --- NUEVO: tabla de mensajes con límite de 144 chars ---
CREATE_MESSAGES_TABLE = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    text TEXT NOT NULL CHECK (length(text) <= 144),
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);
"""

CREATE_IDX_MESSAGES_USER_TS = """
CREATE INDEX IF NOT EXISTS idx_messages_user_ts
ON messages(username, ts);
"""


# ---------------------------------------------------------------------------
# Inicialización y datos de ejemplo
# ---------------------------------------------------------------------------


def init_db() -> None:
    con = get_conn()
    try:
        cur = con.cursor()
        # Modo WAL y sincronización razonable para mejorar concurrencia de escrituras
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")

        cur.execute(CREATE_USERS_TABLE)
        cur.execute(CREATE_TRANSACTIONS_TABLE)
        cur.execute(CREATE_IDX_TX_USER_TS)
        cur.execute(CREATE_NONCES_TABLE)

        cur.execute(CREATE_MESSAGES_TABLE)
        cur.execute(CREATE_IDX_MESSAGES_USER_TS)

        con.commit()
    finally:
        con.close()


def seed_users() -> int:
    """
    Inserta 1 usuario demo si la tabla está vacía (idempotente).
    Ajusta o elimina esta función si ya gestionas seeds por otro lado.
    """
    con = get_conn()
    inserted = 0
    try:
        cur = con.cursor()
        total = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if total == 0:
            username = "demo"
            password = "demo"
            pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            inserted = 1
        con.commit()
        return inserted
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Usuarios
# ---------------------------------------------------------------------------


def add_user(username: str, password_plain: str) -> bool:
    """
    Crea un usuario con contraseña hasheada. Devuelve True si se insertó,
    False si ya existía.
    """
    pw_hash = bcrypt.hashpw(password_plain.encode("utf-8"), bcrypt.gensalt())
    con = get_conn()
    try:
        cur = con.cursor()
        # Evita pisar si ya existe
        row = cur.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row:
            return False
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
        con.commit()
        return True
    finally:
        con.close()


def get_user(username: str) -> Optional[sqlite3.Row]:
    con = get_conn()
    try:
        row = con.execute(
            "SELECT username, password_hash, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return row
    finally:
        con.close()


def verify_user_credentials(username: str, password_plain: str) -> bool:
    """
    Verifica credenciales contra bcrypt.
    Tolera password_hash almacenado como BLOB (bytes), TEXT (str) o memoryview.
    Nunca propaga excepciones; devuelve False si algo falla.
    """
    con = get_conn()
    try:
        row = con.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return False

        stored = row["password_hash"]

        # Normalizar a bytes
        try:
            if isinstance(stored, memoryview):
                pw_hash_bytes = stored.tobytes()
            elif isinstance(stored, bytes):
                pw_hash_bytes = stored
            elif isinstance(stored, str):
                pw_hash_bytes = stored.encode("utf-8", "ignore")
            else:
                pw_hash_bytes = bytes(stored)
        except Exception:
            return False

        try:
            return bcrypt.checkpw(password_plain.encode("utf-8"), pw_hash_bytes)
        except Exception:
            return False
    except Exception:
        return False
    finally:
        con.close()


# Aliases de compatibilidad (por si tus handlers usan estos nombres)
register_user = add_user
authenticate_user = verify_user_credentials


# ---------------------------------------------------------------------------
# Nonces (anti-replay)
# ---------------------------------------------------------------------------


def has_nonce(nonce: str) -> bool:
    con = get_conn()
    try:
        row = con.execute(
            "SELECT 1 FROM nonces_seen WHERE nonce = ?", (nonce,)
        ).fetchone()
        return row is not None
    finally:
        con.close()


def record_nonce(nonce: str) -> bool:
    """
    Registra el nonce. Devuelve True si se insertó, False si ya existía.
    """
    con = get_conn()
    try:
        cur = con.cursor()
        try:
            cur.execute(
                "INSERT INTO nonces_seen (nonce) VALUES (?)",
                (nonce,),
            )
            con.commit()
            return True
        except sqlite3.IntegrityError:
            # clave primaria (nonce) duplicada
            return False
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Transacciones (legacy PAI1, las mantenemos para compatibilidad)
# ---------------------------------------------------------------------------


def add_transaction(username: str, src: str, dst: str, amount: float) -> int:
    """
    Inserta una transacción y devuelve su id.
    """
    con = get_conn()
    try:
        cur = con.execute(
            "INSERT INTO transactions (username, src, dst, amount) VALUES (?, ?, ?, ?)",
            (username, src, dst, float(amount)),
        )
        con.commit()
        return int(cur.lastrowid)
    finally:
        con.close()


def list_transactions_by_user(username: str, limit: int = 50) -> List[sqlite3.Row]:
    con = get_conn()
    try:
        cur = con.execute(
            """
            SELECT id, src, dst, amount, ts
            FROM transactions
            WHERE username = ?
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            (username, limit),
        )
        return cur.fetchall()
    finally:
        con.close()


# Alias de compatibilidad (p. ej. si tus handlers llaman save_tx)
save_tx = add_transaction


# ---------------------------------------------------------------------------
# Mensajes (PAI2): ≤144 chars, persistencia y consulta
# ---------------------------------------------------------------------------


def add_message(username: str, text: str) -> int:
    """
    Inserta un mensaje (<=144 chars) para 'username'.
    Lanza ValueError si text es None o supera 144.
    Devuelve el id autoincremental del mensaje.
    """
    if text is None:
        raise ValueError("text no puede ser None")
    if len(text) > 144:
        # Validación en aplicación (además del CHECK de la tabla)
        raise ValueError("message too long (>144)")

    con = get_conn()
    try:
        cur = con.execute(
            "INSERT INTO messages (username, text) VALUES (?, ?)",
            (username, text),
        )
        con.commit()
        return int(cur.lastrowid)
    finally:
        con.close()


def count_messages_by_user(username: str) -> int:
    con = get_conn()
    try:
        row = con.execute(
            "SELECT COUNT(*) AS c FROM messages WHERE username = ?",
            (username,),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        con.close()


def list_messages_by_user(username: str, limit: int = 50) -> List[sqlite3.Row]:
    con = get_conn()
    try:
        cur = con.execute(
            """
            SELECT id, text, ts
            FROM messages
            WHERE username = ?
            ORDER BY ts DESC, id DESC
            LIMIT ?
            """,
            (username, limit),
        )
        return cur.fetchall()
    finally:
        con.close()
