# server/handlers.py
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, Optional

from server.logging_setup import get_logger
from server.persistence import (
    add_message,
    add_transaction,
    add_user,
    count_messages_by_user,
    verify_user_credentials,
)

log = get_logger("server.handlers")

# ---------------------------------------------------------------------
# Rate limit de login por IP (sencillo, en memoria)
# ---------------------------------------------------------------------

RATE_LIMIT_LOGIN_ATTEMPTS = 5  # intentos permitidos
RATE_LIMIT_WINDOW_SECONDS = 60  # ventana (s)

# Mapa ip -> deque de timestamps (segundos)
_login_attempts: Dict[str, Deque[float]] = {}


def _allow_login_for(ip: str) -> bool:
    now = time.time()
    dq = _login_attempts.setdefault(ip, deque())
    # purga intentos fuera de ventana
    while dq and now - dq[0] > RATE_LIMIT_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_LOGIN_ATTEMPTS:
        return False
    dq.append(now)
    return True


def _reset_login_window(ip: str) -> None:
    _login_attempts.pop(ip, None)


# ---------------------------------------------------------------------
# Helpers comunes
# ---------------------------------------------------------------------


def _require_fields(payload: dict, fields: tuple[str, ...]) -> Optional[str]:
    """
    Verifica que payload contenga los campos requeridos y que no sean None/"".
    Devuelve mensaje de error o None si está OK.
    """
    for f in fields:
        v = payload.get(f)
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return f"'{f}' requerido"
    return None


# ---------------------------------------------------------------------
# Handlers de operaciones
# ---------------------------------------------------------------------


def handle_register(msg: dict, *, client_ip: Optional[str] = None) -> dict:
    payload = msg.get("payload") or {}
    err = _require_fields(payload, ("username", "password"))
    if err:
        return {"ok": False, "message": err}

    username = payload["username"]
    password = payload["password"]

    try:
        created = add_user(username, password)
    except Exception as e:
        log.exception(
            "Error registrando usuario %s desde %s: %s", username, client_ip, e
        )
        return {"ok": False, "message": "error interno registrando"}

    if not created:
        return {"ok": False, "message": "usuario ya existe"}

    log.info("Usuario %s registrado desde %s", username, client_ip)
    return {"ok": True, "message": "usuario creado"}


def handle_login(msg: dict, *, client_ip: Optional[str] = None) -> dict:
    payload = msg.get("payload") or {}
    err = _require_fields(payload, ("username", "password"))
    if err:
        return {"ok": False, "message": err}

    # Rate limit por IP
    ip = client_ip or "unknown"
    if not _allow_login_for(ip):
        log.warning("Rate limit de login excedido para %s", ip)
        return {"ok": False, "message": "demasiados intentos, inténtalo más tarde"}

    username = payload["username"]
    password = payload["password"]

    try:
        ok = verify_user_credentials(username, password)
    except Exception as e:
        log.exception("Error verificando credenciales de %s: %s", username, e)
        return {"ok": False, "message": "error interno autenticando"}

    if not ok:
        log.info("Login KO para %s desde %s", username, ip)
        return {"ok": False, "message": "credenciales inválidas"}

    # éxito: resetea ventana de rate limit para este ip
    _reset_login_window(ip)
    log.info("Login OK para %s desde %s", username, ip)
    return {"ok": True, "message": "login ok"}


def handle_tx(msg: dict, *, client_ip: Optional[str] = None) -> dict:
    """
    Operación legacy PAI1 (se mantiene por compatibilidad):
    payload = {"username": str, "src": str, "dst": str, "amount": num}
    """
    payload = msg.get("payload") or {}
    err = _require_fields(payload, ("username", "src", "dst", "amount"))
    if err:
        return {"ok": False, "message": err}

    username = payload["username"]
    src = payload["src"]
    dst = payload["dst"]

    try:
        amount = float(payload["amount"])
    except Exception:
        return {"ok": False, "message": "amount debe ser numérico"}

    try:
        tx_id = add_transaction(username, src, dst, amount)
    except Exception as e:
        log.exception("Error insertando tx de %s desde %s: %s", username, client_ip, e)
        return {"ok": False, "message": "error interno persistiendo tx"}

    log.info(
        "TX %s insertada para %s (%s -> %s %.2f) ip=%s",
        tx_id,
        username,
        src,
        dst,
        amount,
        client_ip,
    )
    return {
        "ok": True,
        "message": f"transferencia registrada (id {tx_id})",
        "id": tx_id,
    }


def handle_logout(msg: dict, *, client_ip: Optional[str] = None) -> dict:
    # Si tienes sesión/estado, aquí sería el sitio de invalidarla.
    return {"ok": True, "message": "logout ok"}


# --------------------- NUEVO: MENSAJES ≤144 ----------------------------


def handle_message_send(msg: dict, *, client_ip: Optional[str] = None) -> dict:
    """
    Espera: {"type": "message", "payload": {"username": str, "text": str}}
    Valida longitud ≤144, persiste y devuelve contador por usuario.
    """
    payload = msg.get("payload") or {}
    err = _require_fields(payload, ("username", "text"))
    if err:
        return {"ok": False, "message": err}

    username = payload["username"]
    text = payload["text"]

    if not isinstance(text, str):
        return {"ok": False, "message": "text debe ser string"}
    if len(text) > 144:
        return {"ok": False, "message": "mensaje demasiado largo (>144)"}

    try:
        mid = add_message(username, text)
    except ValueError as e:
        return {"ok": False, "message": f"error de validación: {e}"}
    except Exception as e:
        log.exception(
            "Fallo insertando mensaje de %s desde %s: %s", username, client_ip, e
        )
        return {"ok": False, "message": "error interno persistiendo mensaje"}

    total = 0
    try:
        total = count_messages_by_user(username)
    except Exception:
        pass

    log.info(
        "Mensaje %s insertado para %s (total=%s) ip=%s", mid, username, total, client_ip
    )
    return {"ok": True, "message": f"Mensaje guardado (total {total}).", "id": mid}


# ---------------------------------------------------------------------
# Dispatcher principal
# ---------------------------------------------------------------------


def handle_message(msg: dict, *, client_ip: Optional[str] = None) -> dict:
    """
    Enruta por msg['type'] y delega en el handler correspondiente.
    """
    t = (msg.get("type") or "").lower()

    if t == "register":
        return handle_register(msg, client_ip=client_ip)

    elif t == "login":
        return handle_login(msg, client_ip=client_ip)

    elif t == "tx":
        return handle_tx(msg, client_ip=client_ip)

    elif t == "logout":
        return handle_logout(msg, client_ip=client_ip)

    elif t == "message":
        return handle_message_send(msg, client_ip=client_ip)

    else:
        return {"ok": False, "message": f"tipo desconocido: {t}"}
