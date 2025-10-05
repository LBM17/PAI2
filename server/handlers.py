from server.logging_setup import get_logger
from server.persistence import (
    add_tx,
    add_user,
    nonce_seen,
    store_nonce,
    verify_credentials,
)
from server.rate_limit import RateLimiter, Rule

log = get_logger("server.handlers")
_login_rl = RateLimiter(Rule(max_attempts=5, window_seconds=300, cooldown_seconds=300))


def resp(ok: bool, message: str, data=None):
    return {"ok": ok, "message": message, "data": (data or {})}


def handle_message(msg: dict, client_ip: str | None = None):
    if not msg.get("__mac_ok__"):
        log.warning("MAC inválido (ip=%s, type=%s)", client_ip, msg.get("type"))
        return resp(False, "MAC inválido")

    mtype = msg["type"]
    payload = msg["payload"]
    nonce = msg["nonce"]
    ts = msg["ts"]
    mac = msg["mac"]

    if nonce_seen(nonce):
        log.warning("Replay detectado (ip=%s, nonce=%s)", client_ip, nonce)
        return resp(False, "Replay detectado: nonce repetido")
    store_nonce(nonce, ts)

    if mtype == "register":
        ok, text = add_user(payload["username"], payload["password"])
        log.info(
            "Register %s: %s (ip=%s)",
            payload["username"],
            "OK" if ok else "YA EXISTE",
            client_ip,
        )
        return resp(ok, text)

    if mtype == "login":
        username = payload["username"]
        allow_user, wait_u = _login_rl.register_attempt(f"user:{username}")
        if not allow_user:
            log.warning(
                "RL usuario: %s bloqueado %ss (ip=%s)", username, wait_u, client_ip
            )
            return resp(
                False, f"Demasiados intentos para {username}. Espera {wait_u}s."
            )
        if client_ip:
            allow_ip, wait_ip = _login_rl.register_attempt(f"ip:{client_ip}")
            if not allow_ip:
                log.warning(
                    "RL IP: %s bloqueada %ss (user=%s)", client_ip, wait_ip, username
                )
                return resp(
                    False, f"Demasiados intentos desde {client_ip}. Espera {wait_ip}s."
                )

        ok = verify_credentials(username, payload["password"])
        if ok:
            _login_rl.reset_success(f"user:{username}")
            if client_ip:
                _login_rl.reset_success(f"ip:{client_ip}")
            log.info("Login OK (user=%s, ip=%s)", username, client_ip)
            return resp(True, "Login correcto")
        else:
            log.info("Login KO (user=%s, ip=%s)", username, client_ip)
            return resp(False, "Credenciales inválidas")

    if mtype == "tx":
        add_tx(
            payload["username"],
            payload["src"],
            payload["dst"],
            float(payload["amount"]),
            nonce,
            ts,
            mac,
        )
        log.info(
            "TX OK (user=%s src=%s dst=%s amt=%s ip=%s)",
            payload.get("username"),
            payload.get("src"),
            payload.get("dst"),
            payload.get("amount"),
            client_ip,
        )
        return resp(True, "Transferencia con integridad")

    if mtype == "logout":
        log.info("Logout (user=%s, ip=%s)", payload.get("username"), client_ip)
        return resp(True, "Sesión cerrada")

    log.warning("Tipo no soportado: %s (ip=%s)", mtype, client_ip)
    return resp(False, f"Tipo de mensaje no soportado: {mtype}")
