from server.persistence import (
    add_user, verify_credentials, nonce_seen, store_nonce, add_tx
)

def resp(ok: bool, message: str, data=None):
    return {"ok": ok, "message": message, "data": (data or {})}

def handle_message(msg: dict):
    # 1) Verificación de MAC (la marca la hace verify_and_parse en server/main)
    if not msg.get("__mac_ok__"):
        return resp(False, "MAC inválido")

    mtype = msg["type"]
    payload = msg["payload"]
    nonce = msg["nonce"]; ts = msg["ts"]; mac = msg["mac"]

    # 2) Anti-replay por NONCE
    if nonce_seen(nonce):
        return resp(False, "Replay detectado: nonce repetido")
    store_nonce(nonce, ts)

    # 3) Routing por tipo de mensaje
    if mtype == "register":
        ok, text = add_user(payload["username"], payload["password"])
        return resp(ok, text)

    if mtype == "login":
        ok = verify_credentials(payload["username"], payload["password"])
        return resp(ok, "Login correcto" if ok else "Credenciales inválidas")

    if mtype == "tx":
        # Sin validar cuentas/cantidades: solo registrar (requisito del PAI)
        add_tx(payload["username"], payload["src"], payload["dst"],
               float(payload["amount"]), nonce, ts, mac)
        return resp(True, "Transferencia con integridad")

    if mtype == "logout":
        return resp(True, "Sesión cerrada")

    return resp(False, f"Tipo de mensaje no soportado: {mtype}")
