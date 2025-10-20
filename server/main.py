# server/main.py
import hashlib
import json
import os
import socket
import ssl
import threading

from dotenv import load_dotenv  # cargar .env antes de importar config

# Asegura variables de entorno antes de evaluar common.config
if not os.getenv("HMAC_SECRET"):
    load_dotenv()
else:
    load_dotenv(override=False)

from common.config import HMAC_KEY
from common.io import recv_line, send_line
from common.protocol import verify_and_parse
from common.tls import create_server_context
from server.handlers import handle_message
from server.logging_setup import get_logger
from server.persistence import has_nonce, init_db, record_nonce, seed_users

log = get_logger("server.main")

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "5050"))


def _replay_token(parsed_msg: dict, raw_line: bytes) -> str:
    """
    Devuelve un token único para detectar reenvíos.
    Preferimos el 'nonce' del protocolo si existe; si no, usamos sha256 del
    sobre recibido.
    """
    nonce = parsed_msg.get("nonce")
    if isinstance(nonce, str) and nonce:
        return "n:" + nonce
    # Fallback robusto: hash del paquete bruto, para capturar replay literal
    return "h:" + hashlib.sha256(raw_line).hexdigest()


def _guard_replay(parsed_msg: dict, raw_line: bytes) -> tuple[bool, dict | None]:
    """
    Devuelve (allow, error_reply). Si allow=False, error_reply es la respuesta a enviar.
    Política: cada token (nonce o hash del sobre) solo puede verse una vez.
    """
    try:
        token = _replay_token(parsed_msg, raw_line)
        if has_nonce(token):
            return False, {
                "ok": False,
                "message": "mensaje repetido (replay detectado)",
            }
        record_nonce(token)
        return True, None
    except Exception as e:
        log.exception("Error validando anti-replay: %s", e)
        return False, {"ok": False, "message": "error interno validando nonce"}


def handle_client(conn: socket.socket, addr):
    client_ip = addr[0]
    log.info("Cliente conectado: %s", addr)
    try:
        while True:
            raw_line = recv_line(conn)  # bytes de una línea \n-terminada
            if not raw_line:
                break
            # 1) Verificación HMAC + parseo (puede no exponer 'nonce';
            # por eso guardamos raw_line)
            msg = verify_and_parse(raw_line, HMAC_KEY)

            # 2) Anti-replay por token (nonce o sha256 del sobre)
            allow, err = _guard_replay(msg, raw_line)
            if not allow:
                send_line(conn, (json.dumps(err) + "\n").encode())
                continue

            # 3) Enrutado de operación
            reply = handle_message(msg, client_ip=client_ip)
            send_line(conn, (json.dumps(reply) + "\n").encode())

    except Exception as e:
        log.exception("Error con %s: %s", addr, e)
    finally:
        conn.close()
        log.info("Cliente desconectado: %s", addr)


def main():
    init_db()
    seed_users()
    log.info("DB OK y usuarios seed listos")
    ctx = create_server_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Estas dos líneas ayudan en carga
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(256)  # backlog más alto

        log.info("Escuchando (TLS) en %s:%s", HOST, PORT)

        while True:
            conn, addr = s.accept()
            try:
                tls_conn = ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, ConnectionAbortedError, OSError) as e:
                # En Windows es común ver 10053/EOF si el cliente cierra pronto
                log.warning("Handshake TLS fallido con %s: %s", addr, e)
                try:
                    conn.close()
                except Exception:
                    pass
                continue

            threading.Thread(
                target=handle_client, args=(tls_conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
