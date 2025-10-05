# server/main.py
import json
import os
import socket
import threading
from common.config import HMAC_KEY
from common.io import recv_line, send_line
from common.protocol import verify_and_parse
from server.handlers import handle_message
from server.logging_setup import get_logger
from server.persistence import init_db, seed_users

log = get_logger("server.main")

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "5050"))


def handle_client(conn: socket.socket, addr):
    client_ip = addr[0]
    log.info("Cliente conectado: %s", addr)
    try:
        while True:
            line = recv_line(conn)
            if not line:
                break
            msg = verify_and_parse(line, HMAC_KEY)
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log.info("Escuchando en %s:%s", HOST, PORT)
        while True:
            conn, addr = s.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
