import json
import socket
import threading

from common.config import ENV, HMAC_KEY
from common.io import recv_line, send_line
from common.protocol import verify_and_parse
from server.handlers import handle_message
from server.persistence import init_db, seed_users

HOST, PORT = "127.0.0.1", 5050  # puedes moverlo a .env si quieres


def handle_client(conn: socket.socket, addr):
    try:
        while True:
            line = recv_line(conn)
            if not line:
                break
            # Verifica MAC y parsea
            msg = verify_and_parse(line, HMAC_KEY)
            reply = handle_message(msg)
            send_line(conn, (json.dumps(reply) + "\n").encode())
    except Exception as e:
        if ENV == "dev":
            print(f"[server] error con {addr}: {e}")
    finally:
        conn.close()


def main():
    init_db()
    seed_users()
    print("[server] DB ok y usuarios seed cargados")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            print(f"[server] cliente conectado: {addr}")
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    main()
