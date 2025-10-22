# client/main.py
import json
import os
import socket

from common.config import HMAC_KEY
from common.io import recv_line, send_line
from common.protocol import make_message
from common.tls import create_client_context

HOST, PORT = "127.0.0.1", 5050
TLS_SERVER_NAME = os.getenv("TLS_SERVER_NAME", "localhost")


def ask(prompt):
    return input(prompt).strip()


def send_raw_and_print(sock, raw: bytes):
    send_line(sock, raw)
    resp = json.loads(recv_line(sock).decode("utf-8"))
    print(f"> {resp.get('message')}")
    return resp


def send_and_print(sock, msg_type: str, payload: dict):
    raw = make_message(msg_type, payload, HMAC_KEY)
    return send_raw_and_print(sock, raw), raw


def prompt_message_text() -> str | None:
    print("Escribe tu mensaje (máx. 144 caracteres). Deja vacío para cancelar.")
    text = input("> ").rstrip("\n")
    if not text:
        print("> Cancelado.")
        return None
    if len(text) > 144:
        print(f"> Mensaje demasiado largo ({len(text)}). Debe ser ≤ 144.")
        return None
    return text


def main():
    with socket.create_connection((HOST, PORT)) as raw_sock:
        ctx = create_client_context()
        with ctx.wrap_socket(raw_sock, server_hostname=TLS_SERVER_NAME) as s:
            print("Conectado al servidor (TLS).")
            user = None
            last_tx_raw = None

            while True:
                print(
                    "\n[1] Registrar  [2] Login  [3] Logout  [4] Enviar mensaje (≤144)  "
                    "  [0] Salir"
                )
                op = ask("Opción: ")

                if op == "1":
                    u = ask("Usuario: ")
                    p = ask("Contraseña: ")
                    send_and_print(s, "register", {"username": u, "password": p})

                elif op == "2":
                    u = ask("Usuario: ")
                    p = ask("Contraseña: ")
                    (r, _raw) = send_and_print(
                        s, "login", {"username": u, "password": p}
                    )
                    user = u if r.get("ok") else None

                elif op == "3":
                    send_and_print(s, "logout", {})
                    user = None
                    """if not user:
                        print("> Debes hacer login primero")
                        continue
                    src = ask("Cuenta origen: ")
                    dst = ask("Cuenta destino: ")
                    amt = ask("Cantidad: ")
                    (r, raw) = send_and_print(
                        s,
                        "tx",
                        {"username": user, "src": src, "dst": dst, "amount": amt},
                    )
                    last_tx_raw = raw"""

                elif op == "4":
                    if not user:
                        print("> Debes hacer login primero")
                        continue
                    text = prompt_message_text()
                    if text is None:
                        continue
                    send_and_print(s, "message", {"username": user, "text": text})
                    """send_and_print(s, "logout", {})
                    user = None"""
                
                elif op == "0":
                    break

                else:
                    print("Opción no válida.")

                """elif op == "5":
                    if not last_tx_raw:
                        print("> No hay TX previa para reenviar")
                        continue
                    send_raw_and_print(s, last_tx_raw)

                elif op == "6":
                    if not user:
                        print("> Debes hacer login primero")
                        continue
                    text = prompt_message_text()
                    if text is None:
                        continue
                    send_and_print(s, "message", {"username": user, "text": text})"""



if __name__ == "__main__":
    main()
