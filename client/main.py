import socket, json
from common.config import HMAC_KEY
from common.io import send_line, recv_line
from common.protocol import make_message

HOST, PORT = "127.0.0.1", 5050

def ask(prompt): return input(prompt).strip()

def send_raw_and_print(sock, raw):
    send_line(sock, raw)
    resp = json.loads(recv_line(sock).decode())
    print(f"> {resp['message']}")
    return resp

def send_and_print(sock, msg_type, payload):
    raw = make_message(msg_type, payload, HMAC_KEY)
    return send_raw_and_print(sock, raw), raw  # devolvemos resp y raw

def main():
    with socket.create_connection((HOST, PORT)) as s:
        print("Conectado al servidor.")
        user = None
        last_tx_raw = None  # <-- guardaremos aquí la última TX

        while True:
            print("\n[1] Registrar  [2] Login  [3] Transferir  [4] Logout  [5] Reenviar última TX (replay)  [0] Salir")
            op = ask("Opción: ")
            if op == "1":
                u = ask("Usuario: "); p = ask("Contraseña: ")
                send_and_print(s, "register", {"username": u, "password": p})
            elif op == "2":
                u = ask("Usuario: "); p = ask("Contraseña: ")
                (r, _raw) = send_and_print(s, "login", {"username": u, "password": p})
                user = u if r.get("ok") else None
            elif op == "3":
                if not user:
                    print("> Debes hacer login primero"); continue
                src = ask("Cuenta origen: "); dst = ask("Cuenta destino: "); amt = ask("Cantidad: ")
                (r, raw) = send_and_print(s, "tx", {"username": user, "src": src, "dst": dst, "amount": amt})
                last_tx_raw = raw  # <-- guardamos el sobre EXACTO que se envió
            elif op == "4":
                send_and_print(s, "logout", {}); user = None
            elif op == "5":
                if not last_tx_raw:
                    print("> No hay TX previa para reenviar"); continue
                send_raw_and_print(s, last_tx_raw)  # <-- reenvía MISMO nonce/mac
            elif op == "0":
                break
            else:
                print("Opción no válida.")

if __name__ == "__main__":
    main()
