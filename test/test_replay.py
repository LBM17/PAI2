# test/test_replay.py
import json
import socket

from common.protocol import make_message

HOST, PORT = "127.0.0.1", 5050


def _send_raw(raw: bytes):
    with socket.create_connection((HOST, PORT), timeout=2.0) as s:
        s.sendall(raw)
        data = b""
        while not data.endswith(b"\n"):
            data += s.recv(4096)
    return json.loads(data.decode())


def test_replay_detected(server_proc):
    key = server_proc["key_bytes"]

    # Login OK para usar username en la TX (nuestro server no usa token de sesión)
    _ = _send_raw(
        make_message("login", {"username": "alice", "password": "alice123"}, key)
    )

    # Enviar TX y volver a enviar el MISMO sobre (mismo nonce/mac)
    raw_tx = make_message(
        "tx", {"username": "alice", "src": "23249", "dst": "67856", "amount": 200}, key
    )
    r1 = _send_raw(raw_tx)
    assert r1["ok"] is True
    assert "Transferencia con integridad" in r1["message"]

    r2 = _send_raw(raw_tx)  # replay exacto
    assert r2["ok"] is False
    assert "Replay detectado" in r2["message"]
