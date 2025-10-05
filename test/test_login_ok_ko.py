# test/test_login_ok_ko.py
import json
import socket

from common.protocol import make_message

HOST, PORT = "127.0.0.1", 5050


def _send_msg(msg: bytes):
    with socket.create_connection((HOST, PORT), timeout=2.0) as s:
        s.sendall(msg)
        data = b""
        while not data.endswith(b"\n"):
            data += s.recv(4096)
    return json.loads(data.decode())


def test_login_ok_then_rate_limited(server_proc):
    key = server_proc["key_bytes"]

    # Login correcto con usuario seed (alice/alice123)
    r = _send_msg(
        make_message("login", {"username": "alice", "password": "alice123"}, key)
    )
    assert r["ok"] is True
    assert "Login correcto" in r["message"]

    # 5 intentos fallidos
    for _ in range(5):
        r = _send_msg(
            make_message("login", {"username": "alice", "password": "nope"}, key)
        )
        assert r["ok"] is False
        assert "Credenciales inválidas" in r["message"]

    # 6º intento -> debe bloquear por rate limit
    r = _send_msg(make_message("login", {"username": "alice", "password": "nope"}, key))
    assert r["ok"] is False
    assert "Demasiados intentos" in r["message"]

    # Incluso con credenciales correctas inmediato sigue bloqueado
    r = _send_msg(
        make_message("login", {"username": "alice", "password": "alice123"}, key)
    )
    assert r["ok"] is False
    assert "Demasiados intentos" in r["message"]
