# test/test_register_duplicate.py
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


def test_register_duplicate_rejected(server_proc):
    key = server_proc["key_bytes"]

    r1 = _send_msg(
        make_message("register", {"username": "newuser", "password": "pw"}, key)
    )
    assert r1["ok"] is True

    r2 = _send_msg(
        make_message("register", {"username": "newuser", "password": "pw"}, key)
    )
    assert r2["ok"] is False
    assert "Usuario ya existe" in r2["message"]
