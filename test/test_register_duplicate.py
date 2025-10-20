# test/test_register_duplicate.py
import json
import pathlib
import socket
import ssl

import pytest

from common.protocol import make_message

HOST, PORT = "127.0.0.1", 5050
CA_PEM = "certs/ca/ca.pem"


def _tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=CA_PEM)
    return ctx


def _recv_json_line(s: ssl.SSLSocket, timeout=2.0) -> dict:
    s.settimeout(timeout)
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())


@pytest.mark.skipif(not pathlib.Path(CA_PEM).exists(), reason="Faltan certificados")
def test_register_duplicate_rejected(server_proc):
    """
    Usa TLS y la misma clave HMAC del server (fixture server_proc).
    El primer register debe crear (o decir 'ya existe'), el segundo
    debe ser 'duplicado'.
    """
    key = server_proc["key_bytes"]
    ctx = _tls_ctx()

    user = "newuser"  # fijo para forzar duplicado
    pwd = "pw"

    with socket.create_connection((HOST, PORT), timeout=2.0) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            # 1º intento
            raw1 = make_message("register", {"username": user, "password": pwd}, key)
            s.sendall(raw1)
            r1 = _recv_json_line(s)
            # puede ser {'ok': True, ...} o {'ok': False,
            #  'message': 'usuario ya existe'}
            assert "ok" in r1

            # 2º intento (duplicado)
            raw2 = make_message("register", {"username": user, "password": pwd}, key)
            s.sendall(raw2)
            r2 = _recv_json_line(s)
            # aquí sí esperamos rechazo por duplicado
            assert r2.get("ok") is False
            assert "existe" in r2.get("message", "").lower()
