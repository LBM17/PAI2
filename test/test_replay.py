# test/test_replay.py
import importlib
import json
import os
import pathlib
import socket
import ssl
import uuid

import pytest

HOST, PORT = "127.0.0.1", 5050


def _assert_cert_files_exist():
    ca = pathlib.Path("certs/ca/ca.pem")
    crt = pathlib.Path("certs/server/server.crt")
    key = pathlib.Path("certs/server/server.key")
    missing = [str(p) for p in (ca, crt, key) if not p.exists()]
    if missing:
        pytest.skip(
            f"Faltan certificados: {', '.join(missing)}."
            + "Genera con scripts/gen_certs.ps1/.sh"
        )


def _tls_ctx():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile="certs/ca/ca.pem")
    return ctx


def _recv_json_line(sock) -> dict:
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            break
        buf += b
        if b == b"\n":
            break
    return json.loads(buf.decode("utf-8"))


@pytest.mark.skipif(
    not pathlib.Path("certs/ca/ca.pem").exists(), reason="Faltan certificados"
)
def test_replay_detected(server_proc):
    """
    Requiere que el fixture server_proc arranque el servidor en 127.0.0.1:5050
    y nos proporcione la misma clave HMAC que usa el server.
    """
    _assert_cert_files_exist()

    # Asegura que usamos el MISMO HMAC_SECRET que el server de test
    os.environ["HMAC_SECRET"] = "A" * 64
    import common.config as cfg

    importlib.reload(cfg)
    import common.protocol as proto

    importlib.reload(proto)

    key = cfg.HMAC_KEY
    ctx = _tls_ctx()

    # Usuario aleatorio para garantizar registro+login limpios
    user = "u_" + uuid.uuid4().hex[:8]
    pwd = "p_" + uuid.uuid4().hex[:8]

    # Abre conexión TLS y realiza register + login
    with socket.create_connection((HOST, PORT), timeout=2.0) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            # REGISTER (idempotente)
            raw_reg = proto.make_message(
                "register", {"username": user, "password": pwd}, key
            )
            s.sendall(raw_reg)
            _ = _recv_json_line(s)  # ok o "ya existe"

            # LOGIN (debe ser OK)
            raw_login = proto.make_message(
                "login", {"username": user, "password": pwd}, key
            )
            s.sendall(raw_login)
            resp_login = _recv_json_line(s)
            assert resp_login.get("ok") is True, resp_login

            # 1) TX OK
            tx_payload = {"username": user, "src": "ES00", "dst": "ES11", "amount": 200}
            raw_tx = proto.make_message("tx", tx_payload, key)
            s.sendall(raw_tx)
            resp1 = _recv_json_line(s)
            assert resp1.get("ok") is True, resp1
            # Mensaje del servidor suele contener "transferencia"
            assert "transfer" in resp1.get("message", "").lower()

            # 2) Reenvío literal del MISMO sobre (mismo nonce/mac) -> debe rechazarse
            s.sendall(raw_tx)
            resp2 = _recv_json_line(s)
            assert resp2.get("ok") is False, resp2
            # Mensaje puede variar; aceptamos "replay" o "repetid" (por "repetido")
            assert (
                "replay" in resp2.get("message", "").lower()
                or "repetid" in resp2.get("message", "").lower()
            )
