# test/test_message_len_144.py
import importlib
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import time
import uuid

import pytest

HOST = "127.0.0.1"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


class _ServerProc:
    """
    Lanza 'python -m server.main' con puerto elegido y entorno aislado:
    - HMAC_SECRET de prueba
    - DB_URL apuntando a una BD temporal por test
    """

    def __init__(self, port: int):
        self.port = port
        self.env = os.environ.copy()
        self.env["HMAC_SECRET"] = "A" * 64
        self.env["SERVER_HOST"] = HOST
        self.env["SERVER_PORT"] = str(port)

        # ---- BD temporal por test ----
        data_dir = pathlib.Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)
        self.tmp_db = data_dir / f"test_db_{port}.db"
        # URL sqlite:/// con ruta POSIX (para Windows también funciona)
        self.env["DB_URL"] = f"sqlite:///{self.tmp_db.as_posix()}"

        self.cwd = os.getcwd()
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "server.main"],
            cwd=self.cwd,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        # Espera a que el puerto esté abierto
        deadline = time.time() + 12
        last_err = None
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, self.port), timeout=0.25):
                    break
            except OSError as e:
                last_err = e
                time.sleep(0.1)
        else:
            self.__exit__(None, None, None)
            raise RuntimeError(f"El servidor no abrió el puerto a tiempo: {last_err}")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            if self.tmp_db.exists():
                self.tmp_db.unlink()
        except Exception:
            pass
        return False


def _assert_cert_files_exist():
    ca_path = pathlib.Path("certs/ca/ca.pem")
    crt_path = pathlib.Path("certs/server/server.crt")
    key_path = pathlib.Path("certs/server/server.key")
    missing = [str(p) for p in (ca_path, crt_path, key_path) if not p.exists()]
    if missing:
        pytest.skip(
            f"Faltan certificados: {', '.join(missing)}. "
            f"Genera con scripts/gen_certs.ps1 o gen_certs.sh"
        )


def _tls_client_ctx():
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile="certs/ca/ca.pem")
    return ctx


def _load_protocol_and_key():
    """
    Usa el mismo HMAC_SECRET que el server de test y devuelve (proto, HMAC_KEY).
    """
    os.environ["HMAC_SECRET"] = "A" * 64
    import common.config as cfg

    importlib.reload(cfg)
    import common.protocol as proto

    importlib.reload(proto)
    return proto, cfg.HMAC_KEY


def _send(sock, raw_bytes: bytes):
    sock.sendall(raw_bytes)


def _recv_json(sock) -> dict:
    chunks = []
    while True:
        b = sock.recv(1)
        if not b:
            break
        chunks.append(b)
        if b == b"\n":
            break
    line = b"".join(chunks).decode("utf-8")
    return json.loads(line)


def _register_and_login(s, proto, hmac_key: bytes, username: str, password: str):
    # register
    raw = proto.make_message(
        "register", {"username": username, "password": password}, hmac_key
    )
    _send(s, raw)
    reg = _recv_json(s)
    assert reg.get("ok") is True or "ya existe" in (
        reg.get("message") or ""
    ), f"register KO: {reg}"

    # login
    raw = proto.make_message(
        "login", {"username": username, "password": password}, hmac_key
    )
    _send(s, raw)
    resp = _recv_json(s)
    assert resp.get("ok") is True, f"login KO: {resp}"


def test_message_len_ok_144():
    _assert_cert_files_exist()
    port = _free_port()
    with _ServerProc(port):
        proto, hmac_key = _load_protocol_and_key()
        ctx = _tls_client_ctx()

        user = "u_" + uuid.uuid4().hex[:8]
        pwd = "p_" + uuid.uuid4().hex[:8]
        msg144 = "x" * 144

        with socket.create_connection((HOST, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                _register_and_login(s, proto, hmac_key, user, pwd)
                # message OK (144)
                raw_msg = proto.make_message(
                    "message", {"username": user, "text": msg144}, hmac_key
                )
                _send(s, raw_msg)
                resp = _recv_json(s)
                assert resp.get("ok") is True, resp
                assert "Mensaje guardado" in resp.get("message", "")


def test_message_len_too_long_145():
    _assert_cert_files_exist()
    port = _free_port()
    with _ServerProc(port):
        proto, hmac_key = _load_protocol_and_key()
        ctx = _tls_client_ctx()

        user = "u_" + uuid.uuid4().hex[:8]
        pwd = "p_" + uuid.uuid4().hex[:8]
        msg145 = "y" * 145

        with socket.create_connection((HOST, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                _register_and_login(s, proto, hmac_key, user, pwd)
                # message KO (>144)
                raw_msg = proto.make_message(
                    "message", {"username": user, "text": msg145}, hmac_key
                )
                _send(s, raw_msg)
                resp = _recv_json(s)
                assert resp.get("ok") is False, resp
                assert (
                    "144" in resp.get("message", "")
                    or "largo" in resp.get("message", "").lower()
                )
