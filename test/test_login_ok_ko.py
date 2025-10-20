# test/test_login_ok_ko.py
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


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


class _ServerProc:
    def __init__(self, port: int):
        self.port = port
        self.env = os.environ.copy()
        self.env["HMAC_SECRET"] = "A" * 64
        self.env["SERVER_HOST"] = HOST
        self.env["SERVER_PORT"] = str(port)
        data_dir = pathlib.Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)
        self.tmp_db = data_dir / f"test_db_{port}.db"
        self.env["DB_URL"] = f"sqlite:///{self.tmp_db.as_posix()}"
        self.cwd = os.getcwd()
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "server.main"],
            cwd=self.cwd,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.time() + 12
        last = None
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, self.port), timeout=0.25):
                    break
            except OSError as e:
                last = e
                time.sleep(0.1)
        else:
            self.__exit__(None, None, None)
            raise RuntimeError(f"Servidor no abrió puerto: {last}")
        return self

    def __exit__(self, *exc):
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


def _ctx():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile="certs/ca/ca.pem")
    return ctx


def _load_proto_key():
    os.environ["HMAC_SECRET"] = "A" * 64
    import common.config as cfg

    importlib.reload(cfg)
    import common.protocol as proto

    importlib.reload(proto)
    return proto, cfg.HMAC_KEY


def _send(sock, raw: bytes):
    sock.sendall(raw)


def _recv_json(sock) -> dict:
    buf = []
    while True:
        b = sock.recv(1)
        if not b:
            break
        buf.append(b)
        if b == b"\n":
            break
    return json.loads(b"".join(buf).decode("utf-8"))


def _register(s, proto, key, u, p):
    _send(s, proto.make_message("register", {"username": u, "password": p}, key))
    return _recv_json(s)


def _login(s, proto, key, u, p):
    _send(s, proto.make_message("login", {"username": u, "password": p}, key))
    return _recv_json(s)


@pytest.mark.skipif(not pathlib.Path("certs/ca/ca.pem").exists(), reason="Faltan certs")
def test_login_ok_and_ko_and_ratelimit():
    port = _free_port()
    with _ServerProc(port):
        proto, key = _load_proto_key()
        ctx = _ctx()
        u = "u_" + uuid.uuid4().hex[:8]
        p = "p_" + uuid.uuid4().hex[:8]

        with socket.create_connection((HOST, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                reg = _register(s, proto, key, u, p)
                assert reg.get("ok") is True or "ya existe" in (
                    reg.get("message") or ""
                )

                ok = _login(s, proto, key, u, p)
                assert ok.get("ok") is True

                bad = _login(s, proto, key, u, "wrong")
                assert bad.get("ok") is False

                # rate-limit (5 intentos/60s) => el 6º debe bloquearse
                for _ in range(4):
                    _ = _login(s, proto, key, u, "wrong")
                rl = _login(s, proto, key, u, "wrong")
                assert rl.get("ok") is False
                assert "demasiados" in (rl.get("message") or "").lower()
