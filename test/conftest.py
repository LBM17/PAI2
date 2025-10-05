# test/conftest.py
# --- añadir la raíz del repo al sys.path ---
import os
import sys

SYS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SYS_ROOT not in sys.path:
    sys.path.insert(0, SYS_ROOT)
# -------------------------------------------

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HOST, PORT = "127.0.0.1", 5050


def _wait_port(host, port, timeout=5.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Servidor no escuchando en {host}:{port} tras {timeout}s")


def _send_recv_raw(raw: bytes) -> dict:
    with socket.create_connection((HOST, PORT), timeout=2.0) as s:
        s.sendall(raw)
        # lee hasta \n
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode())


def pytest_generate_tests(metafunc):
    # nada
    return


import pytest


@pytest.fixture(scope="function")
def server_proc():
    # Genera HMAC de 32 bytes (Base64) y DB temporal para este test
    key_bytes = os.urandom(32)
    key_b64 = base64.b64encode(key_bytes).decode()
    db_fd, db_path = tempfile.mkstemp(prefix="pytest_pai_", suffix=".db")
    os.close(db_fd)  # lo usará sqlite

    env = os.environ.copy()
    env["ENV"] = "dev"
    env["HMAC_SECRET"] = key_b64
    env["DB_URL"] = f"sqlite:///{db_path}"

    # Lanza el server: python -m server.main
    proc = subprocess.Popen([sys.executable, "-m", "server.main"], env=env)
    try:
        _wait_port(HOST, PORT, timeout=7.0)
    except Exception:
        proc.terminate()
        raise

    yield {
        "key_bytes": key_bytes,
        "db_path": db_path,
        "env": env,
        "send_recv_raw": _send_recv_raw,
    }

    # Teardown
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    try:
        os.remove(db_path)
    except OSError:
        pass
