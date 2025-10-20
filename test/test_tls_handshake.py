# test/test_tls_handshake.py
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import time

import pytest

HOST = "127.0.0.1"


def _free_port() -> int:
    """Reserva un puerto libre del SO y lo devuelve."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


class _ServerProc:
    """
    Lanza 'python -m server.main' como subproceso con un puerto elegido
    y HMAC_SECRET temporal. No depende de conftest ni de .env.
    """

    def __init__(self, port: int):
        self.port = port
        self.env = os.environ.copy()
        # Asegura variables mínimas para que arranque sin .env
        self.env.setdefault("HMAC_SECRET", "A" * 64)
        self.env["SERVER_HOST"] = HOST
        self.env["SERVER_PORT"] = str(port)
        self.cwd = os.getcwd()
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        # No capturamos stdout/stderr para evitar bloqueos por buffer
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "server.main"],
            cwd=self.cwd,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Espera a que el puerto esté abierto
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, self.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            # Si no abrió el puerto, cerramos y fallamos
            self.__exit__(None, None, None)
            raise RuntimeError("El servidor no abrió el puerto a tiempo.")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
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


def test_tls_handshake_ok():
    _assert_cert_files_exist()
    port = _free_port()
    with _ServerProc(port):
        # Contexto del cliente con verificación de CA (TLS 1.3)
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile="certs/ca/ca.pem")

        # Handshake exitoso si conseguimos envolver el socket sin excepción
        with socket.create_connection((HOST, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                # Verificaciones mínimas de que hubo handshake real
                assert s.version() == "TLSv1.3"
                assert s.getpeercert() is not None
                # No llamamos a s.unwrap(): muchos servidores no envían close_notify
                # Salimos del with y cerramos sin exigir cierre ordenado a nivel TLS


def test_tls_handshake_fails_without_trusted_ca():
    _assert_cert_files_exist()
    port = _free_port()
    with _ServerProc(port):
        # Contexto "limpio": NO cargamos nuestra CA
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((HOST, port), timeout=2) as raw:
            with pytest.raises((ssl.SSLCertVerificationError, ssl.SSLError)):
                ctx.wrap_socket(raw, server_hostname="localhost")


def test_tls_hostname_mismatch():
    _assert_cert_files_exist()
    port = _free_port()
    with _ServerProc(port):
        # Confiamos en la CA pero forzamos SNI distinto al CN/SAN
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile="certs/ca/ca.pem")

        with socket.create_connection((HOST, port), timeout=2) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                ctx.wrap_socket(raw, server_hostname="not-localhost")
