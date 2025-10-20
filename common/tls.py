# common/tls.py
import os
import ssl


def _get(path_env: str, default: str) -> str:
    return os.getenv(path_env, default)


CERT_FILE = _get("CERT_FILE", "certs/server/server.crt")
KEY_FILE = _get("KEY_FILE", "certs/server/server.key")
CA_FILE = _get("CA_FILE", "certs/ca/ca.pem")


def create_server_context() -> ssl.SSLContext:
    """SSLContext para el servidor (TLS 1.3 mínimo)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    # Mitiga CRIME/BREACH (no comprimir TLS)
    ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


def create_client_context() -> ssl.SSLContext:
    """SSLContext para el cliente (verifica con nuestra CA)."""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Cargamos la CA local; si no existe, lanzará excepción clara en el handshake
    ctx.load_verify_locations(cafile=CA_FILE)
    return ctx
