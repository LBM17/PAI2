# common/config.py
import base64
import os

from dotenv import load_dotenv

# Solo cargar .env si NO está ya HMAC_SECRET en el entorno (p. ej., cuando pytest la inyecta)
if not os.getenv("HMAC_SECRET"):
    load_dotenv()  # no pisa variables de entorno
else:
    load_dotenv(override=False)  # inofensivo

ENV = os.getenv("ENV", "dev")
DB_URL = os.getenv("DB_URL", "sqlite:///pai.db")


def db_path_from_url(url: str) -> str:
    prefix = "sqlite:///"
    return url[len(prefix) :] if url.startswith(prefix) else url


DB_PATH = db_path_from_url(DB_URL)

_secret = os.getenv("HMAC_SECRET")
if not _secret:
    raise RuntimeError("Falta HMAC_SECRET en .env o en el entorno")


def _to_key_bytes(v: str) -> bytes:
    import binascii

    try:
        return base64.b64decode(v, validate=True)
    except Exception:
        try:
            return bytes.fromhex(v)
        except Exception:
            # último recurso (no recomendado)
            return v.encode("utf-8")


HMAC_KEY = _to_key_bytes(_secret)
if len(HMAC_KEY) < 32:
    raise RuntimeError("HMAC_SECRET demasiado corta: usa >= 32 bytes (256 bits).")
