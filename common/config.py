import base64
import os

from dotenv import load_dotenv

# Solo carga .env si HMAC_SECRET no viene ya del entorno (tests/CI)
if not os.getenv("HMAC_SECRET"):
    load_dotenv()
else:
    load_dotenv(override=False)

ENV = os.getenv("ENV", "dev")
DB_URL = os.getenv("DB_URL", "sqlite:///pai.db")


def db_path_from_url(url: str) -> str:
    prefix = "sqlite:///"
    return url[len(prefix) :] if url.startswith(prefix) else url


DB_PATH = db_path_from_url(DB_URL)

_secret = os.getenv("HMAC_SECRET")
if not _secret:
    raise RuntimeError("Falta HMAC_SECRET en .env o en el entorno.")


def _to_key_bytes(v: str) -> bytes:
    # Base64 -> HEX -> UTF-8 (último recurso)
    try:
        return base64.b64decode(v, validate=True)
    except Exception:
        try:
            return bytes.fromhex(v)
        except Exception:
            return v.encode("utf-8")


HMAC_KEY = _to_key_bytes(_secret)
if len(HMAC_KEY) < 32:
    raise RuntimeError("HMAC_SECRET demasiado corta (>= 32 bytes).")
