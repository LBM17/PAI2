# common/config.py
import os, base64
from dotenv import load_dotenv

load_dotenv()  # carga .env

ENV = os.getenv("ENV", "dev")
DB_URL = os.getenv("DB_URL", "sqlite:///pai.db")


# extrae ruta sqlite:///fichero.db  ->  fichero.db
def db_path_from_url(url: str) -> str:
    prefix = "sqlite:///"
    return url[len(prefix) :] if url.startswith(prefix) else url


DB_PATH = db_path_from_url(DB_URL)

_secret = os.getenv("HMAC_SECRET")
if not _secret:
    raise RuntimeError("Falta HMAC_SECRET en .env")


def _to_key_bytes(v: str) -> bytes:
    # Primero Base64, luego HEX; último recurso UTF-8
    try:
        return base64.b64decode(v, validate=True)
    except Exception:
        try:
            return bytes.fromhex(v)
        except Exception:
            return v.encode("utf-8")


HMAC_KEY = _to_key_bytes(_secret)
if len(HMAC_KEY) < 32:
    raise RuntimeError("HMAC_SECRET demasiado corta: usa >= 32 bytes (256 bits).")
