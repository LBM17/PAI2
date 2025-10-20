# common/config.py
import base64
import binascii
import hashlib
import os
from pathlib import Path

from dotenv import load_dotenv

# Cargar .env lo antes posible (sin pisar variables ya presentes)
if not os.getenv("HMAC_SECRET"):
    load_dotenv()
else:
    load_dotenv(override=False)

# -------------------------------------------------
# Entorno / Base de datos
# -------------------------------------------------
ENV = os.getenv("ENV", "dev")

# Por defecto, base en ./data/pai2.db
DEFAULT_DB_URL = "sqlite:///data/pai2.db"
DB_URL = os.getenv("DB_URL", DEFAULT_DB_URL)


def db_path_from_url(url: str) -> str:
    prefix = "sqlite:///"
    return url[len(prefix) :] if url.startswith(prefix) else url


# Si el usuario define DB_PATH en .env, tiene prioridad.
DB_PATH = os.getenv("DB_PATH") or db_path_from_url(DB_URL)

# Normaliza la ruta y crea la carpeta si hace falta (para SQLite local)
DB_PATH = str(Path(DB_PATH))
db_dir = Path(DB_PATH).parent
if str(db_dir) not in ("", "."):
    db_dir.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------
# HMAC: obtener secreto y derivar clave robusta
#   - Acepta HEX, Base64 o texto
#   - Deriva HMAC_KEY = SHA256(secret_bytes)  (32 bytes)
# -------------------------------------------------
def _get_hmac_secret() -> str:
    s = os.getenv("HMAC_SECRET", "").strip()
    if not s:
        raise RuntimeError("Falta HMAC_SECRET en .env o en el entorno.")
    return s


def _secret_to_bytes(secret: str) -> bytes:
    s = secret.strip()
    # 1) Intentar HEX primero (evita que 'AAAA...' sea base64 de ceros)
    try:
        return bytes.fromhex(s)
    except ValueError:
        pass
    # 2) Intentar Base64 (validación estricta)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        pass
    # 3) Texto plano (UTF-8)
    return s.encode("utf-8")


_HMAC_SECRET = _get_hmac_secret()
_HMAC_SECRET_BYTES = _secret_to_bytes(_HMAC_SECRET)

# Clave binaria estable de 32 bytes
HMAC_KEY = hashlib.sha256(_HMAC_SECRET_BYTES).digest()
