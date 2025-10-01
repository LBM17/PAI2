# common/crypto.py
import hmac, hashlib, secrets, time

def hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)

def new_nonce(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)  # 128 bits

def now_epoch() -> int:
    return int(time.time())
