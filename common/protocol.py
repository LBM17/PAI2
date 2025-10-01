# common/protocol.py
import json

from .crypto import hmac_sha256, new_nonce, now_epoch


def _mac_input(msg_type, payload, nonce, ts):
    # JSON estable (claves ordenadas, sin espacios)
    return json.dumps(
        {"type": msg_type, "payload": payload, "nonce": nonce, "ts": ts},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def make_message(msg_type: str, payload: dict, key: bytes) -> bytes:
    nonce = new_nonce()
    ts = now_epoch()
    mac = hmac_sha256(key, _mac_input(msg_type, payload, nonce, ts))
    envelope = {
        "type": msg_type,
        "payload": payload,
        "nonce": nonce,
        "ts": ts,
        "mac": mac,
    }
    return (json.dumps(envelope) + "\n").encode()


def verify_and_parse(raw_line: bytes, key: bytes) -> dict:
    msg = json.loads(raw_line.decode())
    expected = hmac_sha256(
        key, _mac_input(msg["type"], msg["payload"], msg["nonce"], msg["ts"])
    )
    msg["__mac_ok__"] = expected == msg.get("mac")
    return msg
