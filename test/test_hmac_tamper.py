# test/test_hmac_tamper.py
import json

from common.protocol import make_message, verify_and_parse


def test_hmac_tamper_detected():
    key = b"x" * 32
    ok_raw = make_message("ping", {"x": 1}, key)
    ok = verify_and_parse(ok_raw, key)
    assert ok["__mac_ok__"] is True

    # Parseamos el sobre, cambiamos el payload, pero mantenemos el 'mac' original
    msg = json.loads(ok_raw.decode())
    msg["payload"]["x"] = 2  # alteración real del contenido
    tampered_raw = (
        json.dumps(msg, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()

    bad = verify_and_parse(tampered_raw, key)
    assert bad["__mac_ok__"] is False
