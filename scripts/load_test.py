# scripts/load_test.py
import argparse
import json
import os
import socket
import ssl
import statistics
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common.config import HMAC_KEY
from common.protocol import make_message
from common.tls import create_client_context


def _recv_json_line(sock) -> dict:
    """Lee una línea JSON terminada en \n y la decodifica."""
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            # conexión cerrada sin \n -> error de protocolo
            raise TimeoutError("socket closed before newline")
        buf += b
        if b == b"\n":
            break
    return json.loads(buf.decode("utf-8"))


def _rpc(sock: ssl.SSLSocket, msg_type: str, payload: dict) -> dict:
    """Envía un mensaje HMAC y devuelve la respuesta JSON."""
    raw = make_message(msg_type, payload, HMAC_KEY)
    sock.sendall(raw)
    return _recv_json_line(sock)


def _preflight(host: str, port: int, tls_name: str, timeout: float = 3.0) -> None:
    """Comprueba que podemos hacer handshake TLS con el servidor."""
    print(f"[i] Preflight TLS a {host}:{port} (SNI={tls_name}) ...", flush=True)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        ctx = create_client_context()
        with ctx.wrap_socket(raw, server_hostname=tls_name) as s:
            s.settimeout(timeout)
            # no enviamos datos, solo handshake
            pass
    print("[i] Preflight OK", flush=True)


def _worker(
    i: int,
    host: str,
    port: int,
    tls_name: str,
    msgs_per_user: int,
    start_delay_ms: int,
    timeout: float,
) -> dict:
    """
    Un "usuario": register -> login -> enviar N mensajes.
    Devuelve {"ok": True, "lat": [latencias_sec...]} o {"ok": False, "err": "..."}.
    """
    # Escalonado para evitar picos simultáneos de login
    if start_delay_ms > 0:
        time.sleep(start_delay_ms / 1000.0)

    u = f"u_{i}_{uuid.uuid4().hex[:6]}"
    p = "p_" + uuid.uuid4().hex[:6]
    lats = []

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            ctx = create_client_context()
            with ctx.wrap_socket(raw, server_hostname=tls_name) as s:
                s.settimeout(timeout)

                t = time.perf_counter()
                _ = _rpc(s, "register", {"username": u, "password": p})
                lats.append(time.perf_counter() - t)

                t = time.perf_counter()
                r_login = _rpc(s, "login", {"username": u, "password": p})
                lats.append(time.perf_counter() - t)
                if not r_login.get("ok"):
                    return {"ok": False, "err": f"login: {r_login}"}

                for k in range(msgs_per_user):
                    t = time.perf_counter()
                    r = _rpc(s, "message", {"username": u, "text": f"hola {k}"})
                    lats.append(time.perf_counter() - t)
                    if not r.get("ok"):
                        return {"ok": False, "err": f"message: {r}"}

    except Exception as e:
        # devolvemos clase y texto del error para el resumen
        return {"ok": False, "err": f"{type(e).__name__}: {e}"}

    return {"ok": True, "lat": lats}


def main():
    print("[i] Iniciando load_test...", flush=True)

    ap = argparse.ArgumentParser(description="PAI2 load test (TLS + HMAC)")
    ap.add_argument("--host", default=os.getenv("SERVER_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.getenv("SERVER_PORT", "5050")))
    ap.add_argument("--tls-name", default=os.getenv("TLS_SERVER_NAME", "localhost"))
    ap.add_argument(
        "--users", type=int, default=100, help="número de usuarios simulados"
    )
    ap.add_argument("--msgs", type=int, default=3, help="mensajes por usuario")
    ap.add_argument(
        "--workers", type=int, default=50, help="hilos concurrentes máximos"
    )
    ap.add_argument(
        "--ramp-ms", type=int, default=0, help="retraso incremental por usuario (ms)"
    )
    ap.add_argument(
        "--timeout", type=float, default=3.0, help="timeout de socket (segundos)"
    )
    ap.add_argument(
        "--out", default="", help="guardar resumen en logs/OUT.json (opcional)"
    )
    args = ap.parse_args()

    print(
        f"[i] Target: {args.host}:{args.port}  tls_name={args.tls_name}",
        flush=True,
    )
    print(
        f"[i] Plan: users={args.users}, msgs_per_user={args.msgs}, "
        f"workers={args.workers}, ramp_ms={args.ramp_ms}, timeout={args.timeout}s",
        flush=True,
    )

    try:
        _preflight(args.host, args.port, args.tls_name, timeout=args.timeout)
    except Exception:
        print("[x] Preflight falló:")
        traceback.print_exc()
        return

    t0 = time.perf_counter()
    oks, kos, done = [], [], 0

    # Lanzamos los usuarios con ThreadPool + ramp-up
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = []
        for i in range(args.users):
            start_delay_ms = i * args.ramp_ms
            futs.append(
                ex.submit(
                    _worker,
                    i,
                    args.host,
                    args.port,
                    args.tls_name,
                    args.msgs,
                    start_delay_ms,
                    args.timeout,
                )
            )

        step = max(1, args.users // 10)
        for f in as_completed(futs):
            res = f.result()
            (oks if res.get("ok") else kos).append(res)
            done += 1
            if done % step == 0 or done == args.users:
                print(f"[.] Progreso: {done}/{args.users}", flush=True)

    wall = time.perf_counter() - t0
    all_lat = [x for r in oks for x in r["lat"]]

    p50_ms = p95_ms = None
    if all_lat:
        try:
            p50_ms = round(statistics.median(all_lat) * 1000, 1)
            if len(all_lat) >= 20:
                p95 = statistics.quantiles(all_lat, n=20)[18]  # ~95%
                p95_ms = round(p95 * 1000, 1)
            else:
                p95_ms = p50_ms
        except Exception:
            pass

    print("\n=== RESUMEN ===")
    print(f"ok={len(oks)}  ko={len(kos)}  total={args.users}")
    print(f"duración total={wall:.2f}s")
    if p50_ms is not None:
        print(f"latencia p50={p50_ms} ms  p95={p95_ms} ms")
    if kos:
        sample = kos[:5]
        print(f"errores (muestra {len(sample)}/{len(kos)}):")
        for e in sample:
            print("  -", e.get("err"))

    if args.out:
        Path("logs").mkdir(exist_ok=True)
        out_path = Path("logs") / args.out
        payload = {
            "plan": {
                "host": args.host,
                "port": args.port,
                "tls_name": args.tls_name,
                "users": args.users,
                "msgs": args.msgs,
                "workers": args.workers,
                "ramp_ms": args.ramp_ms,
                "timeout": args.timeout,
            },
            "summary": {
                "ok": len(oks),
                "ko": len(kos),
                "users": args.users,
                "wall_sec": round(wall, 3),
                "lat_p50_ms": p50_ms,
                "lat_p95_ms": p95_ms,
            },
            "errors": [e.get("err") for e in kos],
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[i] Guardado: {out_path}")


if __name__ == "__main__":
    main()
