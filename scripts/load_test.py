# scripts/load_test.py
from __future__ import annotations

import argparse
import json
import queue
import random
import socket
import ssl
import string
import threading
import time
from statistics import median
from typing import Dict, List, Tuple

HOST = "127.0.0.1"
PORT = 5050
SNI = "localhost"
CAFILE = "certs/ca/ca.pem"


# -----------------------------
# TLS y protocolo (import-safe)
# -----------------------------
def _tls_ctx(timeout: float) -> ssl.SSLContext:
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=CAFILE)
    # el timeout se aplica al socket; el contexto no lo usa
    return ctx


def _proto_and_key():
    """
    Importa perezosamente common.protocol y common.config solo cuando se necesitan.
    Evita romper la importación del módulo en CI si pytest inspecciona scripts/.
    """
    import importlib

    proto = importlib.import_module("common.protocol")
    cfg = importlib.import_module("common.config")
    return proto, cfg.HMAC_KEY


# -----------------------------
# Utilidades
# -----------------------------
def _rand_user(i: int) -> Tuple[str, str]:
    suffix = "".join(random.choices(string.hexdigits.lower(), k=6))
    return (f"u_{i}_{suffix}", f"p_{suffix}")


def _recv_json_line(s: ssl.SSLSocket, timeout: float) -> Dict:
    s.settimeout(timeout)
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode() or "{}")


def _preflight(host: str, port: int, timeout: float) -> None:
    ctx = _tls_ctx(timeout)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=SNI):
            pass


# -----------------------------
# Worker
# -----------------------------
def _worker(
    q: "queue.Queue[Tuple[int, int]]",
    results: List[Tuple[bool, float, str]],
    timeout: float,
    msgs_per_user: int,
    lock: threading.Lock,
):
    proto, key = _proto_and_key()
    ctx = _tls_ctx(timeout)

    while True:
        try:
            i, _ = q.get_nowait()
        except queue.Empty:
            return

        user, pwd = _rand_user(i)
        t0 = time.perf_counter()
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=SNI) as s:
                    # register (idempotente)
                    s.sendall(
                        proto.make_message(
                            "register", {"username": user, "password": pwd}, key
                        )
                    )
                    _ = _recv_json_line(s, timeout)

                    # login
                    s.sendall(
                        proto.make_message(
                            "login", {"username": user, "password": pwd}, key
                        )
                    )
                    rlogin = _recv_json_line(s, timeout)
                    if not rlogin.get("ok"):
                        with lock:
                            results.append(
                                (
                                    False,
                                    0.0,
                                    f"login: {json.dumps(rlogin, ensure_ascii=False)}",
                                )
                            )
                        q.task_done()
                        continue

                    # msgs
                    for k in range(msgs_per_user):
                        s.sendall(
                            proto.make_message(
                                "message",
                                {"username": user, "text": f"hola #{k} de {user}"},
                                key,
                            )
                        )
                        rmsg = _recv_json_line(s, timeout)
                        if not rmsg.get("ok"):
                            raise RuntimeError(f"message ko: {rmsg}")

            dt = time.perf_counter() - t0
            with lock:
                results.append((True, dt, ""))
        except Exception as e:
            with lock:
                results.append((False, 0.0, f"{e.__class__.__name__}: {e}"))
        finally:
            q.task_done()


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Mini prueba de carga PAI-2")
    ap.add_argument("--users", type=int, default=50)
    ap.add_argument("--msgs", type=int, default=3, help="mensajes por usuario")
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument(
        "--ramp-ms", type=int, default=0, help="espaciado entre tareas (ms)"
    )
    ap.add_argument("--timeout", type=float, default=5.0, help="timeout socket (s)")
    ap.add_argument(
        "--out", type=str, default="", help="ruta JSON de salida (opcional)"
    )
    args = ap.parse_args()

    print("[i] Iniciando load_test...")
    print(f"[i] Target: {HOST}:{PORT}  tls_name={SNI}")
    print(
        f"[i] Plan: users={args.users}, msgs_per_user={args.msgs}, "
        f"workers={args.workers}, ramp_ms={args.ramp_ms}, timeout={args.timeout:.1f}s"
    )
    print(f"[i] Preflight TLS a {HOST}:{PORT} (SNI={SNI}) ...")
    _preflight(HOST, PORT, args.timeout)
    print("[i] Preflight OK")

    q: "queue.Queue[Tuple[int, int]]" = queue.Queue()
    for i in range(args.users):
        q.put((i, 0))

    results: List[Tuple[bool, float, str]] = []
    lock = threading.Lock()
    threads = []

    t_start = time.perf_counter()

    for _ in range(args.workers):
        th = threading.Thread(
            target=_worker,
            args=(q, results, args.timeout, args.msgs, lock),
            daemon=True,
        )
        th.start()
        threads.append(th)

    # Feed & progreso
    fed = 0
    while fed < args.users:
        time.sleep(max(args.ramp_ms, 0) / 1000.0)
        fed += 1
        if fed % 5 == 0 or fed == args.users:
            print(f"[.] Progreso: {fed}/{args.users}")

    q.join()
    for th in threads:
        th.join(timeout=1.0)

    t_total = time.perf_counter() - t_start

    oks = [dt for ok, dt, _ in results if ok]
    kos = [err for ok, _, err in results if not ok]
    p50 = median(oks) if oks else 0.0
    p95 = sorted(oks)[int(0.95 * len(oks)) - 1] if len(oks) >= 1 else 0.0

    print("\n=== RESUMEN ===")
    print(f"ok={len(oks)}  ko={len(kos)}  total={len(results)}")
    print(f"duración total={t_total:.2f}s")
    print(f"latencia p50={p50*1000:.1f} ms  p95={p95*1000:.1f} ms")

    if kos:
        print("errores (muestra 5/{}):".format(len(kos)))
        for e in kos[:5]:
            print(f"  - {e}")

    if args.out:
        payload = {
            "host": HOST,
            "port": PORT,
            "users": args.users,
            "msgs_per_user": args.msgs,
            "workers": args.workers,
            "ramp_ms": args.ramp_ms,
            "timeout": args.timeout,
            "duration_sec": t_total,
            "ok_count": len(oks),
            "ko_count": len(kos),
            "latency_ms": [dt * 1000.0 for dt in oks],
            "errors": kos,
        }
        import pathlib

        path = pathlib.Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
        print(f"[i] Guardado: {path}")


if __name__ == "__main__":
    main()
