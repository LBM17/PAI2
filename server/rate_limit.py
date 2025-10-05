# server/rate_limit.py
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Tuple


@dataclass
class Rule:
    max_attempts: int = 5  # p.ej. 5 intentos
    window_seconds: int = 300  # en 5 minutos
    cooldown_seconds: int = 300  # bloquea 5 min al superar el umbral


class RateLimiter:
    """
    Ventana deslizante + cooldown. Thread-safe.
    Clave puede ser 'user:alice' o 'ip:127.0.0.1'.
    """

    def __init__(self, rule: Rule):
        self.rule = rule
        self._tries: Dict[str, Deque[int]] = {}
        self._blocked_until: Dict[str, int] = {}
        self._lock = threading.Lock()

    def _now(self) -> int:
        return int(time.time())

    def _prune(self, key: str, now: int):
        dq = self._tries.get(key)
        if not dq:
            return
        limit = now - self.rule.window_seconds
        while dq and dq[0] < limit:
            dq.popleft()

    def is_blocked(self, key: str, now: int | None = None) -> Tuple[bool, int]:
        now = now or self._now()
        until = self._blocked_until.get(key, 0)
        if until > now:
            return True, until - now
        return False, 0

    def register_attempt(self, key: str, now: int | None = None) -> Tuple[bool, int]:
        """
        Registra un intento (fallido normalmente).
        Devuelve (permitir, segundos_restantes_bloqueo).
        """
        now = now or self._now()
        with self._lock:
            blocked, remain = self.is_blocked(key, now)
            if blocked:
                return False, remain

            dq = self._tries.setdefault(key, deque())
            self._prune(key, now)
            dq.append(now)

            if len(dq) > self.rule.max_attempts:
                # Superó umbral: activa cooldown
                self._blocked_until[key] = now + self.rule.cooldown_seconds
                return False, self.rule.cooldown_seconds
            return True, 0

    def reset_success(self, key: str):
        """Limpia estado tras un login correcto."""
        with self._lock:
            self._tries.pop(key, None)
            self._blocked_until.pop(key, None)
