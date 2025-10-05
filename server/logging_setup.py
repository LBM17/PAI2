# server/logging_setup.py
import logging
import os
from logging.handlers import RotatingFileHandler


def get_logger(name: str = "server"):
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger(name)
    if logger.handlers:  # evitar duplicados en recargas
        return logger
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(
        "logs/server.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    # opcional: también a consola en dev
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger
