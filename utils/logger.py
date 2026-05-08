"""Logger centralizado para StrikeBack."""
import logging
import os
import config


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"StrikeBack.{name}")

    if not logger.handlers:
        level = getattr(logging, config.LOG_LEVEL, logging.INFO)
        logger.setLevel(level)

        os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)

        # Handler a archivo
        fh = logging.FileHandler(config.LOG_PATH, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)

        # Silenciar en consola (el dashboard de Rich maneja el output)
        logger.propagate = False

    return logger
