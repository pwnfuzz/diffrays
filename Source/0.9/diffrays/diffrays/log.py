import logging
import sys
from pathlib import Path

def get_logger(
    name: str = "diffrays",
    log_file: str | None = None,
    console_level: int = logging.CRITICAL + 1,  # default: silent
    file_level: int | None = None,
):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(console_level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        fh.setLevel(file_level or logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger
