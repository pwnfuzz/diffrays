import logging
import sys
from pathlib import Path

def get_logger(name: str = "diffrays", log_file: str | None = None, level: int = logging.INFO):
    """
    Create and configure a logger.
    
    Args:
        name: Logger name (usually __name__ of the caller).
        log_file: Optional path to a log file.
        level: Logging level (default: INFO).
    
    Returns:
        logging.Logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger  # Avoid duplicate handlers on re-import

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(ch)

    # Optional file handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)

    return logger
