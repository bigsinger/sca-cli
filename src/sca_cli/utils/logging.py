from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Configure logging for sca-cli."""
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        handlers=handlers,
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger for the given module name."""
    return logging.getLogger(name)
