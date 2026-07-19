# modules/logger.py
from loguru import logger
from pathlib import Path
import sys

def setup_logger():
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    logger.remove()

    logger.add(
        sys.stdout,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> → <level>{message}</level>",
        level="INFO"
    )

    logger.add(
        log_dir / "whisperward_{time:YYYY-MM-DD}.log",
        rotation="10 MB",
        retention="30 days",
        level="DEBUG",
        encoding="utf-8"
    )

    logger.info("WhisperWard Logger initialized")
    return logger

log = setup_logger()