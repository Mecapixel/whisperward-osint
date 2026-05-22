# config.py
from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    SHERLOCK_TIMEOUT = int(os.getenv("SHERLOCK_TIMEOUT", 12))
    ROBLOX_TIMEOUT = int(os.getenv("ROBLOX_TIMEOUT", 10))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", 3))
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

config = Config()