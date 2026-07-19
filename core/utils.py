# modules/utils.py
from pathlib import Path

def ensure_directories():
    """Ensure all required output directories exist"""
    directories = ["exports", "reports", "knowledge_base", "prompts", "temp"]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ Project directories ready")