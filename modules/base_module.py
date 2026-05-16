# modules/base_module.py
import hashlib
import json
import aiohttp
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseOSINTModule(ABC):
    """Abstract base class for all OSINT modules"""

    def __init__(self, module_name: str):
        self.module_name = module_name

    @staticmethod
    def hash_data(data: Any) -> str:
        if isinstance(data, (dict, list)):
            content = json.dumps(data, sort_keys=True, default=str)
        else:
            content = str(data)
        return hashlib.sha256(content.encode()).hexdigest()

    async def safe_fetch(self, url: str, headers: Optional[Dict] = None) -> Dict:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers or {}, timeout=15) as resp:
                if resp.status == 200:
                    return await resp.json()
                return {"error": f"HTTP {resp.status}", "url": url}