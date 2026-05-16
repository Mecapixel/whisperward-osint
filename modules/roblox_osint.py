# modules/roblox_osint.py
from .base_module import BaseOSINTModule

class RobloxOSINT(BaseOSINTModule):
    def __init__(self):
        super().__init__("RobloxOSINT")

    async def collect(self, username: str, case_id: str, db, target_id: int):
        print(f"[RobloxOSINT] Scanning user: {username}")
        sample_data = {
            "username": username,
            "platform": "roblox",
            "status": "collected"
        }
        db.save_artifact(target_id, self.module_name, "profile", sample_data)
        print(f"    -> Artifact saved for {username}")