# modules/discord_osint.py
from .base_module import BaseOSINTModule

class DiscordOSINT(BaseOSINTModule):
    def __init__(self):
        super().__init__("DiscordOSINT")

    async def collect(self, username: str, case_id: str, db, target_id: int):
        print(f"[DiscordOSINT] Scanning user: {username}")
        sample_data = {
            "username": username,
            "platform": "discord",
            "status": "collected"
        }
        db.save_artifact(target_id, self.module_name, "profile", sample_data)
        print(f"    -> Artifact saved for {username}")