# modules/roblox_osint.py
import aiohttp
from datetime import datetime
from .base_module import BaseOSINTModule

class RobloxOSINT(BaseOSINTModule):
    def __init__(self):
        super().__init__("RobloxOSINT")

    async def collect(self, username: str, case_id: str, db, target_id: int):
        print(f"[RobloxOSINT] Collecting public data for: {username}")
        data = {
            "username": username,
            "collected_at": datetime.now().isoformat(),
            "platform": "roblox"
        }

        user_id = await self._get_user_id(username)
        if user_id:
            data["user_id"] = user_id
            user_info = await self._get_user_info(user_id)
            if user_info:
                data.update(user_info)
            thumbnail = await self._get_thumbnail(user_id)
            if thumbnail:
                data["avatar_url"] = thumbnail

        artifact_id = db.save_artifact(
            target_id=target_id,
            module_name=self.module_name,
            artifact_type="profile",
            raw_data=data
        )
        print(f"    ✅ Roblox profile saved (Artifact ID: {artifact_id})")
        if "displayName" in data:
            print(f"       Display Name: {data.get('displayName')}")

    async def _get_user_id(self, username: str):
        url = "https://users.roblox.com/v1/usernames/users"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={"usernames": [username], "excludeBannedUsers": False}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("data"):
                            return data["data"][0]["id"]
        except Exception as e:
            print(f"    ⚠️ Could not get user ID: {e}")
        return None

    async def _get_user_info(self, user_id: int):
        url = f"https://users.roblox.com/v1/users/{user_id}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            print(f"    ⚠️ Could not get user info: {e}")
        return None

    async def _get_thumbnail(self, user_id: int):
        url = f"https://thumbnails.roblox.com/v1/users/avatar?userIds={user_id}&size=420x420&format=Png"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("data"):
                            return data["data"][0].get("imageUrl")
        except Exception as e:
            print(f"    ⚠️ Could not get thumbnail: {e}")
        return None