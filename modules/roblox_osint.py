# modules/roblox_osint.py
import aiohttp
import asyncio
from datetime import datetime
from .base_module import BaseOSINTModule

class RobloxOSINT(BaseOSINTModule):
    def __init__(self):
        super().__init__("RobloxOSINT")
        self.max_retries = 3
        self.timeout = 10

    async def collect(self, username: str, case_id: str, db, target_id: int):
        """Collect Roblox data with retry logic"""
        print(f"[RobloxOSINT] Collecting public data for: {username}")

        data = {
            "username": username,
            "collected_at": datetime.now().isoformat(),
            "platform": "roblox"
        }

        # Get User ID with retry
        user_id = await self._get_with_retry(self._get_user_id, username)
        if user_id:
            data["user_id"] = user_id
            
            # Get detailed info
            user_info = await self._get_with_retry(self._get_user_info, user_id)
            if user_info:
                data.update(user_info)

            # Get avatar
            thumbnail = await self._get_with_retry(self._get_thumbnail, user_id)
            if thumbnail:
                data["avatar_url"] = thumbnail

        # Save artifact
        artifact_id = db.save_artifact(
            target_id=target_id,
            module_name=self.module_name,
            artifact_type="profile",
            raw_data=data
        )

        print(f"    ✅ Roblox profile saved (Artifact ID: {artifact_id})")
        if "displayName" in data:
            print(f"       Display Name: {data.get('displayName')}")

    async def _get_with_retry(self, func, param):
        """Generic retry wrapper"""
        for attempt in range(self.max_retries):
            try:
                return await func(param)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    print(f"    ⚠️ Failed after {self.max_retries} attempts: {e}")
                    return None
                await asyncio.sleep(1 * (attempt + 1))  # Backoff
        return None

    async def _get_user_id(self, username: str):
        url = "https://users.roblox.com/v1/usernames/users"
        payload = {"usernames": [username], "excludeBannedUsers": False}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    if result.get("data"):
                        return result["data"][0]["id"]
        return None

    async def _get_user_info(self, user_id: int):
        url = f"https://users.roblox.com/v1/users/{user_id}"
        try:
            data = await self.safe_fetch(url)
            return {
                "displayName": data.get("displayName"),
                "description": data.get("description", ""),
                "created": data.get("created"),
                "isBanned": data.get("isBanned", False)
            }
        except:
            return {}

    async def _get_thumbnail(self, user_id: int):
        url = f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=420x420&format=Png"
        try:
            data = await self.safe_fetch(url)
            if data.get("data"):
                return data["data"][0].get("imageUrl")
        except:
            pass
        return None