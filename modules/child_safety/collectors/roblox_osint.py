# modules/roblox_osint.py
import aiohttp
import asyncio
from datetime import datetime
from core.base_module import BaseOSINTModule
from core.rate_limiter import api_limiter

class RobloxOSINT(BaseOSINTModule):
    def __init__(self):
        super().__init__("RobloxOSINT")
        self.max_retries = 3
        self.timeout = 10

    async def collect(self, username: str, case_id: str, db, target_id: int):
        print(f"[RobloxOSINT] Collecting public data for: {username}")

        async with api_limiter:
            data = {
                "username": username,
                "collected_at": datetime.now().isoformat(),
                "platform": "roblox"
            }

            user_id = await self._get_with_retry(self._get_user_id, username)
            if user_id:
                data["user_id"] = user_id
                user_info = await self._get_with_retry(self._get_user_info, user_id)
                if user_info:
                    data.update(user_info)
                thumbnail = await self._get_with_retry(self._get_thumbnail, user_id)
                if thumbnail:
                    data["avatar_url"] = thumbnail

                # Milestone 8 — richer public-data collection. Each of these is
                # best-effort: the endpoints rate-limit aggressively and can be
                # hidden by a user's privacy or region settings, so a failure
                # degrades to an empty result rather than failing the whole scan.
                friends = await self._get_with_retry(self._get_friends, user_id)
                if friends is not None:
                    data["friends"] = friends
                    data["friend_count"] = len(friends)

                groups = await self._get_with_retry(self._get_groups, user_id)
                if groups is not None:
                    data["groups"] = groups
                    data["group_count"] = len(groups)

                games = await self._get_with_retry(self._get_games, user_id)
                if games is not None:
                    data["games"] = games
                    data["game_count"] = len(games)

            artifact_id = db.save_artifact(
                target_id=target_id,
                module_name=self.module_name,
                artifact_type="profile",
                raw_data=data
            )
            print(f"    ✅ Roblox profile saved (Artifact ID: {artifact_id})")
            if "displayName" in data:
                print(f"       Display Name: {data.get('displayName')}")
            if "friend_count" in data:
                print(f"       Friends: {data['friend_count']} | Groups: {data.get('group_count', 0)} | Games: {data.get('game_count', 0)}")

    async def _get_with_retry(self, func, param):
        for attempt in range(self.max_retries):
            try:
                return await func(param)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    print(f"    ⚠️ Failed after {self.max_retries} attempts: {e}")
                    return None
                await asyncio.sleep(1 * (attempt + 1))
        return None

    async def _get_user_id(self, username: str):
        url = "https://users.roblox.com/v1/usernames/users"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            async with session.post(url, json={"usernames": [username], "excludeBannedUsers": False}) as resp:
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
        except (KeyError, TypeError, AttributeError) as exc:
            # A hidden profile or an unexpected payload shape yields no info
            # rather than an error, so a single bad response cannot fail a scan.
            print(f"    [roblox] user info unavailable: {exc}")
            return {}

    async def _get_thumbnail(self, user_id: int):
        url = f"https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={user_id}&size=420x420&format=Png"
        try:
            data = await self.safe_fetch(url)
            if data.get("data"):
                return data["data"][0].get("imageUrl")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            # The thumbnail endpoint rate-limits and can return an unexpected
            # shape; a missing avatar is not fatal to the scan.
            print(f"    [roblox] thumbnail unavailable: {exc}")
        return None

    async def _get_friends(self, user_id: int):
        """Fetch the user's public friends list. Returns a list of dicts with
        id, name, and displayName, or an empty list when the list is hidden or
        unavailable. Public endpoint, no authentication required."""
        url = f"https://friends.roblox.com/v1/users/{user_id}/friends"
        try:
            data = await self.safe_fetch(url)
            friends = []
            for f in (data.get("data") or []):
                friends.append({
                    "id": f.get("id"),
                    "name": f.get("name"),
                    "displayName": f.get("displayName"),
                })
            return friends
        except Exception:
            return []

    async def _get_groups(self, user_id: int):
        """Fetch the groups (communities) the user belongs to, with the user's
        role in each. Returns a list of dicts with group id, name, member count,
        and the user's role. Public endpoint. Empty list on failure or privacy."""
        url = f"https://groups.roblox.com/v2/users/{user_id}/groups/roles"
        try:
            data = await self.safe_fetch(url)
            groups = []
            for entry in (data.get("data") or []):
                group = entry.get("group", {}) or {}
                role = entry.get("role", {}) or {}
                groups.append({
                    "group_id": group.get("id"),
                    "name": group.get("name"),
                    "member_count": group.get("memberCount"),
                    "role": role.get("name"),
                })
            return groups
        except Exception:
            return []

    async def _get_games(self, user_id: int):
        """Fetch the user's public created games. Returns a list of dicts with
        place/universe id, name, and play count. Best-effort: this endpoint is
        less consistently public than friends/groups, so it degrades to an empty
        list rather than failing."""
        url = f"https://games.roblox.com/v2/users/{user_id}/games?accessFilter=Public&sortOrder=Asc&limit=50"
        try:
            data = await self.safe_fetch(url)
            games = []
            for g in (data.get("data") or []):
                games.append({
                    "universe_id": g.get("id"),
                    "root_place_id": (g.get("rootPlace") or {}).get("id"),
                    "name": g.get("name"),
                    "place_visits": g.get("placeVisits"),
                })
            return games
        except Exception:
            return []