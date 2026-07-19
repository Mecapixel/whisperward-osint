# modules/discord_osint.py
"""
WhisperWard OSINT — Discord Public OSINT Module
Pixora Inc.

This module collects Discord intelligence from strictly public, tokenless
surfaces. Discord deliberately has no public endpoint for looking up an arbitrary
user by username, and the endpoints that would return that information require a
bot or user token and, in many cases, a shared server. WhisperWard does not use
tokens, does not read private or direct messages, and does not join servers to
observe them. Doing any of those would cross the line this project draws around
public-signal collection.

What is genuinely public, and what this module uses, is twofold:

  1. The server widget endpoint, /api/guilds/{guild_id}/widget.json. A server
     owner must explicitly enable the widget for this to return anything; when
     enabled, Discord itself serves it without authentication. It exposes the
     server name, an approximate presence count, a list of currently online
     members limited to their public display data, and any active invite the
     widget advertises. This is opt-in public data published by the server.

  2. Public invite metadata, /api/v10/invites/{code}?with_counts=true. An invite
     code is something a person chose to share publicly. Resolving it returns the
     destination server's public profile — name, description, approximate member
     and online counts, verification level, and any public features — without a
     token and without joining.

Both are public by the platform's own design. Neither reads message content,
neither requires credentials, and neither observes anyone who has not been made
public by a server they belong to. A username-style query is therefore treated
as a server or invite reference: if it looks like an invite code or URL it is
resolved as an invite, otherwise if it is a numeric snowflake it is treated as a
guild id for the widget endpoint. When an input is neither, the module returns a
complete, empty, clearly annotated result rather than reaching for a private API.

Collection is rate-limit aware. It routes through the shared api_limiter the
other collectors use, sets a descriptive User-Agent as Discord's API guidelines
request, and honors HTTP 429 Retry-After with bounded backoff. Every network
step is best-effort: a disabled widget, an expired invite, a rate limit, or a
transient error degrades to an annotated empty result rather than raising, so a
Discord lookup can never bring down a multi-platform scan.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aiohttp

from core.base_module import BaseOSINTModule
from core.rate_limiter import api_limiter


# Discord API surface. Only public, tokenless endpoints appear here by design.
_DISCORD_API_BASE = "https://discord.com/api/v10"
_WIDGET_URL = "https://discord.com/api/guilds/{guild_id}/widget.json"
_INVITE_URL = _DISCORD_API_BASE + "/invites/{code}?with_counts=true&with_expiration=true"

# Discord asks automated clients to identify themselves. This is not an auth
# token; it is a courtesy identifier per Discord's API guidelines.
_USER_AGENT = (
    "WhisperWard-OSINT (+https://github.com/Mecapixel/whisperward-osint, "
    "child-safety research; public-data only)"
)

# Matches a bare invite code or any of the invite URL forms a person might paste.
_INVITE_PATTERNS = [
    re.compile(r"(?:https?://)?discord(?:app)?\.com/invite/([A-Za-z0-9\-]+)", re.I),
    re.compile(r"(?:https?://)?discord\.gg/([A-Za-z0-9\-]+)", re.I),
]

# A Discord snowflake is a 17-20 digit id. Used to recognise a guild id input.
_SNOWFLAKE = re.compile(r"^\d{17,20}$")


def _extract_invite_code(reference: str) -> Optional[str]:
    """Return the invite code from a bare code, a discord.gg URL, or a full
    invite URL. A bare token that is not clearly an invite URL is treated as an
    invite code only when it contains no spaces and is not a pure snowflake."""
    text = (reference or "").strip()
    for pattern in _INVITE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(1)
    # A bare, URL-free token that looks like an invite code (letters/digits,
    # not a numeric snowflake) is accepted as a code. Snowflakes fall through
    # to widget handling instead.
    if text and " " not in text and not _SNOWFLAKE.match(text):
        if re.fullmatch(r"[A-Za-z0-9\-]{2,32}", text) and not text.isdigit():
            return text
    return None


def _shape_invite(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the public fields WhisperWard cares about from an invite payload.

    Only public server metadata is retained. The inviter object, when present, is
    reduced to a public display handle; never any private data.
    """
    guild = payload.get("guild") or {}
    channel = payload.get("channel") or {}
    shaped: Dict[str, Any] = {
        "server_name": guild.get("name"),
        "server_id": guild.get("id"),
        "server_description": guild.get("description"),
        "verification_level": guild.get("verification_level"),
        "server_features": guild.get("features") or [],
        "approximate_member_count": payload.get("approximate_member_count"),
        "approximate_presence_count": payload.get("approximate_presence_count"),
        "invite_channel": channel.get("name"),
        "invite_expires_at": payload.get("expires_at"),
    }
    icon = guild.get("icon")
    if guild.get("id") and icon:
        shaped["server_icon_url"] = (
            f"https://cdn.discordapp.com/icons/{guild['id']}/{icon}.png"
        )
    inviter = payload.get("inviter") or {}
    if inviter:
        # Public handle only. Username plus discriminator is public profile data
        # on an invite; nothing private is taken.
        handle = inviter.get("username")
        disc = inviter.get("discriminator")
        if handle and disc and disc != "0":
            shaped["inviter_handle"] = f"{handle}#{disc}"
        elif handle:
            shaped["inviter_handle"] = handle
        shaped["inviter_id"] = inviter.get("id")
    return shaped


def _shape_widget(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract public fields from a widget payload.

    The widget lists currently online members with only their public display
    data. WhisperWard keeps a bounded, reduced view: display name, public id, and
    status, never anything more. The list is capped so an unusually large widget
    cannot bloat an artifact.
    """
    members = payload.get("members") or []
    reduced_members = []
    for m in members[:100]:
        reduced_members.append({
            "display_name": m.get("username"),
            "public_id": m.get("id"),
            "status": m.get("status"),
        })
    shaped: Dict[str, Any] = {
        "server_name": payload.get("name"),
        "server_id": payload.get("id"),
        "approximate_presence_count": payload.get("presence_count"),
        "instant_invite": payload.get("instant_invite"),
        "public_online_members": reduced_members,
        "public_online_member_count": len(reduced_members),
        "public_channels": [
            {"name": c.get("name"), "public_id": c.get("id")}
            for c in (payload.get("channels") or [])[:50]
        ],
    }
    return shaped


class _RateLimited(Exception):
    """Internal signal that Discord returned HTTP 429 with a retry hint."""

    def __init__(self, retry_after: float):
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


class DiscordOSINT(BaseOSINTModule):
    """Collects public Discord server and invite intelligence without tokens.

    The collect signature matches the other WhisperWard collectors so the plugin
    layer and the pipeline treat Discord identically to Roblox: given a reference
    and a case, it persists a single normalized profile artifact.
    """

    def __init__(self):
        super().__init__("DiscordOSINT")
        self.max_retries = 3
        self.timeout = 12

    # ── public entry point ────────────────────────────────────────────────────
    async def collect(self, username: str, case_id: str, db, target_id: int) -> Dict[str, Any]:
        """Collect public Discord data for a reference and persist it.

        `username` is interpreted as a public reference: an invite code/URL, or a
        numeric guild id for the widget endpoint. The collected dictionary is
        saved as a 'profile' artifact, mirroring the Roblox collector, and also
        returned so the plugin can normalize it without a second fetch.
        """
        print(f"[DiscordOSINT] Collecting public Discord data for: {username}")
        data = await self.fetch(username)

        if db is not None and target_id is not None:
            try:
                artifact_id = db.save_artifact(
                    target_id=target_id,
                    module_name=self.module_name,
                    artifact_type="profile",
                    raw_data=data,
                )
                print(f"    ✅ Discord profile saved (Artifact ID: {artifact_id})")
            except Exception as exc:  # persistence must never crash a scan
                print(f"    ⚠️ Could not persist Discord artifact: {exc}")

        ref = data.get("reference_type", "unknown")
        if data.get("server_name"):
            print(f"       Server: {data['server_name']} | via {ref}")
        elif data.get("collection_note"):
            print(f"       {data['collection_note']}")
        return data

    # ── fetch orchestration ───────────────────────────────────────────────────
    async def fetch(self, reference: str) -> Dict[str, Any]:
        """Resolve a reference to public Discord data. Never raises; annotates."""
        data: Dict[str, Any] = {
            "reference": reference,
            "platform": "discord",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "reference_type": None,
            "public_data_only": True,
        }

        invite_code = _extract_invite_code(reference)
        try:
            async with api_limiter:
                if invite_code:
                    data["reference_type"] = "invite"
                    data["invite_code"] = invite_code
                    payload = await self._get_with_retry(self._fetch_invite, invite_code)
                    if payload:
                        data.update(_shape_invite(payload))
                    else:
                        data["collection_note"] = (
                            "Invite could not be resolved. It may be expired, "
                            "revoked, or invalid. No private lookup was attempted."
                        )
                elif _SNOWFLAKE.match(reference.strip()):
                    data["reference_type"] = "guild_widget"
                    guild_id = reference.strip()
                    data["guild_id"] = guild_id
                    payload = await self._get_with_retry(self._fetch_widget, guild_id)
                    if payload:
                        data.update(_shape_widget(payload))
                    else:
                        data["collection_note"] = (
                            "The server widget is disabled or the guild id is not "
                            "public. Only widget-enabled servers expose public "
                            "data; no token-based lookup was attempted."
                        )
                else:
                    # Not a resolvable public reference. Discord has no public
                    # username search, so this is where the public boundary ends.
                    data["reference_type"] = "unresolvable"
                    data["collection_note"] = (
                        "Input is not a public Discord reference. Discord exposes "
                        "no tokenless username lookup, so collection is limited to "
                        "invite codes and widget-enabled guild ids. No private API "
                        "was used."
                    )
        except Exception as exc:  # the whole fetch is best-effort
            data["fetch_error"] = str(exc)
            data["collection_note"] = (
                "A transient error occurred during public collection; the result "
                "is intentionally empty rather than partial."
            )
        return data

    # ── network helpers ───────────────────────────────────────────────────────
    async def _get_with_retry(self, func, param):
        """Best-effort retry with bounded backoff, honoring Retry-After on 429.

        Mirrors the retry posture of the Roblox collector: a persistent failure
        returns None so the caller degrades to an annotated empty result.
        """
        for attempt in range(self.max_retries):
            try:
                return await func(param)
            except _RateLimited as rl:
                wait = min(rl.retry_after, 10.0)
                if attempt == self.max_retries - 1:
                    print(f"    ⚠️ Discord rate limit persisted after {self.max_retries} attempts")
                    return None
                await asyncio.sleep(wait)
            except Exception as exc:
                if attempt == self.max_retries - 1:
                    print(f"    ⚠️ Discord fetch failed after {self.max_retries} attempts: {exc}")
                    return None
                await asyncio.sleep(1.5 * (attempt + 1))
        return None

    async def _fetch_invite(self, code: str) -> Optional[Dict[str, Any]]:
        return await self._get_json(_INVITE_URL.format(code=code))

    async def _fetch_widget(self, guild_id: str) -> Optional[Dict[str, Any]]:
        return await self._get_json(_WIDGET_URL.format(guild_id=guild_id))

    async def _get_json(self, url: str) -> Optional[Dict[str, Any]]:
        headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 429:
                    retry_after = 1.0
                    try:
                        body = await resp.json()
                        retry_after = float(body.get("retry_after", 1.0))
                    except Exception:
                        header_val = resp.headers.get("Retry-After")
                        if header_val:
                            try:
                                retry_after = float(header_val)
                            except ValueError:
                                retry_after = 1.0
                    raise _RateLimited(retry_after)
                # 401/403/404 and friends are expected for disabled widgets,
                # expired invites, or private guilds. Treat as "no public data".
                return None
