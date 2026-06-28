"""
WhisperWard OSINT — Platform Plugin Architecture
Phase 4, Milestone 6
Pixora Inc.

This module defines a clean interface for the platforms WhisperWard investigates,
so that adding a platform is a matter of writing a plugin rather than threading a
new platform string through the codebase. The design keeps the analysis side of
the system platform agnostic. The correlation engine and the risk engine consume a
normalized profile shape, and each plugin is responsible for turning its own
platform's raw data into that shape and for declaring the risk signals that are
specific to it.

Each plugin owns three responsibilities. It fetches a profile for a username from
its platform. It normalizes that platform's raw response into the common profile
shape the rest of the system understands. And it declares its platform specific
risk signals, the things that, on that platform, are worth a human's attention.

The existing OSINT modules already work and are exercised by the pipeline, so the
plugins wrap them rather than replacing them. The Roblox plugin delegates fetching
to the existing RobloxOSINT module and adds normalization and signal declaration
on top. Nothing about the existing collection code changes.

The normalized profile shape is intentionally small and stable:

    {
        "platform":      str,            the platform name, lower case
        "username":      str,            the queried username
        "platform_uid":  str or None,    the platform's own id for the account
        "display_name":  str or None,
        "description":   str or None,    bio or profile text
        "created_at":    str or None,    account creation timestamp if known
        "avatar_url":    str or None,
        "flags":         dict,           platform booleans, for example is_banned
        "raw":           dict,           the unmodified platform payload
    }

A consumer can rely on those keys existing for any platform. Anything platform
specific lives under raw, and a plugin's risk signals interpret raw without the
rest of the system needing to know its shape.
"""

from __future__ import annotations

from typing import Optional, Dict, Any, List


# The canonical keys every normalized profile carries. Used for validation so a
# plugin cannot quietly return a shape the rest of the system does not expect.
NORMALIZED_KEYS = {
    "platform", "username", "platform_uid", "display_name",
    "description", "created_at", "avatar_url", "flags", "raw",
}


def empty_profile(platform: str, username: str) -> Dict[str, Any]:
    """Returns a normalized profile with every key present and empty. Plugins
    start from this so the output shape is guaranteed complete even when a fetch
    returns little or nothing."""
    return {
        "platform": platform.lower(),
        "username": username,
        "platform_uid": None,
        "display_name": None,
        "description": None,
        "created_at": None,
        "avatar_url": None,
        "flags": {},
        "raw": {},
    }


class RiskSignal:
    """A single platform specific observation worth a human's attention. A signal
    carries a short machine code, a human readable description, and a weight from
    zero to one indicating how much it should draw attention. Signals are leads
    for review, not determinations, which is why a plugin emits them rather than a
    verdict."""

    def __init__(self, code: str, description: str, weight: float):
        self.code = code
        self.description = description
        self.weight = max(0.0, min(1.0, float(weight)))

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "description": self.description, "weight": self.weight}


class PlatformPlugin:
    """The interface every platform plugin implements. A plugin is identified by
    its platform name and provides fetching, normalization, and risk signal
    declaration. Subclasses override fetch_profile, normalize, and risk_signals.
    The base class provides the validation and the public profile_for entry point
    that ties the steps together."""

    platform_name: str = "base"

    def is_available(self) -> bool:
        """Whether the plugin can actually run. A plugin that wraps an external
        module returns False when that module is not importable, so the registry
        can report capability honestly rather than failing at call time."""
        return True

    async def fetch_profile(self, username: str, db=None, case_id: Optional[str] = None,
                            target_id: Optional[int] = None) -> Dict[str, Any]:
        """Fetches the raw platform payload for a username. Implementations return
        the platform's own dictionary, which normalize then shapes. The db, case_id
        and target_id are passed through for plugins that wrap a collector which
        also persists artifacts."""
        raise NotImplementedError

    def normalize(self, raw: Dict[str, Any], username: str) -> Dict[str, Any]:
        """Turns a raw platform payload into the common normalized shape. The base
        implementation returns an empty profile carrying the raw payload, which a
        subclass refines."""
        profile = empty_profile(self.platform_name, username)
        profile["raw"] = raw or {}
        return profile

    def risk_signals(self, profile: Dict[str, Any]) -> List[RiskSignal]:
        """Declares the platform specific risk signals present in a normalized
        profile. The base implementation declares none."""
        return []

    def validate_profile(self, profile: Dict[str, Any]) -> bool:
        """Confirms a normalized profile carries exactly the canonical keys, so a
        malformed plugin output is caught at the boundary rather than downstream."""
        return set(profile.keys()) == NORMALIZED_KEYS

    async def profile_for(self, username: str, db=None, case_id: Optional[str] = None,
                          target_id: Optional[int] = None) -> Dict[str, Any]:
        """The public entry point. Fetches, normalizes, validates, and attaches the
        declared risk signals. Returns the normalized profile with a signals list."""
        raw = await self.fetch_profile(username, db=db, case_id=case_id, target_id=target_id)
        profile = self.normalize(raw or {}, username)
        if not self.validate_profile(profile):
            # A plugin that returns a malformed shape is a programming error. Fall
            # back to a complete empty profile carrying the raw payload so the rest
            # of the system stays safe, and mark the problem in flags.
            safe = empty_profile(self.platform_name, username)
            safe["raw"] = raw or {}
            safe["flags"]["normalization_error"] = True
            profile = safe
        profile["signals"] = [s.to_dict() for s in self.risk_signals(profile)]
        return profile


class RobloxPlugin(PlatformPlugin):
    """Wraps the existing RobloxOSINT collector. Fetching and artifact persistence
    are delegated to that module unchanged. This plugin adds the normalization into
    the common shape and the Roblox specific risk signals."""

    platform_name = "roblox"

    def __init__(self):
        self._module = None
        try:
            from .roblox_osint import RobloxOSINT
            self._module_cls = RobloxOSINT
        except Exception:
            try:
                from modules.roblox_osint import RobloxOSINT
                self._module_cls = RobloxOSINT
            except Exception:
                self._module_cls = None

    def is_available(self) -> bool:
        return self._module_cls is not None

    async def fetch_profile(self, username: str, db=None, case_id: Optional[str] = None,
                            target_id: Optional[int] = None) -> Dict[str, Any]:
        """Delegates to RobloxOSINT. When a db and target_id are supplied the
        existing collector persists an artifact as it always has. Either way the
        raw profile dictionary is returned for normalization. When the collector
        is unavailable an empty raw payload is returned so the pipeline degrades
        rather than crashing."""
        if self._module_cls is None:
            return {}
        module = self._module_cls()

        # The existing collect method fetches and saves but does not return the
        # data dictionary. To get the normalized profile without changing that
        # module, we reuse its individual fetch helpers, which are public enough to
        # call, and persist through it only when a db is provided.
        raw = {
            "username": username,
            "platform": "roblox",
        }
        try:
            user_id = await module._get_with_retry(module._get_user_id, username)
            if user_id:
                raw["user_id"] = user_id
                info = await module._get_with_retry(module._get_user_info, user_id)
                if info:
                    raw.update(info)
                thumb = await module._get_with_retry(module._get_thumbnail, user_id)
                if thumb:
                    raw["avatar_url"] = thumb

                # Milestone 8 enrichment. The collector's friends, groups, and
                # games helpers are best-effort and self-degrading, so a hidden
                # list or a rate limit yields an empty result rather than an
                # error. Each is guarded with hasattr so the plugin still works
                # against an older collector that lacks these methods.
                if hasattr(module, "_get_friends"):
                    friends = await module._get_with_retry(module._get_friends, user_id)
                    if friends is not None:
                        raw["friends"] = friends
                        raw["friend_count"] = len(friends)
                if hasattr(module, "_get_groups"):
                    groups = await module._get_with_retry(module._get_groups, user_id)
                    if groups is not None:
                        raw["groups"] = groups
                        raw["group_count"] = len(groups)
                if hasattr(module, "_get_games"):
                    games = await module._get_with_retry(module._get_games, user_id)
                    if games is not None:
                        raw["games"] = games
                        raw["game_count"] = len(games)
        except Exception as exc:
            raw["fetch_error"] = str(exc)

        # Persist through the existing collector path when asked, so artifact
        # behavior is identical to the current pipeline.
        if db is not None and target_id is not None:
            try:
                db.save_artifact(target_id=target_id, module_name="RobloxOSINT",
                                 artifact_type="profile", raw_data=raw)
            except Exception:
                pass
        return raw

    def normalize(self, raw: Dict[str, Any], username: str) -> Dict[str, Any]:
        profile = empty_profile(self.platform_name, username)
        profile["raw"] = raw or {}
        profile["platform_uid"] = str(raw.get("user_id")) if raw.get("user_id") else None
        profile["display_name"] = raw.get("displayName")
        profile["description"] = raw.get("description")
        profile["created_at"] = raw.get("created")
        profile["avatar_url"] = raw.get("avatar_url")
        profile["flags"] = {"is_banned": bool(raw.get("isBanned", False))}
        return profile

    def risk_signals(self, profile: Dict[str, Any]) -> List[RiskSignal]:
        """Declares Roblox specific signals. These are conservative leads for human
        review, not conclusions. A banned account, an empty or very new profile,
        and contact solicitation language in the description are the kinds of thing
        an analyst would want flagged."""
        signals = []
        raw = profile.get("raw", {})
        description = (profile.get("description") or "").lower()

        if profile.get("flags", {}).get("is_banned"):
            signals.append(RiskSignal(
                "account_banned",
                "The account is banned on the platform, which warrants review of why.",
                0.3))

        if not profile.get("display_name") and not description:
            signals.append(RiskSignal(
                "sparse_profile",
                "The profile carries little public information, common for burner accounts.",
                0.2))

        # Contact solicitation language is a known grooming pattern. This is a
        # keyword lead only, explicitly for human review, never a determination.
        solicitation_terms = ["add me on", "dm me", "snap me", "discord", "kik",
                              "message me on", "find me on"]
        if any(term in description for term in solicitation_terms):
            signals.append(RiskSignal(
                "offsite_contact_solicitation",
                "The profile text invites contact on another platform, a pattern worth review.",
                0.5))

        # Milestone 8 — signals derived from the enriched friends, groups, and
        # games data. Every one of these is a conservative lead for a human
        # analyst, never a determination. The data is public and the thresholds
        # are deliberately loose so the signal surfaces a pattern to look at, not
        # a conclusion about a person.

        friends = raw.get("friends") or []
        friend_count = raw.get("friend_count")
        groups = raw.get("groups") or []
        games = raw.get("games") or []

        # A large friend network is context, not an accusation. Surfaced with a
        # low weight because the number alone proves nothing; it matters only
        # when an analyst weighs it against the account's age and activity.
        if isinstance(friend_count, int) and friend_count >= 200:
            signals.append(RiskSignal(
                "large_friend_network",
                "The account has a large public friend list, useful context when "
                "weighed against the account's age and activity.",
                0.2))

        # Group names are public text. Surfacing groups whose names contain terms
        # commonly associated with inappropriate Roblox spaces is a review lead
        # only. It flags a candidate for a human to look at; it is never a
        # determination that a group is what the term suggests.
        review_terms = ["condo", "scented con", "vibe", "18+", "nsfw"]
        flagged_groups = []
        for g in groups:
            name = (g.get("name") or "").lower()
            if any(term in name for term in review_terms):
                flagged_groups.append(g.get("name"))
        if flagged_groups:
            preview = ", ".join(str(n) for n in flagged_groups[:3] if n)
            signals.append(RiskSignal(
                "group_name_review_lead",
                "One or more group names match terms sometimes associated with "
                "inappropriate spaces and should be reviewed by an analyst: "
                f"{preview}. This is a lead for human review, not a determination.",
                0.4))

        # The same conservative, review-only treatment for created games.
        flagged_games = []
        for g in games:
            name = (g.get("name") or "").lower()
            if any(term in name for term in review_terms):
                flagged_games.append(g.get("name"))
        if flagged_games:
            preview = ", ".join(str(n) for n in flagged_games[:3] if n)
            signals.append(RiskSignal(
                "game_name_review_lead",
                "One or more created game names match terms worth an analyst's "
                f"review: {preview}. This is a lead for human review, not a "
                "determination.",
                0.4))

        return signals


class DiscordPlugin(PlatformPlugin):
    """Placeholder for Discord. The interface is defined so Milestone 8, the cross
    platform investigation work, can implement fetching and signals against a
    stable contract. Until then the plugin reports itself unavailable and returns
    an empty normalized profile, so the rest of the system treats Discord as a
    known but not yet implemented platform rather than an error."""

    platform_name = "discord"

    def is_available(self) -> bool:
        return False

    async def fetch_profile(self, username: str, db=None, case_id: Optional[str] = None,
                            target_id: Optional[int] = None) -> Dict[str, Any]:
        return {"username": username, "platform": "discord",
                "note": "Discord collection is not yet implemented."}

    def normalize(self, raw: Dict[str, Any], username: str) -> Dict[str, Any]:
        profile = empty_profile(self.platform_name, username)
        profile["raw"] = raw or {}
        return profile


class PluginRegistry:
    """Holds the available plugins and resolves a platform name to its plugin. The
    registry is the single place the rest of the system asks about platform
    capability, so capability reporting stays honest and centralized."""

    def __init__(self):
        self._plugins: Dict[str, PlatformPlugin] = {}

    def register(self, plugin: PlatformPlugin):
        self._plugins[plugin.platform_name.lower()] = plugin

    def get(self, platform: str) -> Optional[PlatformPlugin]:
        return self._plugins.get((platform or "").lower())

    def platforms(self) -> List[str]:
        return sorted(self._plugins.keys())

    def available_platforms(self) -> List[str]:
        return sorted(name for name, p in self._plugins.items() if p.is_available())

    def capabilities(self) -> Dict[str, bool]:
        """Returns a map of platform name to whether it is currently available, for
        the metrics endpoint and for honest capability reporting in the UI."""
        return {name: p.is_available() for name, p in sorted(self._plugins.items())}


def default_registry() -> PluginRegistry:
    """Builds the registry with the plugins WhisperWard ships. Roblox is live,
    Discord is a defined but not yet implemented contract for Milestone 8."""
    registry = PluginRegistry()
    registry.register(RobloxPlugin())
    registry.register(DiscordPlugin())
    return registry