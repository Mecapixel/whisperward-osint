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
            from modules.child_safety.collectors.roblox_osint import RobloxOSINT
            self._module_cls = RobloxOSINT
        except Exception:
            try:
                from modules.child_safety.collectors.roblox_osint import RobloxOSINT
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
    """Wraps the DiscordOSINT collector. Like the Roblox plugin, fetching and
    artifact persistence are delegated to the collector unchanged; this plugin
    adds normalization into the common profile shape and the Discord specific
    risk signals.

    Discord is a public-signal-only platform here. The collector resolves invite
    codes and widget-enabled guild ids and never touches a private, token-gated
    endpoint, so 'username' at this layer means a public Discord reference (an
    invite or a guild id), not an arbitrary account name. That boundary is a
    deliberate design choice, documented in modules/discord_osint.py, not a gap.
    """

    platform_name = "discord"

    def __init__(self):
        self._module_cls = None
        try:
            from modules.child_safety.collectors.discord_osint import DiscordOSINT
            self._module_cls = DiscordOSINT
        except Exception:
            try:
                from modules.child_safety.collectors.discord_osint import DiscordOSINT
                self._module_cls = DiscordOSINT
            except Exception:
                self._module_cls = None

    def is_available(self) -> bool:
        return self._module_cls is not None

    async def fetch_profile(self, username: str, db=None, case_id: Optional[str] = None,
                            target_id: Optional[int] = None) -> Dict[str, Any]:
        """Delegates to DiscordOSINT. When a db and target_id are supplied the
        collector persists an artifact exactly as the Roblox path does. The raw
        public payload is returned for normalization either way. When the
        collector is unavailable an annotated empty payload is returned so the
        pipeline degrades rather than crashing."""
        if self._module_cls is None:
            return {"username": username, "platform": "discord",
                    "collection_note": "Discord collector is not importable."}
        module = self._module_cls()
        if db is not None and target_id is not None:
            # collect() both persists and returns the payload.
            return await module.collect(username, case_id, db, target_id)
        # No persistence context: fetch without saving.
        return await module.fetch(username)

    def normalize(self, raw: Dict[str, Any], username: str) -> Dict[str, Any]:
        profile = empty_profile(self.platform_name, username)
        profile["raw"] = raw or {}
        # A Discord "profile" is a public server or invite view. The server is the
        # subject of the normalized shape: its name is the display_name, its
        # description the description, its id the platform_uid, its icon the
        # avatar. This keeps Discord consumable by the same correlation and risk
        # code that reads any other platform's normalized profile.
        profile["platform_uid"] = raw.get("server_id") or raw.get("guild_id")
        profile["display_name"] = raw.get("server_name")
        profile["description"] = raw.get("server_description")
        profile["avatar_url"] = raw.get("server_icon_url")
        profile["flags"] = {
            "reference_type": raw.get("reference_type"),
            "public_data_only": bool(raw.get("public_data_only", True)),
            "resolved": bool(raw.get("server_name")),
        }
        return profile

    def risk_signals(self, profile: Dict[str, Any]) -> List[RiskSignal]:
        """Declares Discord specific signals from public server data. Every one is
        a conservative lead for a human analyst, never a determination. The data
        is public server metadata; the thresholds are deliberately loose so a
        signal surfaces a pattern to look at, not a conclusion about a person or a
        community."""
        signals: List[RiskSignal] = []
        raw = profile.get("raw", {})

        description = (profile.get("description") or "").lower()
        server_name = (profile.get("display_name") or "").lower()
        features = [str(f).lower() for f in (raw.get("server_features") or [])]

        # Server or channel names and descriptions are public text. Terms
        # commonly associated with inappropriate Discord spaces are surfaced as a
        # review lead only, exactly as the Roblox plugin does for group and game
        # names. This flags a candidate for a human to look at; it never asserts
        # what the space is.
        review_terms = ["nsfw", "18+", "e-girl", "e-boy", "condo", "dating",
                        "hookup", "teen dating", "vibe", "nudes"]
        matched = [t for t in review_terms if t in server_name or t in description]
        if matched:
            preview = ", ".join(sorted(set(matched))[:4])
            signals.append(RiskSignal(
                "server_name_or_bio_review_lead",
                "The public server name or description contains terms sometimes "
                f"associated with inappropriate spaces ({preview}) and should be "
                "reviewed by an analyst. This is a lead for human review, not a "
                "determination.",
                0.4))

        # An unverified server that nonetheless carries an age-gated feature is a
        # mild context signal: age-gating exists but Discord's own verification
        # floor does not. Surfaced low because the combination is context, not
        # proof of anything.
        verification_level = raw.get("verification_level")
        if isinstance(verification_level, int) and verification_level == 0:
            if "invite_splash" in features or any("nsfw" in f for f in features):
                signals.append(RiskSignal(
                    "low_verification_public_server",
                    "The server publishes public features while sitting at the "
                    "lowest verification level, worth an analyst's context.",
                    0.2))

        # A very small but highly active server, or a resolvable invite that an
        # analyst is pivoting from, is useful correlation context. A large
        # presence relative to membership is surfaced as low-weight context.
        members = raw.get("approximate_member_count")
        presence = raw.get("approximate_presence_count")
        if isinstance(members, int) and isinstance(presence, int) and members > 0:
            if members <= 50 and presence >= max(10, int(members * 0.6)):
                signals.append(RiskSignal(
                    "small_high_activity_server",
                    "A small server with unusually high concurrent presence, "
                    "useful context when weighed against how the invite surfaced.",
                    0.2))

        # If the collector could not resolve anything public, that is not a risk
        # signal, and no signal is emitted. Absence of data is not a lead.
        return signals


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