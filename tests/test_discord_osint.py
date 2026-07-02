# tests/test_discord_osint.py
"""
Tests for the Discord public OSINT module and plugin.

No network calls: fetch is exercised by shaping fabricated public payloads, and
the plugin is exercised through the shared contract. Everything here confirms the
public-data boundary, the normalized shape, the risk-signal behavior, and honest
degradation when nothing public resolves.
"""

import asyncio

import pytest

from modules.discord_osint import (
    DiscordOSINT, _extract_invite_code, _shape_invite, _shape_widget,
)
from modules.platform_plugin import default_registry, NORMALIZED_KEYS


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── reference resolution ──────────────────────────────────────────────────────
class TestReferenceResolution:
    def test_bare_invite_code(self):
        assert _extract_invite_code("aBcD1234") == "aBcD1234"

    def test_discord_gg_url(self):
        assert _extract_invite_code("https://discord.gg/xyz789") == "xyz789"

    def test_full_invite_url(self):
        assert _extract_invite_code("discord.com/invite/HelloWorld") == "HelloWorld"

    def test_snowflake_is_not_an_invite(self):
        # A numeric guild id must not be misread as an invite code.
        assert _extract_invite_code("123456789012345678") is None

    def test_garbage_with_spaces_is_not_an_invite(self):
        assert _extract_invite_code("not a code") is None


# ── shaping keeps only public fields ──────────────────────────────────────────
class TestShaping:
    def test_invite_shape_extracts_public_server_fields(self):
        payload = {
            "guild": {"id": "42", "name": "Synthetic Server", "description": "desc",
                       "verification_level": 1, "features": ["COMMUNITY"], "icon": "abc"},
            "channel": {"name": "general"},
            "approximate_member_count": 1000,
            "approximate_presence_count": 120,
            "expires_at": None,
            "inviter": {"username": "synthetic_inviter", "discriminator": "0", "id": "7"},
        }
        shaped = _shape_invite(payload)
        assert shaped["server_name"] == "Synthetic Server"
        assert shaped["server_id"] == "42"
        assert shaped["approximate_member_count"] == 1000
        assert shaped["server_icon_url"].endswith("/icons/42/abc.png")
        # discriminator "0" is the new-username scheme; handle carries no suffix
        assert shaped["inviter_handle"] == "synthetic_inviter"

    def test_widget_shape_bounds_member_list(self):
        payload = {
            "id": "99", "name": "Widget Server", "presence_count": 500,
            "instant_invite": "https://discord.gg/abc",
            "members": [{"username": f"u{i}", "id": str(i), "status": "online"}
                        for i in range(250)],
            "channels": [{"name": "voice", "id": "1"}],
        }
        shaped = _shape_widget(payload)
        assert shaped["server_name"] == "Widget Server"
        # Member list is capped at 100 to bound artifact size.
        assert shaped["public_online_member_count"] == 100
        assert len(shaped["public_online_members"]) == 100
        # Only public display fields are retained per member.
        assert set(shaped["public_online_members"][0].keys()) == {
            "display_name", "public_id", "status"}


# ── fetch degrades honestly without network ───────────────────────────────────
class TestFetchDegradation:
    def test_unresolvable_reference_annotates_not_raises(self):
        module = DiscordOSINT()
        data = run(module.fetch("this is not a discord reference"))
        assert data["platform"] == "discord"
        assert data["public_data_only"] is True
        assert data["reference_type"] == "unresolvable"
        assert "no tokenless username lookup" in data["collection_note"].lower()
        # Nothing public resolved, so no server fields are present.
        assert data.get("server_name") is None


# ── plugin contract ───────────────────────────────────────────────────────────
class TestDiscordPlugin:
    def test_plugin_available_and_registered(self):
        registry = default_registry()
        assert "discord" in registry.available_platforms()
        assert registry.capabilities()["discord"] is True

    def test_normalized_shape_is_canonical(self):
        plugin = default_registry().get("discord")
        raw = {
            "server_id": "42", "server_name": "Synthetic Server",
            "server_description": "a synthetic community",
            "server_icon_url": "https://cdn.discordapp.com/icons/42/abc.png",
            "reference_type": "invite", "public_data_only": True,
        }
        profile = plugin.normalize(raw, "discord.gg/synthetic")
        assert set(profile.keys()) == NORMALIZED_KEYS
        assert profile["platform"] == "discord"
        assert profile["platform_uid"] == "42"
        assert profile["display_name"] == "Synthetic Server"
        assert profile["flags"]["resolved"] is True

    def test_risk_signal_is_review_lead_only(self):
        plugin = default_registry().get("discord")
        raw = {
            "server_id": "42", "server_name": "teen dating vibe server",
            "server_description": "18+ nsfw", "reference_type": "invite",
            "public_data_only": True,
        }
        profile = plugin.normalize(raw, "discord.gg/x")
        signals = plugin.risk_signals(profile)
        codes = {s.code for s in signals}
        assert "server_name_or_bio_review_lead" in codes
        lead = next(s for s in signals if s.code == "server_name_or_bio_review_lead")
        # The framing must be a lead for human review, never a determination.
        assert "not a determination" in lead.description.lower()
        assert 0.0 <= lead.weight <= 1.0

    def test_no_signal_when_nothing_resolves(self):
        plugin = default_registry().get("discord")
        raw = {"reference_type": "unresolvable", "public_data_only": True,
               "collection_note": "nothing public"}
        profile = plugin.normalize(raw, "garbage")
        # Absence of data is not a lead.
        assert plugin.risk_signals(profile) == []

    def test_profile_for_end_to_end_without_network(self):
        # profile_for should fetch (unresolvable, no network), normalize, validate,
        # and attach a signals list — all without raising.
        plugin = default_registry().get("discord")
        profile = run(plugin.profile_for("not-a-real-reference-string xyz"))
        assert set(profile.keys()) == NORMALIZED_KEYS | {"signals"}
        assert isinstance(profile["signals"], list)
