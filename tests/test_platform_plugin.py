"""
WhisperWard OSINT — Test suite for the Platform Plugin Architecture
Phase 4, Milestone 6
Pixora Inc.

These tests lock in the plugin contract. The guarantees are that the normalized
profile carries exactly the canonical keys, that the Roblox plugin maps a raw
payload into that shape correctly, that Roblox specific risk signals fire on the
patterns they are meant to catch and stay quiet otherwise, that the registry
resolves platforms and reports capability honestly, that the Discord stub is a
defined but unavailable contract, and that a plugin returning a malformed shape is
caught at the boundary and degraded safely rather than propagating.
"""

import asyncio

import pytest

from core.platform_plugin import (PlatformPlugin, RobloxPlugin, DiscordPlugin,
                                      PluginRegistry, default_registry,
                                      empty_profile, NORMALIZED_KEYS, RiskSignal)


class TestNormalizedShape:
    def test_empty_profile_has_all_keys(self):
        assert set(empty_profile("roblox", "u").keys()) == NORMALIZED_KEYS

    def test_roblox_normalize_maps_fields(self):
        rb = RobloxPlugin()
        raw = {"username": "u", "user_id": 999, "displayName": "Name",
               "description": "bio", "created": "2026-01-01T00:00:00Z",
               "avatar_url": "http://x/a.png", "isBanned": False}
        p = rb.normalize(raw, "u")
        assert p["platform"] == "roblox"
        assert p["platform_uid"] == "999"
        assert p["display_name"] == "Name"
        assert p["description"] == "bio"
        assert p["created_at"] == "2026-01-01T00:00:00Z"
        assert p["avatar_url"] == "http://x/a.png"
        assert p["flags"]["is_banned"] is False

    def test_roblox_normalize_shape_valid(self):
        rb = RobloxPlugin()
        p = rb.normalize({"user_id": 1}, "u")
        assert rb.validate_profile(p)

    def test_normalize_handles_empty_raw(self):
        rb = RobloxPlugin()
        p = rb.normalize({}, "u")
        assert set(p.keys()) == NORMALIZED_KEYS
        assert p["platform_uid"] is None


class TestRiskSignals:
    def test_banned_signal_fires(self):
        rb = RobloxPlugin()
        p = rb.normalize({"isBanned": True}, "u")
        codes = [s.code for s in rb.risk_signals(p)]
        assert "account_banned" in codes

    def test_solicitation_signal_fires(self):
        rb = RobloxPlugin()
        p = rb.normalize({"description": "add me on discord"}, "u")
        codes = [s.code for s in rb.risk_signals(p)]
        assert "offsite_contact_solicitation" in codes

    def test_sparse_profile_signal_fires(self):
        rb = RobloxPlugin()
        p = rb.normalize({}, "u")
        codes = [s.code for s in rb.risk_signals(p)]
        assert "sparse_profile" in codes

    def test_clean_profile_no_solicitation(self):
        rb = RobloxPlugin()
        p = rb.normalize({"displayName": "Real Name",
                          "description": "I like building games"}, "u")
        codes = [s.code for s in rb.risk_signals(p)]
        assert "offsite_contact_solicitation" not in codes

    def test_signal_weight_clamped(self):
        s = RiskSignal("x", "desc", 5.0)
        assert s.weight == 1.0
        s2 = RiskSignal("y", "desc", -3.0)
        assert s2.weight == 0.0


class TestRegistry:
    def test_default_registry_has_roblox_and_discord(self):
        reg = default_registry()
        assert "roblox" in reg.platforms()
        assert "discord" in reg.platforms()

    def test_get_resolves_plugin(self):
        reg = default_registry()
        assert isinstance(reg.get("roblox"), RobloxPlugin)
        assert isinstance(reg.get("discord"), DiscordPlugin)

    def test_get_unknown_returns_none(self):
        assert default_registry().get("myspace") is None

    def test_capabilities_map(self):
        reg = default_registry()
        caps = reg.capabilities()
        assert "roblox" in caps and "discord" in caps
        # Discord is now implemented as a public-signal plugin and reports
        # available whenever its collector module is importable.
        assert caps["discord"] is True

    def test_register_custom_plugin(self):
        class FakePlugin(PlatformPlugin):
            platform_name = "fakebook"

        reg = PluginRegistry()
        reg.register(FakePlugin())
        assert "fakebook" in reg.platforms()


class TestDiscordPluginContract:
    def test_discord_available(self):
        # Discord is now a real public-signal plugin; it is available whenever
        # its collector module imports.
        assert DiscordPlugin().is_available() is True

    def test_discord_profile_well_formed(self):
        # An unresolvable reference (no network needed) still yields a canonical,
        # validated profile with a signals list and no fabricated data.
        dc = DiscordPlugin()
        p = asyncio.run(dc.profile_for("not a resolvable reference xyz"))
        non_signal = {k: v for k, v in p.items() if k != "signals"}
        assert set(non_signal.keys()) == NORMALIZED_KEYS
        assert isinstance(p["signals"], list)
        # Nothing public resolved, so there are no leads.
        assert p["signals"] == []
        assert p["flags"].get("resolved") is False


class TestMalformedSafety:
    def test_malformed_normalize_is_caught(self):
        # A plugin that returns a broken shape must be degraded safely by
        # profile_for, not allowed to propagate.
        class BadPlugin(PlatformPlugin):
            platform_name = "bad"

            async def fetch_profile(self, username, db=None, case_id=None, target_id=None):
                return {"some": "payload"}

            def normalize(self, raw, username):
                return {"only": "two", "keys": "here"}  # missing canonical keys

        p = asyncio.run(BadPlugin().profile_for("u"))
        non_signal = {k: v for k, v in p.items() if k != "signals"}
        assert set(non_signal.keys()) == NORMALIZED_KEYS
        assert p["flags"]["normalization_error"] is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))