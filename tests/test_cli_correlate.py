# tests/test_cli_correlate.py
"""
Tests for the CLI correlate command.

All data is synthetic. The command must: refuse gracefully with fewer than
two targets, build profiles from persisted artifacts only, surface pairwise
leads and identity groups, and seal the full result into the evidence store
as an artifact. Semantic mode stays off in tests so the suite never depends
on a model download.
"""

import json

import pytest
from typer.testing import CliRunner

from database.db_manager import DatabaseManager
from whisperward import app, _build_correlation_profiles

runner = CliRunner()


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    database = DatabaseManager(db_path=str(tmp_path / "correlate_test.db"))
    database.init()
    # The CLI module holds its own DatabaseManager at import time; point it at
    # the isolated test database for the duration of each test.
    import whisperward
    monkeypatch.setattr(whisperward, "db", database)
    return database


def _seed_case(database, usernames_and_bios):
    case_id = database.create_case("SYNTHETIC correlate test", "synthetic", "pytest")
    for username, bio in usernames_and_bios:
        database.add_target(case_id, "roblox", username)
    targets = database.get_case_targets(case_id)
    for target, (username, bio) in zip(targets, usernames_and_bios):
        database.save_artifact(
            target_id=target["target_id"],
            module_name="RobloxOSINT",
            artifact_type="profile",
            raw_data={"username": username, "platform": "roblox", "description": bio},
        )
    return case_id, targets


class TestCorrelateCommand:
    def test_requires_two_targets(self, test_db):
        case_id, _ = _seed_case(test_db, [("synthetic_lonely_account", "just one")])
        result = runner.invoke(app, ["correlate", "--case", case_id])
        assert result.exit_code == 0
        assert "at least two targets" in result.output

    def test_correlates_and_seals_artifact(self, test_db):
        bio = "building obbies all day, trading limiteds, message me on the other app"
        case_id, targets = _seed_case(test_db, [
            ("synthetic_xX_shadow_Xx", bio),
            ("synthetic_xX_shad0w_Xx", bio),
        ])
        result = runner.invoke(app, ["correlate", "--case", case_id])
        assert result.exit_code == 0
        assert "Pairwise Correlation" in result.output
        assert "Identity groups" in result.output
        assert "sealed as artifact" in result.output

        # The full result must be persisted in the evidence store.
        conn = test_db.get_connection()
        row = conn.execute(
            "SELECT raw_data FROM artifacts WHERE module_name = 'CorrelationEngine'"
        ).fetchone()
        assert row is not None
        payload = json.loads(row["raw_data"])
        assert payload["case_id"] == case_id
        assert len(payload["pairwise"]) == 1
        assert payload["cluster"]["groups"]
        assert payload["semantic_enabled"] is False

        # Human-review framing must survive into the sealed payload.
        assert "qualified human" in payload["pairwise"][0]["disclaimer"]

    def test_profile_builder_uses_only_persisted_artifacts(self, test_db):
        case_id, _ = _seed_case(test_db, [
            ("synthetic_builder_a", "synthetic bio a"),
            ("synthetic_builder_b", ""),
        ])
        profiles = _build_correlation_profiles(case_id, test_db)
        assert len(profiles) == 2
        assert profiles[0].messages == ["synthetic bio a"]
        # Empty description degrades to no messages rather than failing.
        assert profiles[1].messages == []
        assert profiles[0].profile_id.startswith("roblox:")
