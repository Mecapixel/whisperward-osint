#!/usr/bin/env python3
"""
create_synthetic_case.py
WhisperWard OSINT — Synthetic Case Generator (development / demo tool)
Pixora Inc.

Creates clearly labeled synthetic cases for testing and demonstration. Every
case, target, and message produced here is fabricated. No real account, no real
minor, and no real chat log is ever used. This is the synthetic data the
governance framework permits for development and demonstration.

The generator exists because real burner accounts are deliberately empty and
therefore score near zero, which does not exercise the risk engine across its
range. A synthetic grooming case lets a reviewer see the engine escalate, and
gives a stable fixture for regression testing as weights are refined.

The fabricated chat is stored in the target's profile description so the existing
scoring bridge reads it without modification. It is prefixed with a synthetic
label so it can never be mistaken for collected data.

Usage:
    python create_synthetic_case.py --type grooming    # high Tier 2 demo
    python create_synthetic_case.py --type subtle       # edge case, softer signals
    python create_synthetic_case.py --type clean        # low-risk baseline
    python create_synthetic_case.py --type all          # create all three

After creation, score it through the normal pipeline:
    python whisperward.py analyze --case CASE-XXXXXXXX --ai
"""

import argparse
from datetime import datetime, timedelta, timezone

from database import DatabaseManager


SYNTHETIC_LABEL = "[SYNTHETIC GROOMING DEMO — FABRICATED, FOR TESTING ONLY]"

# A real Roblox avatar image, used purely so the synthetic demo case renders an
# avatar instead of a blank placeholder. This is a direct CDN image URL from an
# investigator-owned burner account, so it displays in an img tag. The URL is a
# 30-day signed CDN link; refresh it if it ever stops resolving. The case itself
# remains clearly labeled synthetic.
SYNTHETIC_AVATAR_URL = (
    "https://tr.rbxcdn.com/30DAY-AvatarHeadshot-"
    "44F0F82C4F2991A2E9BBC686FC599724-Png/420/420/AvatarHeadshot/Png/noFilter"
)


def _iso_days_ago(days: int) -> str:
    """Return an ISO 8601 timestamp `days` in the past, for a young synthetic
    account age that the velocity component will read."""
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# Fabricated message logs. These are invented to exercise the classifier's
# pattern categories. They are not derived from any real conversation.

SEVERE_LOG = f"""{SYNTHETIC_LABEL}
Message log (fabricated):
Subject: hey, how old are you? you seem really mature for your age
Subject: you're so much more grown up than other kids i talk to
Subject: i really like talking to you, you're special to me
Subject: do your parents let you stay up late? what grade are you in?
Subject: this can be just between us, don't tell your parents okay
Subject: let's move to discord where we can talk more privately
Subject: add me on discord so it's just the two of us
Subject: if you send me a pic i'll give you some robux
Subject: keep this our little secret, they wouldn't understand
"""

GROOMING_LOG = f"""{SYNTHETIC_LABEL}
Message log (fabricated):
Subject: hey, how old are you? you seem mature for your age
Subject: i really like talking to you, you're not like other kids
Subject: what grade are you in?
Subject: maybe we could talk on discord, it's more private there
Subject: let's keep this just between us, don't tell your parents
"""

SUBTLE_LOG = f"""{SYNTHETIC_LABEL}
Message log (fabricated):
Subject: you seem really mature for your age
Subject: i like talking to you, you're different
Subject: maybe we could talk somewhere more private sometime
Subject: what grade are you in by the way?
"""

CLEAN_LOG = f"""{SYNTHETIC_LABEL}
Message log (fabricated):
Subject: gg that round was so close
Subject: anyone want to team up for the next game?
Subject: nice build, how long did that take you
"""


def _build_roblox_artifact(username: str, description: str, account_age_days: int,
                           friend_count: int, games: list, groups: list) -> dict:
    """Shape a synthetic artifact like the RobloxOSINT collector would produce,
    so the scoring bridge reads it through the normal path."""
    return {
        "username": username,
        "platform": "roblox",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "user_id": 0,  # synthetic, no real account
        "displayName": username,
        "description": description,
        "created": _iso_days_ago(account_age_days),
        "isBanned": False,
        "avatar_url": SYNTHETIC_AVATAR_URL,
        "friends": [],
        "friend_count": friend_count,
        "groups": groups,
        "group_count": len(groups),
        "games": games,
        "game_count": len(games),
        "synthetic": True,
    }


def _build_sherlock_artifact(username: str, platforms_found: int) -> dict:
    """Shape a synthetic Sherlock-style artifact for the cross-platform signal."""
    sites = ["Twitter", "Instagram", "Discord", "Reddit", "TikTok"][:platforms_found]
    return {
        "username": username,
        "platforms_found": platforms_found,
        "found_sites": sites,
        "synthetic": True,
    }


VARIANTS = {
    "grooming": {
        "case_name": "SYNTHETIC — Grooming Pattern Demo (high Tier 2)",
        "username": "synthetic_groomer_demo",
        "description": GROOMING_LOG,
        "account_age_days": 20,      # young-ish account -> some velocity
        "friend_count": 90,          # moderate network
        "platforms_found": 2,        # two platforms -> partial cross_platform
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
        "groups": [],
    },
    "severe": {
        "case_name": "SYNTHETIC — Severe Multi-Signal Case (Tier 3)",
        "username": "synthetic_severe_demo",
        "description": SEVERE_LOG,
        "account_age_days": 12,      # very young -> strong velocity
        "friend_count": 280,         # high friend network on a new account
        "platforms_found": 4,        # full cross-platform footprint
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
        "groups": [],
    },
    "subtle": {
        "case_name": "SYNTHETIC — Subtle Grooming Edge Case",
        "username": "synthetic_subtle_demo",
        "description": SUBTLE_LOG,
        "account_age_days": 45,
        "friend_count": 60,
        "platforms_found": 2,
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
        "groups": [],
    },
    "clean": {
        "case_name": "SYNTHETIC — Clean Low-Risk Baseline",
        "username": "synthetic_clean_demo",
        "description": CLEAN_LOG,
        "account_age_days": 800,
        "friend_count": 30,
        "platforms_found": 1,
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
        "groups": [],
    },
}


def create_variant(db: DatabaseManager, key: str) -> str:
    v = VARIANTS[key]
    case_id = db.create_case(
        v["case_name"],
        f"Fabricated synthetic case for testing and demonstration. {SYNTHETIC_LABEL}",
        "Meca Dismukes",
    )
    db.add_target(case_id, "roblox", v["username"], notes=SYNTHETIC_LABEL)
    targets = db.get_case_targets(case_id)
    target_id = targets[0]["target_id"]

    roblox_artifact = _build_roblox_artifact(
        v["username"], v["description"], v["account_age_days"],
        v["friend_count"], v["games"], v["groups"],
    )
    db.save_artifact(target_id, "RobloxOSINT", "profile", roblox_artifact)

    sherlock_artifact = _build_sherlock_artifact(v["username"], v["platforms_found"])
    db.save_artifact(target_id, "SherlockIntegration", "username_correlation", sherlock_artifact)

    print(f"  Created {key:9s} -> {case_id}  (target_id={target_id})")
    return case_id


def main():
    parser = argparse.ArgumentParser(description="Create clearly labeled synthetic WhisperWard cases.")
    parser.add_argument("--type", choices=["grooming", "severe", "subtle", "clean", "all"],
                        default="grooming", help="Which synthetic variant to create.")
    args = parser.parse_args()

    db = DatabaseManager()

    print("Creating synthetic case(s). All data is fabricated for testing only.")
    if args.type == "all":
        created = [create_variant(db, k) for k in ("grooming", "severe", "subtle", "clean")]
    else:
        created = [create_variant(db, args.type)]

    print("\nDone. Score a case through the normal pipeline to see the result:")
    for cid in created:
        print(f"  python whisperward.py analyze --case {cid} --ai")


if __name__ == "__main__":
    main()