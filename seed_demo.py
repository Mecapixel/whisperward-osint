#!/usr/bin/env python3
"""
seed_demo.py
WhisperWard OSINT — Demo Seeder
Pixora Inc.

Seeds the database with clearly labeled synthetic demo cases, but only when the
database has no cases of its own. This exists for stateless deployments such as
the free Render tier, whose disk does not persist, so the database is empty on
every start. Without a seed the public demo would show an empty registry.

Everything seeded here is fabricated synthetic data, the same the governance
framework permits for demonstration. No real account and no real person is used.
The cases are identical in spirit to those produced by create_synthetic_case.py,
and they are scored with the structured RiskEngine directly, with no AI step, so
this runs anywhere without a local model. The result is a live demo that shows
the real scoring, the tier progression, and the signals breakdown.

The seeder is idempotent by guard: it does nothing when any case already exists,
so it never disturbs a real working database and never duplicates on restart of
a persistent deployment.
"""

from datetime import datetime, timedelta, timezone


SYNTHETIC_LABEL = "[SYNTHETIC GROOMING DEMO — FABRICATED, FOR TESTING ONLY]"

SYNTHETIC_AVATAR_URL = (
    "https://tr.rbxcdn.com/30DAY-AvatarHeadshot-"
    "44F0F82C4F2991A2E9BBC686FC599724-Png/420/420/AvatarHeadshot/Png/noFilter"
)


def _iso_days_ago(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


GROOMING_LOG = f"""{SYNTHETIC_LABEL}
Message log (fabricated):
Subject: hey, how old are you? you seem mature for your age
Subject: i really like talking to you, you're not like other kids
Subject: what grade are you in?
Subject: maybe we could talk on discord, it's more private there
Subject: let's keep this just between us, don't tell your parents
"""

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


def _roblox_artifact(username, description, account_age_days, friend_count, games):
    return {
        "username": username,
        "platform": "roblox",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "user_id": 0,
        "displayName": username,
        "description": description,
        "created": _iso_days_ago(account_age_days),
        "isBanned": False,
        "avatar_url": SYNTHETIC_AVATAR_URL,
        "friends": [],
        "friend_count": friend_count,
        "groups": [],
        "group_count": 0,
        "games": games,
        "game_count": len(games),
        "synthetic": True,
    }


def _sherlock_artifact(username, platforms_found):
    sites = ["Twitter", "Instagram", "Discord", "Reddit", "TikTok"][:platforms_found]
    return {"username": username, "platforms_found": platforms_found,
            "found_sites": sites, "synthetic": True}


DEMO_VARIANTS = [
    {
        "case_name": "SYNTHETIC — Grooming Pattern Demo (high Tier 2)",
        "username": "synthetic_groomer_demo",
        "description": GROOMING_LOG,
        "account_age_days": 20,
        "friend_count": 90,
        "platforms_found": 2,
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
    },
    {
        "case_name": "SYNTHETIC — Severe Multi-Signal Case (Tier 3)",
        "username": "synthetic_severe_demo",
        "description": SEVERE_LOG,
        "account_age_days": 12,
        "friend_count": 280,
        "platforms_found": 4,
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
    },
]


def seed_if_empty(db) -> bool:
    """Seed synthetic demo cases only when the database has no cases. Returns True
    if seeding ran, False if the database already had cases. Safe to call on every
    startup; it guards itself."""
    try:
        existing = db.get_all_cases()
    except Exception:
        existing = []
    if existing:
        return False

    print("[seed_demo] empty database detected — seeding synthetic demo cases")

    # Import the scorer lazily so a scoring import problem cannot block startup.
    try:
        from modules.risk_scoring import score_target
    except Exception as exc:
        print(f"[seed_demo] could not import scorer, seeding cases without scores: {exc}")
        score_target = None

    conn = db.get_connection()

    for v in DEMO_VARIANTS:
        try:
            case_id = db.create_case(
                v["case_name"],
                f"Fabricated synthetic case for demonstration. {SYNTHETIC_LABEL}",
                "Meca Dismukes",
            )
            db.add_target(case_id, "roblox", v["username"], notes=SYNTHETIC_LABEL)
            targets = db.get_case_targets(case_id)
            target_id = targets[0]["target_id"]

            db.save_artifact(target_id, "RobloxOSINT", "profile",
                             _roblox_artifact(v["username"], v["description"],
                                              v["account_age_days"], v["friend_count"],
                                              v["games"]))
            db.save_artifact(target_id, "SherlockIntegration", "username_correlation",
                             _sherlock_artifact(v["username"], v["platforms_found"]))

            # Score with the structured engine directly. No AI step, so this runs
            # on any host. Persist so the dashboard, gauge, and signals panel
            # have real data.
            if score_target is not None:
                result = score_target(conn, target_id, ai_findings=None)
                db.save_analysis(target_id, result)
                print(f"[seed_demo]   seeded {case_id} -> score {result.get('risk_score')}")
            else:
                print(f"[seed_demo]   seeded {case_id} (unscored)")
        except Exception as exc:
            print(f"[seed_demo]   failed to seed a case: {exc}")

    return True