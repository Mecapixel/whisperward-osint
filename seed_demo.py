#!/usr/bin/env python3
"""
seed_demo.py
WhisperWard OSINT — Demo Seeder
Pixora Inc.

Seeds the database with clearly labeled synthetic demo cases, but only when the
database has no cases of its own. This exists for stateless deployments such as
the free Render tier, whose disk does not persist, so the database is empty on
every start. Without a seed the public demo would show an empty registry.

Everything seeded here is fabricated synthetic data, the kind the governance
framework permits for demonstration. No real account and no real person is used.

Design note: rather than run the risk engine at startup, this seeder writes the
known, pre-computed scoring result for each synthetic case directly. The cases
are fixed, so their structured scores are fixed too; recomputing them on every
cold start would add a failure point on a constrained host for no benefit. The
findings written here are the genuine RiskEngine output captured from a local
run, so the dashboard, gauge, and signals panel display real, accurate data.
This makes the seeder dependency-free and robust on any host.

The seeder is idempotent by guard: it does nothing when any case already exists,
so it never disturbs a real working database and never duplicates on restart.
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


# Pre-computed RiskEngine findings, captured from a local scoring run. These are
# the genuine structured outputs for the two fixed synthetic cases. Seeding them
# directly avoids running the engine at startup on a constrained host.
GROOMING_FINDINGS = {
    "engine": "RiskEngine",
    "tier": 2,
    "tier_label": "Human Review Required",
    "components": [
        {"name": "grooming_classifier", "weight": 0.4, "raw_score": 0.6333,
         "weighted_score": 0.2533,
         "explanation": "strong grooming language pattern detected across multiple categories"},
        {"name": "cross_platform_correlation", "weight": 0.25, "raw_score": 0.4,
         "weighted_score": 0.1, "explanation": "username present on 2 platforms"},
        {"name": "anonymization_ip", "weight": 0.15, "raw_score": 0.0,
         "weighted_score": 0.0, "explanation": "no anonymization tools detected"},
        {"name": "behavioral_velocity", "weight": 0.1, "raw_score": 0.3,
         "weighted_score": 0.03, "explanation": "account is 20 days old"},
        {"name": "historical_signals", "weight": 0.1, "raw_score": 0.0,
         "weighted_score": 0.0, "explanation": "no prior flags in database"},
    ],
    "top_signals": [
        "strong grooming language pattern detected across multiple categories",
        "username present on 2 platforms",
        "account is 20 days old",
        "secrecy solicitation detected (2 instances)",
        "platform migration pressure detected (2 instances)",
    ],
    "explanation": ("Moderate risk — human review required within 24 hours. "
                    "Primary signal: strong grooming language pattern detected "
                    "across multiple categories"),
}

SEVERE_FINDINGS = {
    "engine": "RiskEngine",
    "tier": 3,
    "tier_label": "Escalate — Evidence Package",
    "components": [
        {"name": "grooming_classifier", "weight": 0.4, "raw_score": 1.0,
         "weighted_score": 0.4,
         "explanation": "strong grooming language pattern detected across multiple categories"},
        {"name": "cross_platform_correlation", "weight": 0.25, "raw_score": 1.0,
         "weighted_score": 0.25,
         "explanation": "username present on 4 platforms — high cross-platform footprint"},
        {"name": "anonymization_ip", "weight": 0.15, "raw_score": 0.0,
         "weighted_score": 0.0, "explanation": "no anonymization tools detected"},
        {"name": "behavioral_velocity", "weight": 0.1, "raw_score": 0.7,
         "weighted_score": 0.07,
         "explanation": "account is 12 days old; high friend acquisition rate (23.3/day)"},
        {"name": "historical_signals", "weight": 0.1, "raw_score": 0.0,
         "weighted_score": 0.0, "explanation": "no prior flags in database"},
    ],
    "top_signals": [
        "strong grooming language pattern detected across multiple categories",
        "username present on 4 platforms — high cross-platform footprint",
        "account is 12 days old; high friend acquisition rate (23.3/day)",
        "age probing detected (3 instances)",
        "secrecy solicitation detected (2 instances)",
    ],
    "explanation": ("High risk — evidence package generated. Human sign-off "
                    "required before any filing. Primary signal: strong grooming "
                    "language pattern detected across multiple categories"),
}


DEMO_VARIANTS = [
    {
        "case_name": "SYNTHETIC — Grooming Pattern Demo (high Tier 2)",
        "username": "synthetic_groomer_demo",
        "description": GROOMING_LOG,
        "account_age_days": 20,
        "friend_count": 90,
        "platforms_found": 2,
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
        "risk_score": 4.83,
        "findings": GROOMING_FINDINGS,
    },
    {
        "case_name": "SYNTHETIC — Severe Multi-Signal Case (Tier 3)",
        "username": "synthetic_severe_demo",
        "description": SEVERE_LOG,
        "account_age_days": 12,
        "friend_count": 280,
        "platforms_found": 4,
        "games": [{"name": "Synthetic Demo Place", "place_visits": 0}],
        "risk_score": 8.2,
        "findings": SEVERE_FINDINGS,
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

            # Write the known, pre-computed structured result directly. A copy of
            # the findings is made and stamped with the scoring time, so each
            # seeded record carries its own timestamp.
            findings = dict(v["findings"])
            findings["scored_at"] = datetime.now(timezone.utc).isoformat()
            result = {
                "analysis_type": "risk_engine_v1",
                "risk_score": v["risk_score"],
                "findings": findings,
                "notes": "Seeded synthetic demo case (pre-computed RiskEngine result).",
            }
            db.save_analysis(target_id, result)
            print(f"[seed_demo]   seeded {case_id} -> score {v['risk_score']}")
        except Exception as exc:
            print(f"[seed_demo]   failed to seed a case: {exc}")

    return True