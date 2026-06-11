# WhisperWard OSINT — Synthetic Test Cases

**Version:** 4.1 | **Last Updated:** June 2026 | **Maintainer:** Pixora Inc.

All profiles below are entirely fabricated. No real users, no real children,
no real predator accounts. These exist solely for validation of the risk engine
and grooming classifier. All usernames, IDs, and chat content are invented.

Tier ranges reflect the June 2026 threshold calibration performed against a
seed-42 balanced synthetic evaluation dataset.

---

## Case 1 — Tier 1 (Monitor Only)

**Profile ID:** SYNTH-SAFE-001
**Expected Risk Score:** 1.2 / 10
**Expected Tier:** Tier 1 — Monitor Only (0.0 to 1.9)

**Profile Summary:**
Synthetic Roblox account with normal usage patterns. Account age of 400 days,
45 friends, active during daytime hours, plays popular public games only.
No anonymization tools detected. No prior flags.

**Chat Content (fabricated):**
"hey wanna play together?", "nice game!", "gg everyone", "what server are you on?",
"bro that was so close lol", "anyone wanna trade?"

**Signal Breakdown:**
- Grooming classifier: 0.0 — no patterns detected
- Cross-platform correlation: 0.0 — single platform only
- Anonymization/IP: 0.0 — no Tor, no VPN
- Behavioral velocity: 0.05 — established account, normal friend rate
- Historical signals: 0.0 — no prior flags

**Expected Outcome:** Case logged for monitoring. No notification generated.
No analyst action required.

---

## Case 2 — Tier 2 (Human Review Required)

**Profile ID:** SYNTH-EDGE-001
**Expected Risk Score:** 5.1 / 10
**Expected Tier:** Tier 2 — Human Review Required (2.0 to 6.9)

**Profile Summary:**
Synthetic account 20 days old with 200 friends, active predominantly late at
night, uses a VPN, present on 3 platforms. Chat history contains age probing,
platform migration pressure, and one secrecy solicitation message. No Tor.
One prior flag in database.

**Chat Content (fabricated):**
"how old are you?", "add me on discord it's more private",
"don't tell your parents", "gg everyone", "what server are you on?"

**Signal Breakdown:**
- Grooming classifier: 0.35 — age probing and platform migration detected
- Cross-platform correlation: 0.7 — present on 3 platforms
- Anonymization/IP: 0.4 — VPN detected, no Tor
- Behavioral velocity: 0.6 — new account, high friend rate, late-night activity
- Historical signals: 0.4 — one prior flag

**Expected Outcome:** Human reviewer notified immediately. Reviewer must
acknowledge within 24 hours. No escalation without explicit reviewer approval.

---

## Case 3 — Tier 3 (Escalate — Evidence Package)

**Profile ID:** SYNTH-THREAT-001
**Expected Risk Score:** 8.7 / 10
**Expected Tier:** Tier 3 — Escalate (7.0 to 10.0)

**Profile Summary:**
Synthetic account 5 days old with 300 friends, active late at night, routing
through both Tor and VPN, present on 4 platforms. Chat history contains
secrecy solicitation, age probing, platform migration pressure, gift incentives,
and isolation language across multiple messages. Two prior flags in database.
Three flagged game titles in history.

**Chat Content (fabricated):**
"don't tell your parents about this", "how old are you?",
"add me on discord it's more private", "i'll give you robux if you keep talking to me",
"keep this just between us okay?", "let's talk somewhere private",
"you seem really mature for your age"

**Signal Breakdown:**
- Grooming classifier: 0.85 — multiple categories, multi-step sequence confirmed
- Cross-platform correlation: 1.0 — present on 4 platforms
- Anonymization/IP: 1.0 — Tor and VPN both active
- Behavioral velocity: 1.0 — 5-day-old account, 60 friends/day rate, late night
- Historical signals: 0.7 — two prior flags

**Expected Outcome:** Evidence package generated automatically. Human sign-off
required before package is filed. NCMEC CyberTipline format pre-populated for
reviewer completion. All actions logged with operator ID and UTC timestamp.

---

## Validation Instructions

To validate these cases against the live risk engine:

```python
from risk_engine import RiskEngine, RiskSignals

engine = RiskEngine()

tier1_signals = RiskSignals(
    chat_messages=["hey wanna play together?", "nice game!", "gg everyone"],
    platform_count=1,
    is_tor=False,
    is_vpn=False,
    account_age_days=400,
    friend_count=45,
    late_night_activity=False,
    game_history_flags=0,
    prior_case_flags=0,
)

result = engine.score(tier1_signals)
print(result.risk_score, result.tier)
```

Run all three synthetic cases through `pytest test_risk_engine.py -v` to confirm
tier assignments are correct on each release.

---

*All content in this document is fabricated for testing purposes only.*
*No real user data was used at any stage of development.*