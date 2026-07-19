"""
synthetic_profile_generator.py
WhisperWard OSINT — Synthetic Data Pipeline
Pixora Inc. | Phase 4 Milestone 1

Generates entirely fabricated Roblox and Discord profiles for testing
and validation. No real user data is ever used.
"""

import hashlib
import json
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from faker import Faker

fake = Faker()


@dataclass
class SyntheticChatMessage:
    sender: str
    content: str
    timestamp: str
    platform: str


@dataclass
class SyntheticProfile:
    profile_id: str
    profile_type: str
    seed: int
    username: str
    display_name: str
    account_age_days: int
    declared_age: Optional[int]
    platform: str
    friend_count: int
    game_history: list[str]
    activity_timing: list[str]
    avatar_hash: str
    ip_stub: str
    is_tor: bool
    is_vpn: bool
    chat_history: list[SyntheticChatMessage]
    expected_tier: int
    expected_risk_range: tuple[float, float]
    generated_at: str
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "profile_type": self.profile_type,
            "seed": self.seed,
            "username": self.username,
            "display_name": self.display_name,
            "account_age_days": self.account_age_days,
            "declared_age": self.declared_age,
            "platform": self.platform,
            "friend_count": self.friend_count,
            "game_history": self.game_history,
            "activity_timing": self.activity_timing,
            "avatar_hash": self.avatar_hash,
            "ip_stub": self.ip_stub,
            "is_tor": self.is_tor,
            "is_vpn": self.is_vpn,
            "chat_history": [vars(m) for m in self.chat_history],
            "expected_tier": self.expected_tier,
            "expected_risk_range": list(self.expected_risk_range),
            "generated_at": self.generated_at,
            "notes": self.notes,
        }


@dataclass
class SyntheticDataset:
    dataset_id: str
    seed: int
    safe_profiles: list[SyntheticProfile]
    threat_profiles: list[SyntheticProfile]
    edge_profiles: list[SyntheticProfile]
    generated_at: str

    @property
    def all_profiles(self) -> list[SyntheticProfile]:
        return self.safe_profiles + self.threat_profiles + self.edge_profiles

    @property
    def total_count(self) -> int:
        return len(self.all_profiles)

    def to_dict(self) -> dict:
        return {
            "dataset_id": self.dataset_id,
            "seed": self.seed,
            "safe_count": len(self.safe_profiles),
            "threat_count": len(self.threat_profiles),
            "edge_count": len(self.edge_profiles),
            "total_count": self.total_count,
            "generated_at": self.generated_at,
            "profiles": [p.to_dict() for p in self.all_profiles],
        }

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


SAFE_GAME_NAMES = [
    "Adopt Me!", "Brookhaven RP", "Bloxburg", "Tower of Hell",
    "Piggy", "Arsenal", "Jailbreak", "Murder Mystery 2",
    "Royale High", "Pet Simulator X", "Natural Disaster Survival",
    "Work at a Pizza Place", "Lumber Tycoon 2", "Phantom Forces",
]

THREAT_GAME_NAMES = [
    "Condo_Server_2026", "Private_RP_Adults", "18plus_server_xyz",
    "SecretMeet_v3", "PrivateGame_NoKids", "AdultRP_Final",
    "Hidden_Condo_Real", "MatureContent_v2",
]

SAFE_CHAT_MESSAGES = [
    "hey wanna play together?",
    "nice game!",
    "gg everyone",
    "what server are you on?",
    "bro that was so close lol",
    "i need more robux smh",
    "anyone wanna trade?",
    "this game is actually really fun",
    "how do you get that badge?",
    "my favorite game is tower of hell",
]

GROOMING_CHAT_MESSAGES = [
    "hey how old are you?",
    "you seem really mature for your age",
    "lets talk somewhere private",
    "dont tell your parents about this",
    "i can send you robux if you keep talking to me",
    "can you move to discord? its more private",
    "you're really special, not like other kids",
    "this is just between us okay?",
    "do your parents let you stay up late?",
    "i have a special game just for us",
    "whats your real name?",
    "do you have snapchat or instagram?",
    "i really like talking to you, more than anyone else",
    "can you send me a picture?",
]

SAFE_USERNAMES_PREFIXES = [
    "cool", "epic", "gaming", "pro", "super", "mega", "ultra",
    "dark", "light", "fire", "ice", "star", "moon", "sun",
]

SAFE_USERNAMES_SUFFIXES = [
    "gamer", "player", "noob", "master", "ninja", "legend",
    "wizard", "hero", "boss", "king", "queen", "beast",
]

THREAT_USERNAMES_PREFIXES = [
    "adult", "real", "not_a_kid", "grown", "mature", "older",
]

THREAT_USERNAMES_SUFFIXES = [
    "man", "guy", "dude", "bro", "friend", "pal",
]


class SyntheticProfileGenerator:

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)
        Faker.seed(seed)
        self._fake = Faker()

    def generate(
        self,
        profile_type: str,
        count: int,
        platform: str = "roblox",
    ) -> list[SyntheticProfile]:
        if profile_type not in ("safe", "threat", "edge_case"):
            raise ValueError(
                f"Invalid profile_type: {profile_type}. "
                "Must be 'safe', 'threat', or 'edge_case'."
            )
        profiles = []
        for i in range(count):
            profile_seed = self._rng.randint(1000, 999999)
            if profile_type == "safe":
                profile = self._generate_safe(profile_seed, platform, i)
            elif profile_type == "threat":
                profile = self._generate_threat(profile_seed, platform, i)
            else:
                profile = self._generate_edge_case(profile_seed, platform, i)
            profiles.append(profile)
        return profiles

    def generate_balanced_dataset(
        self,
        safe_count: int = 50,
        threat_count: int = 50,
        edge_count: int = 10,
    ) -> SyntheticDataset:
        return SyntheticDataset(
            dataset_id=str(uuid.uuid4()),
            seed=self.seed,
            safe_profiles=self.generate("safe", safe_count),
            threat_profiles=self.generate("threat", threat_count),
            edge_profiles=self.generate("edge_case", edge_count),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _generate_safe(self, seed: int, platform: str, index: int) -> SyntheticProfile:
        rng = random.Random(seed)
        username = (
            rng.choice(SAFE_USERNAMES_PREFIXES)
            + rng.choice(SAFE_USERNAMES_SUFFIXES)
            + str(rng.randint(100, 9999))
        )
        return SyntheticProfile(
            profile_id=f"SYNTH-SAFE-{seed:06d}",
            profile_type="safe",
            seed=seed,
            username=username,
            display_name=username,
            account_age_days=rng.randint(90, 1500),
            declared_age=rng.randint(13, 17),
            platform=platform,
            friend_count=rng.randint(5, 150),
            game_history=rng.choices(SAFE_GAME_NAMES, k=rng.randint(3, 8)),
            activity_timing=self._generate_timing(rng, count=5, late_night=False),
            avatar_hash=self._synthetic_hash(seed, "safe"),
            ip_stub=self._safe_ip(rng),
            is_tor=False,
            is_vpn=False,
            chat_history=self._generate_safe_chat(rng, username, platform),
            expected_tier=1,
            expected_risk_range=(0.0, 3.9),
            generated_at=datetime.now(timezone.utc).isoformat(),
            notes="Standard safe user profile. No threat signals.",
        )

    def _generate_threat(self, seed: int, platform: str, index: int) -> SyntheticProfile:
        rng = random.Random(seed)
        username = (
            rng.choice(THREAT_USERNAMES_PREFIXES)
            + rng.choice(THREAT_USERNAMES_SUFFIXES)
            + str(rng.randint(10, 99))
        )
        return SyntheticProfile(
            profile_id=f"SYNTH-THREAT-{seed:06d}",
            profile_type="threat",
            seed=seed,
            username=username,
            display_name=username,
            account_age_days=rng.randint(1, 30),
            declared_age=rng.choice([None, 25, 28, 31, 35]),
            platform=platform,
            friend_count=rng.randint(200, 800),
            game_history=rng.choices(
                THREAT_GAME_NAMES + SAFE_GAME_NAMES[:3], k=rng.randint(3, 6)
            ),
            activity_timing=self._generate_timing(rng, count=8, late_night=True),
            avatar_hash=self._synthetic_hash(seed, "threat"),
            ip_stub=self._safe_ip(rng),
            is_tor=rng.random() > 0.6,
            is_vpn=rng.random() > 0.4,
            chat_history=self._generate_threat_chat(rng, username, platform),
            expected_tier=3,
            expected_risk_range=(7.0, 10.0),
            generated_at=datetime.now(timezone.utc).isoformat(),
            notes="Threat profile with grooming signals, anonymization, and new account.",
        )

    def _generate_edge_case(self, seed: int, platform: str, index: int) -> SyntheticProfile:
        rng = random.Random(seed)
        username = (
            rng.choice(SAFE_USERNAMES_PREFIXES)
            + str(rng.randint(1, 999))
        )
        return SyntheticProfile(
            profile_id=f"SYNTH-EDGE-{seed:06d}",
            profile_type="edge_case",
            seed=seed,
            username=username,
            display_name=username,
            account_age_days=rng.randint(15, 60),
            declared_age=rng.choice([None, 16, 18, 21]),
            platform=platform,
            friend_count=rng.randint(50, 200),
            game_history=rng.choices(SAFE_GAME_NAMES, k=rng.randint(2, 5)),
            activity_timing=self._generate_timing(rng, count=4, late_night=True),
            avatar_hash=self._synthetic_hash(seed, "edge"),
            ip_stub=self._safe_ip(rng),
            is_tor=False,
            is_vpn=rng.random() > 0.5,
            chat_history=self._generate_edge_chat(rng, username, platform),
            expected_tier=2,
            expected_risk_range=(4.0, 6.9),
            generated_at=datetime.now(timezone.utc).isoformat(),
            notes="Ambiguous profile. Some signals present but not conclusive.",
        )

    def _generate_safe_chat(self, rng, username, platform):
        messages = []
        base_time = datetime.now(timezone.utc) - timedelta(days=rng.randint(1, 30))
        for i in range(rng.randint(3, 8)):
            messages.append(SyntheticChatMessage(
                sender=username,
                content=rng.choice(SAFE_CHAT_MESSAGES),
                timestamp=(base_time + timedelta(minutes=i * rng.randint(5, 60))).isoformat(),
                platform=platform,
            ))
        return messages

    def _generate_threat_chat(self, rng, username, platform):
        messages = []
        base_time = datetime.now(timezone.utc) - timedelta(days=rng.randint(1, 7))
        for i in range(rng.randint(5, 12)):
            content = rng.choice(
                GROOMING_CHAT_MESSAGES if rng.random() > 0.3 else SAFE_CHAT_MESSAGES
            )
            messages.append(SyntheticChatMessage(
                sender=username,
                content=content,
                timestamp=(base_time + timedelta(minutes=i * rng.randint(2, 20))).isoformat(),
                platform=platform,
            ))
        return messages

    def _generate_edge_chat(self, rng, username, platform):
        messages = []
        base_time = datetime.now(timezone.utc) - timedelta(days=rng.randint(5, 20))
        for i in range(rng.randint(3, 7)):
            content = rng.choice(
                GROOMING_CHAT_MESSAGES[:4] if rng.random() > 0.6 else SAFE_CHAT_MESSAGES
            )
            messages.append(SyntheticChatMessage(
                sender=username,
                content=content,
                timestamp=(base_time + timedelta(minutes=i * rng.randint(10, 45))).isoformat(),
                platform=platform,
            ))
        return messages

    def _generate_timing(self, rng, count, late_night):
        timestamps = []
        base = datetime.now(timezone.utc) - timedelta(days=14)
        for _ in range(count):
            hour = rng.choice([22, 23, 0, 1, 2, 3]) if late_night else rng.randint(9, 21)
            ts = base.replace(hour=hour) + timedelta(
                days=rng.randint(0, 14),
                minutes=rng.randint(0, 59),
            )
            timestamps.append(ts.isoformat())
        return sorted(timestamps)

    def _synthetic_hash(self, seed: int, profile_type: str) -> str:
        raw = f"synthetic_{profile_type}_{seed}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def _safe_ip(self, rng) -> str:
        prefix = rng.choice(["192.0.2", "198.51.100", "203.0.113"])
        return f"{prefix}.{rng.randint(1, 254)}"