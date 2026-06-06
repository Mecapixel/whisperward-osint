import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PatternCategory(str, Enum):
    ISOLATION_LANGUAGE = "isolation_language"
    SECRECY_SOLICITATION = "secrecy_solicitation"
    COMPLIMENT_ESCALATION = "compliment_escalation"
    AGE_PROBING = "age_probing"
    GIFT_INCENTIVE = "gift_incentive"
    PLATFORM_MIGRATION = "platform_migration"
    IDENTITY_PROBING = "identity_probing"
    TRUST_BUILDING = "trust_building"


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    ESCALATE = "escalate"


PATTERN_WEIGHTS = {
    PatternCategory.SECRECY_SOLICITATION: 0.24,
    PatternCategory.PLATFORM_MIGRATION: 0.18,
    PatternCategory.AGE_PROBING: 0.16,
    PatternCategory.ISOLATION_LANGUAGE: 0.14,
    PatternCategory.IDENTITY_PROBING: 0.10,
    PatternCategory.GIFT_INCENTIVE: 0.10,
    PatternCategory.COMPLIMENT_ESCALATION: 0.05,
    PatternCategory.TRUST_BUILDING: 0.03,
}

GROOMING_PATTERNS = {
    PatternCategory.ISOLATION_LANGUAGE: [
        r"\b(let'?s|let us)\s+(talk|chat|hang)\s+(somewhere\s+)?private\b",
        r"\bjust\s+(the\s+two\s+of\s+us|us)\b",
        r"\bdon'?t\s+(tell|let)\s+(anyone|your\s+(parents?|mom|dad|friends?))\b",
        r"\bour\s+(little\s+)?secret\b",
        r"\bnobody\s+(needs?\s+to\s+)?know\b",
        r"\bkeep\s+(this|it)\s+(between\s+us|quiet|secret)\b",
        r"\baway\s+from\s+(everyone|the\s+others?|the\s+group)\b",
    ],
    PatternCategory.SECRECY_SOLICITATION: [
        r"\bdon'?t\s+tell\s+your\s+(parents?|mom|dad|family|guardians?)\b",
        r"\bkeep\s+this\s+(a\s+)?secret\b",
        r"\bjust\s+between\s+(you\s+and\s+me|us)\b",
        r"\bif\s+you\s+tell\s+(anyone|them)\b",
        r"\bthis\s+is\s+(just\s+)?between\s+us\b",
        r"\byour\s+(parents?|family)\s+wouldn'?t\s+understand\b",
        r"\bthey\s+wouldn'?t\s+get\s+it\b",
    ],
    PatternCategory.COMPLIMENT_ESCALATION: [
        r"\byou'?re\s+(so\s+)?(mature|grown\s+up|different|special|not\s+like\s+other\s+kids)\b",
        r"\bfor\s+your\s+age\b",
        r"\byou\s+(seem|look|act)\s+(older|more\s+mature)\b",
        r"\byou'?re\s+so\s+(pretty|beautiful|cute|hot|attractive)\b",
        r"\bi\s+(really\s+)?like\s+(talking\s+to\s+)?you\b",
        r"\byou'?re\s+special\s+to\s+me\b",
        r"\bi'?ve\s+never\s+(met|talked\s+to)\s+(anyone|someone)\s+like\s+you\b",
    ],
    PatternCategory.AGE_PROBING: [
        r"\bhow\s+old\s+are\s+you\b",
        r"\bwhat'?s\s+your\s+age\b",
        r"\bare\s+you\s+(really\s+)?\d+\b",
        r"\byou\s+don'?t\s+seem\s+\d+\b",
        r"\bdo\s+your\s+parents?\s+(let|allow)\b",
        r"\bwhat\s+grade\s+are\s+you\s+in\b",
        r"\bdo\s+you\s+go\s+to\s+(school|college)\b",
        r"\bare\s+you\s+in\s+(middle|high)\s+school\b",
    ],
    PatternCategory.GIFT_INCENTIVE: [
        r"\bi'?ll\s+(give|send|buy)\s+you\s+(robux|v-?bucks|gift\s+cards?|money|presents?)\b",
        r"\bfree\s+robux\b",
        r"\bi\s+can\s+(get|buy|send)\s+you\b",
        r"\bif\s+you\s+(do|send|give)\s+.{0,30}(i'?ll\s+(give|send|buy))\b",
        r"\breward\s+you\b",
        r"\brobux\s+for\b",
        r"\bgift\s+card\s+if\b",
    ],
    PatternCategory.PLATFORM_MIGRATION: [
        r"\b(add|find|follow)\s+me\s+on\s+(discord|snapchat|instagram|telegram|whatsapp|kik|signal)\b",
        r"\b(move|go|switch|talk)\s+(to|on)\s+(discord|snapchat|instagram|telegram|whatsapp|kik)\b",
        r"\bmy\s+(discord|snap|insta|telegram)\s+(is|tag|username|handle)\b",
        r"\bdm\s+me\s+on\b",
        r"\bmore\s+private\s+(on|there)\b",
        r"\bbetter\s+(on|there)\s+(discord|snap)\b",
    ],
    PatternCategory.IDENTITY_PROBING: [
        r"\bwhat'?s\s+your\s+(real\s+)?(name|address|school|location|city|phone)\b",
        r"\bwhere\s+do\s+you\s+(live|go\s+to\s+school)\b",
        r"\bdo\s+you\s+have\s+(a\s+phone|snapchat|instagram)\b",
        r"\bcan\s+you\s+(send|share)\s+(me\s+)?(a\s+)?(photo|pic|picture|selfie)\b",
        r"\bsend\s+(me\s+)?(a\s+)?(photo|pic|picture|selfie)\b",
        r"\bwhat\s+do\s+you\s+look\s+like\b",
    ],
    PatternCategory.TRUST_BUILDING: [
        r"\bi\s+(really\s+)?trust\s+you\b",
        r"\byou\s+can\s+trust\s+me\b",
        r"\bi\s+understand\s+you\b",
        r"\bno\s+one\s+else\s+(understands?|gets?\s+it)\b",
        r"\bwe\s+have\s+(such\s+a\s+)?special\s+(connection|bond|relationship)\b",
        r"\bi'?m\s+(not\s+like\s+)?other\s+(guys?|people|adults?)\b",
    ],
}

NEGATION_PATTERNS = [
    r"\bdo\s+not\s+groom\b",
    r"\bnot\s+grooming\b",
    r"\bchild\s+protection\b",
    r"\bsafety\s+training\b",
    r"\breport\s+to\s+cybertip\b",
    r"\bthis\s+is\s+an?\s+example\b",
    r"\beducational\b",
    r"\btraining\b",
]


@dataclass(frozen=True)
class PatternMatch:
    category: PatternCategory
    pattern: str
    matched_text: str
    position: int
    message_index: int


@dataclass
class ClassifierResult:
    grooming_score: float
    detected_patterns: list[PatternMatch]
    category_scores: dict[str, float]
    top_signals: list[str]
    message_count: int
    flagged_message_count: int
    decision: Decision
    analysis_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "grooming_score": round(self.grooming_score, 4),
            "detected_patterns": [
                {
                    "category": p.category.value,
                    "matched_text": p.matched_text,
                    "position": p.position,
                    "message_index": p.message_index,
                }
                for p in self.detected_patterns
            ],
            "category_scores": {k: round(v, 4) for k, v in self.category_scores.items()},
            "top_signals": self.top_signals,
            "message_count": self.message_count,
            "flagged_message_count": self.flagged_message_count,
            "decision": self.decision.value,
            "analysis_notes": self.analysis_notes,
        }


class Thresholds:
    review: float = 0.25
    escalate: float = 0.55


class GroomingClassifier:
    def __init__(self, thresholds: Optional[Thresholds] = None):
        self.thresholds = thresholds or Thresholds()
        self._compiled_patterns = {
            cat: [re.compile(p, re.IGNORECASE | re.UNICODE) for p in patterns]
            for cat, patterns in GROOMING_PATTERNS.items()
        }
        self._compiled_negations = [
            re.compile(p, re.IGNORECASE | re.UNICODE) for p in NEGATION_PATTERNS
        ]

    def classify_text(self, text: str) -> ClassifierResult:
        return self._analyze([text])

    def classify_messages(self, messages: list[str]) -> ClassifierResult:
        return self._analyze(messages)

    def classify_profile(
        self,
        chat_messages: list[str],
        account_age_days: Optional[int] = None,
        friend_count: Optional[int] = None,
        is_new_account: bool = False,
    ) -> ClassifierResult:
        result = self._analyze(chat_messages)
        boost = self._behavior_boost(account_age_days, friend_count, is_new_account)
        result.grooming_score = min(1.0, result.grooming_score + boost)
        result.decision = self._decide(
            result.grooming_score, result.flagged_message_count, result.message_count
        )
        if boost > 0:
            note = "velocity signals applied"
            result.analysis_notes = (
                f"{result.analysis_notes}; {note}" if result.analysis_notes else note
            )
        return result

    def _behavior_boost(
        self,
        account_age_days: Optional[int],
        friend_count: Optional[int],
        is_new_account: bool,
    ) -> float:
        boost = 0.0
        if account_age_days is not None and friend_count is not None:
            if account_age_days < 30 and friend_count > 100:
                boost += 0.12
            if is_new_account and friend_count > 200:
                boost += 0.08
        return boost

    def _decide(self, score: float, flagged_messages: int, total_messages: int) -> Decision:
        if total_messages < 2:
            return Decision.ALLOW if score < self.thresholds.escalate else Decision.REVIEW
        if score >= self.thresholds.escalate and flagged_messages >= 2:
            return Decision.ESCALATE
        if score >= self.thresholds.review:
            return Decision.REVIEW
        return Decision.ALLOW

    def _analyze(self, messages: list[str]) -> ClassifierResult:
        all_matches: list[PatternMatch] = []
        category_hit_counts: dict[PatternCategory, int] = {cat: 0 for cat in PatternCategory}
        flagged_count = 0

        for i, message in enumerate(messages):
            if self._is_negated_context(message):
                continue

            message_matched = False
            for category, compiled_list in self._compiled_patterns.items():
                for pattern in compiled_list:
                    for match in pattern.finditer(message):
                        all_matches.append(
                            PatternMatch(
                                category=category,
                                pattern=pattern.pattern,
                                matched_text=match.group(0),
                                position=match.start(),
                                message_index=i,
                            )
                        )
                        category_hit_counts[category] += 1
                        message_matched = True

            if message_matched:
                flagged_count += 1

        category_scores: dict[str, float] = {}
        raw_score = 0.0

        for category, weight in PATTERN_WEIGHTS.items():
            hits = category_hit_counts[category]
            normalized = min(1.0, hits / 3.0)
            contribution = normalized * weight
            category_scores[category.value] = contribution
            raw_score += contribution

        sequence_bonus = self._sequence_bonus(all_matches)
        grooming_score = min(1.0, raw_score + sequence_bonus)

        top_signals = self._build_top_signals(category_scores, category_hit_counts)

        notes = []
        if sequence_bonus > 0:
            notes.append("multi-step pattern sequence detected")
        if flagged_count > 0 and flagged_count < len(messages) and len(messages) >= 5:
            notes.append("pattern spread across multiple messages")

        return ClassifierResult(
            grooming_score=grooming_score,
            detected_patterns=all_matches,
            category_scores=category_scores,
            top_signals=top_signals,
            message_count=len(messages),
            flagged_message_count=flagged_count,
            decision=self._decide(grooming_score, flagged_count, len(messages)),
            analysis_notes="; ".join(notes),
        )

    def _is_negated_context(self, message: str) -> bool:
        return any(p.search(message) for p in self._compiled_negations)

    def _sequence_bonus(self, matches: list[PatternMatch]) -> float:
        cats = {m.category for m in matches}
        if {
            PatternCategory.AGE_PROBING,
            PatternCategory.PLATFORM_MIGRATION,
            PatternCategory.SECRECY_SOLICITATION,
        }.issubset(cats):
            return 0.15
        if {
            PatternCategory.COMPLIMENT_ESCALATION,
            PatternCategory.TRUST_BUILDING,
            PatternCategory.IDENTITY_PROBING,
        }.issubset(cats):
            return 0.08
        if len(cats) >= 4:
            return 0.10
        return 0.0

    def _build_top_signals(
        self,
        category_scores: dict[str, float],
        hit_counts: dict[PatternCategory, int],
    ) -> list[str]:
        signal_labels = {
            PatternCategory.SECRECY_SOLICITATION: "secrecy solicitation detected",
            PatternCategory.PLATFORM_MIGRATION: "platform migration pressure detected",
            PatternCategory.AGE_PROBING: "age probing detected",
            PatternCategory.ISOLATION_LANGUAGE: "isolation language detected",
            PatternCategory.GIFT_INCENTIVE: "gift or incentive offers detected",
            PatternCategory.COMPLIMENT_ESCALATION: "compliment escalation detected",
            PatternCategory.IDENTITY_PROBING: "identity and location probing detected",
            PatternCategory.TRUST_BUILDING: "trust-building language detected",
        }

        active = [(cat, score) for cat, score in category_scores.items() if score > 0]
        active.sort(key=lambda x: x[1], reverse=True)

        signals = []
        for cat_str, _ in active[:5]:
            cat = PatternCategory(cat_str)
            hits = hit_counts[cat]
            signals.append(
                f"{signal_labels[cat]} ({hits} instance{'s' if hits != 1 else ''})"
            )
        return signals