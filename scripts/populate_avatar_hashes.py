"""
correlation_engine.py
WhisperWard OSINT — Cross-Platform Correlation Engine
Pixora Inc. | Phase 4 Milestone 3

Fuses five independent identity signals into a single correlation
confidence with a structured rationale. The engine never asserts that
two profiles are the same person. It emits a correlation strength and
the evidence trail behind it, for a human analyst to confirm.

Signals fused:
    Username similarity (RapidFuzz, rarity-weighted)
    Writing style fingerprint (stylometry fused with semantic embedding)
    Activity timing correlation (rarity-weighted by hour)
    Friend network overlap (NetworkX, inverse-degree weighted)
    Avatar perceptual hash match (phash and dhash agreement)

Design principles:
    Rarity weighting lives in one helper and is reused everywhere.
    Weak or common signals contribute near-zero evidence.
    Stylometry blends topic-independent style features with a semantic
        embedding so neither dominates, and reports a confidence interval.
    Conflicting signals can subtract confidence, not only add it.
    Pairwise scores feed entity clustering across N profiles.
    Correlation operates only on data already collected in-case.

All development and testing uses synthetic profiles only.
No real user data is used at any stage.

Usage:
    engine = CorrelationEngine()
    result = engine.correlate(profile_a, profile_b)
    print(result.correlation_strength, result.rationale)

    cluster = engine.cluster_identities([p1, p2, p3, p4])
    print(cluster.groups)
"""

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rapidfuzz import fuzz


# ─────────────────────────────────────────────
# Optional heavy dependencies
# ─────────────────────────────────────────────
# networkx and sentence-transformers are imported lazily so the module
# can be imported and unit-tested without the model downloads. Each
# capability degrades gracefully when its library is unavailable.

try:
    import networkx as nx
    _HAS_NETWORKX = True
except ImportError:
    _HAS_NETWORKX = False

try:
    import sentence_transformers  # noqa: F401
    _HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    _HAS_SENTENCE_TRANSFORMERS = False


# ─────────────────────────────────────────────
# Signal weights
# ─────────────────────────────────────────────
# These weights govern how much each signal can contribute to the fused
# correlation strength. They are kept in one place so they can be tuned
# against labeled synthetic data without touching the scoring logic.
# They sum to 1.0.

SIGNAL_WEIGHTS = {
    "username": 0.25,
    "stylometry": 0.25,
    "timing": 0.15,
    "network": 0.25,
    "avatar": 0.10,
}

# A profile pair must clear this fused strength before the engine
# reports it as a correlation lead worth analyst attention.
CORRELATION_LEAD_THRESHOLD = 0.45

# Minimum number of messages required before stylometry is trusted.
# Below this, the stylometry signal returns reduced confidence and a
# wider confidence interval rather than guessing.
STYLOMETRY_MIN_MESSAGES = 5

# Blend of topic-independent style versus semantic embedding inside the
# stylometry signal. Style is weighted higher because semantic embeddings
# cluster by topic, so two different people discussing the same subject
# can look similar regardless of who they are.
STYLE_BLEND = 0.65
SEMANTIC_BLEND = 0.35

# Embedding model. Matches the model used elsewhere in WhisperWard for
# consistency. Loaded lazily and only once per process.
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# Known default or placeholder avatar hashes are excluded from avatar
# matching so that everyone sharing the platform default does not
# correlate with everyone else. This list is populated per deployment.
DEFAULT_AVATAR_HASHES = {
    "400669d4d4cc0b40",
    "408e69d4d4cc0bc0",
    "608e69d4d4cc0b54",
    "7079f8ecf4ccf8b6",
    "93ce6c3184cedb64",
    "967869c724c7662d",
    "c39e2c61919ecf64",
    "c3ce3c71918fda30",
    "c3cf3c30919bce61",
    "c78e3c61919acf61",
    "d38e2c71949ecb64",
}


# ─────────────────────────────────────────────
# Embedding model and cache
# ─────────────────────────────────────────────
# The sentence-transformer model is expensive to load and embeddings are
# recomputed constantly during testing, so the model is loaded once and
# embeddings are cached by a hash of the joined message text.

_EMBEDDING_MODEL = None
_EMBEDDING_CACHE: dict = {}


def _get_embedding_model():
    """
    Load the sentence-transformer model once per process and reuse it.
    Returns None if sentence-transformers is not installed.
    """
    global _EMBEDDING_MODEL
    if not _HAS_SENTENCE_TRANSFORMERS:
        return None
    if _EMBEDDING_MODEL is None:
        from sentence_transformers import SentenceTransformer
        _EMBEDDING_MODEL = SentenceTransformer(EMBEDDING_MODEL_NAME)
    return _EMBEDDING_MODEL


def semantic_embedding(messages: list[str]):
    """
    Return a cached semantic embedding for a set of messages, or None if
    embeddings are unavailable or there is no content. The cache key is a
    hash of the joined messages so repeated calls during testing are free.
    """
    if not messages or not _HAS_SENTENCE_TRANSFORMERS:
        return None

    joined = "\n".join(messages)
    key = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    if key in _EMBEDDING_CACHE:
        return _EMBEDDING_CACHE[key]

    model = _get_embedding_model()
    if model is None:
        return None

    vector = model.encode(joined, convert_to_numpy=True)
    _EMBEDDING_CACHE[key] = vector
    return vector


def clear_embedding_cache():
    """Empty the embedding cache. Useful between large test runs."""
    _EMBEDDING_CACHE.clear()


def _cosine_numpy(vec_a, vec_b) -> float:
    """
    Cosine similarity between two numpy vectors, mapped to 0.0 to 1.0.
    Returns 0.0 for missing vectors or zero magnitude.
    """
    if vec_a is None or vec_b is None:
        return 0.0
    import numpy as np
    denom = float(np.linalg.norm(vec_a) * np.linalg.norm(vec_b))
    if denom == 0.0:
        return 0.0
    raw = float(np.dot(vec_a, vec_b) / denom)
    # Map cosine range -1..1 into 0..1 so it composes with the other signals.
    return max(0.0, min(1.0, (raw + 1.0) / 2.0))


# ─────────────────────────────────────────────
# Rarity weighting helper
# ─────────────────────────────────────────────

COMMON_HANDLE_TOKENS = {
    "gamer", "player", "pro", "noob", "official", "real", "the",
    "xx", "yt", "ttv", "king", "queen", "boss", "god", "lord",
    "cool", "epic", "super", "mega", "ultra", "best", "top",
}


def string_entropy(text: str) -> float:
    """
    Shannon entropy of a string in bits per character. Higher entropy
    means a more distinctive, less guessable string. Returns 0.0 for
    empty input.
    """
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def handle_rarity(handle: str) -> float:
    """
    Estimate how distinctive a username is on a 0.0 to 1.0 scale.

    A high score means the handle is rare and therefore strong evidence
    when it matches. A low score means the handle is common and a match
    tells us little. The estimate combines character entropy, length,
    and a penalty for dictionary-word and common-handle tokens.
    """
    if not handle:
        return 0.0

    normalized = handle.lower()

    entropy = string_entropy(normalized)
    entropy_factor = min(1.0, entropy / 4.0)

    length_factor = min(1.0, len(normalized) / 12.0)

    token_penalty = 0.0
    for token in COMMON_HANDLE_TOKENS:
        if token in normalized:
            token_penalty += 0.4
    token_penalty = min(0.85, token_penalty)

    digit_run = re.search(r"\d{3,}", normalized)
    digit_penalty = 0.25 if digit_run else 0.0

    rarity = (entropy_factor * 0.6 + length_factor * 0.4)
    rarity = rarity * (1.0 - token_penalty) * (1.0 - digit_penalty)

    return max(0.0, min(1.0, rarity))


def inverse_degree_weight(shared_degree: int) -> float:
    """
    Weight a shared connection by the inverse of its degree. Sharing a
    massive public account is near-zero evidence. Sharing membership in
    a small private group is highly distinctive. Degree is the number of
    accounts connected to the shared node.
    """
    if shared_degree <= 1:
        return 1.0
    return 1.0 / math.log2(shared_degree + 1)


def hour_rarity(hour: int) -> float:
    """
    Weight an activity hour by how unusual it is. Evening hours are common
    and near-zero evidence. Deep overnight hours are rarer and more
    distinctive when two profiles share them. Hour is 0 to 23 in the
    profile's recorded timezone.
    """
    common_evening = {18, 19, 20, 21, 22}
    daytime = {9, 10, 11, 12, 13, 14, 15, 16, 17}
    overnight = {0, 1, 2, 3, 4, 5}

    if hour in common_evening:
        return 0.2
    if hour in daytime:
        return 0.4
    if hour in overnight:
        return 1.0
    return 0.6


# ─────────────────────────────────────────────
# Profile input
# ─────────────────────────────────────────────

@dataclass
class CorrelationProfile:
    """
    Normalized view of a single profile for correlation. Built from
    artifacts already collected in-case. The engine never collects new
    data to populate this.

    profile_id: unique identifier for this profile within the case
    platform: source platform, for example roblox or discord
    username: the account handle
    messages: list of platform-surfaced message strings
    active_hours: list of integer hours 0 to 23 when the account is active
    connections: set of connection identifiers, friends or followers
    connection_degrees: map of connection id to its total degree
    avatar_phash: perceptual hash string from phash, or None
    avatar_dhash: perceptual hash string from dhash, or None
    """
    profile_id: str
    platform: str
    username: str
    messages: list[str] = field(default_factory=list)
    active_hours: list[int] = field(default_factory=list)
    connections: set = field(default_factory=set)
    connection_degrees: dict = field(default_factory=dict)
    avatar_phash: Optional[str] = None
    avatar_dhash: Optional[str] = None


# ─────────────────────────────────────────────
# Signal results
# ─────────────────────────────────────────────

@dataclass
class SignalResult:
    """
    Output of a single correlation signal. raw_score is the unweighted
    signal strength from 0.0 to 1.0. confidence reflects how much the
    signal can be trusted given sample size and data quality.
    confidence_interval is an optional point estimate range for signals
    where sample size affects reliability. rationale is a plain-language
    explanation for the analyst.
    """
    name: str
    raw_score: float
    confidence: float
    rationale: str
    confidence_interval: Optional[tuple] = None


@dataclass
class CorrelationResult:
    """
    Full pairwise correlation result. correlation_strength is the fused
    confidence from 0.0 to 1.0. is_lead indicates the pair cleared the
    analyst-attention threshold. signals lists every signal that ran.
    rationale is the human-readable evidence trail. contradiction_note
    records any conflicting evidence that reduced the score.
    """
    profile_a: str
    profile_b: str
    correlation_strength: float
    is_lead: bool
    signals: list[SignalResult]
    rationale: list[str]
    contradiction_note: str
    scored_at: str

    def to_dict(self) -> dict:
        return {
            "profile_a": self.profile_a,
            "profile_b": self.profile_b,
            "correlation_strength": round(self.correlation_strength, 4),
            "is_lead": self.is_lead,
            "signals": [
                {
                    "name": s.name,
                    "raw_score": round(s.raw_score, 4),
                    "confidence": round(s.confidence, 4),
                    "confidence_interval": (
                        [round(s.confidence_interval[0], 4),
                         round(s.confidence_interval[1], 4)]
                        if s.confidence_interval else None
                    ),
                    "rationale": s.rationale,
                }
                for s in self.signals
            ],
            "rationale": self.rationale,
            "contradiction_note": self.contradiction_note,
            "scored_at": self.scored_at,
            "disclaimer": (
                "This is a correlation lead with its supporting evidence. "
                "It is not an assertion of shared identity. A qualified human "
                "analyst must confirm any identity link before action."
            ),
        }


@dataclass
class ClusterResult:
    """
    Result of entity clustering across N profiles. groups is a list of
    sets, each set containing profile ids the engine grouped as a likely
    single identity. edges records the weighted pairwise correlations that
    produced the grouping.
    """
    groups: list[set]
    edges: list[dict]
    scored_at: str

    def to_dict(self) -> dict:
        return {
            "groups": [sorted(list(g)) for g in self.groups],
            "edge_count": len(self.edges),
            "edges": self.edges,
            "scored_at": self.scored_at,
        }


# ─────────────────────────────────────────────
# Stylometry helper
# ─────────────────────────────────────────────

FUNCTION_WORDS = {
    "the", "a", "an", "and", "or", "but", "if", "of", "to", "in",
    "for", "on", "with", "as", "at", "by", "from", "is", "are", "was",
    "be", "this", "that", "it", "you", "i", "me", "my", "we", "they",
}


def stylometric_vector(messages: list[str]) -> dict:
    """
    Build a topic-independent authorship feature vector from a set of
    messages. Captures function-word frequency, punctuation habits,
    capitalization, emoji and slang density, and average message length.
    These features describe how a person writes rather than what they
    write about, which is what authorship attribution requires.
    """
    if not messages:
        return {}

    combined = " ".join(messages).lower()
    tokens = re.findall(r"\b\w+\b", combined)
    total_tokens = len(tokens) or 1

    function_word_freq = sum(
        1 for t in tokens if t in FUNCTION_WORDS
    ) / total_tokens

    raw = " ".join(messages)
    char_count = len(raw) or 1

    punctuation_density = sum(
        1 for c in raw if c in ".,!?;:'\"-"
    ) / char_count

    exclamation_density = raw.count("!") / char_count
    question_density = raw.count("?") / char_count
    ellipsis_density = raw.count("...") / (len(messages) or 1)

    uppercase_chars = sum(1 for c in raw if c.isupper())
    alpha_chars = sum(1 for c in raw if c.isalpha()) or 1
    capitalization_ratio = uppercase_chars / alpha_chars

    emoji_pattern = re.compile(
        "[\U0001F300-\U0001FAFF\U00002600-\U000027BF]"
    )
    emoji_density = len(emoji_pattern.findall(raw)) / (len(messages) or 1)

    avg_message_length = sum(len(m) for m in messages) / len(messages)
    length_factor = min(1.0, avg_message_length / 120.0)

    return {
        "function_word_freq": function_word_freq,
        "punctuation_density": punctuation_density,
        "exclamation_density": exclamation_density,
        "question_density": question_density,
        "ellipsis_density": min(1.0, ellipsis_density),
        "capitalization_ratio": capitalization_ratio,
        "emoji_density": min(1.0, emoji_density),
        "length_factor": length_factor,
    }


def vector_similarity(vec_a: dict, vec_b: dict) -> float:
    """
    Cosine-style similarity between two stylometric feature vectors.
    Returns 0.0 to 1.0. Empty vectors return 0.0.
    """
    if not vec_a or not vec_b:
        return 0.0

    keys = set(vec_a) & set(vec_b)
    if not keys:
        return 0.0

    dot = sum(vec_a[k] * vec_b[k] for k in keys)
    mag_a = math.sqrt(sum(vec_a[k] ** 2 for k in keys))
    mag_b = math.sqrt(sum(vec_b[k] ** 2 for k in keys))

    if mag_a == 0 or mag_b == 0:
        return 0.0

    return dot / (mag_a * mag_b)


def confidence_interval_for_sample(point: float, sample_size: int) -> tuple:
    """
    Build an illustrative confidence interval around a similarity point
    estimate. The interval narrows as the message sample grows, so small
    samples honestly report wide uncertainty instead of false precision.
    """
    if sample_size <= 0:
        return (0.0, 1.0)
    half_width = min(0.4, 1.0 / math.sqrt(sample_size))
    low = max(0.0, point - half_width)
    high = min(1.0, point + half_width)
    return (low, high)


# ─────────────────────────────────────────────
# Correlation engine
# ─────────────────────────────────────────────

class CorrelationEngine:
    """
    Cross-platform correlation engine. Fuses five identity signals into a
    single correlation strength with a full evidence trail. Designed for
    forensic explainability: every score is decomposable into the signals
    that produced it.

    The engine outputs leads for human confirmation. It never asserts
    shared identity on its own.
    """

    def __init__(
        self,
        weights: Optional[dict] = None,
        lead_threshold: float = CORRELATION_LEAD_THRESHOLD,
        use_semantic: bool = True,
    ):
        self.weights = weights or SIGNAL_WEIGHTS
        self.lead_threshold = lead_threshold
        self.use_semantic = use_semantic and _HAS_SENTENCE_TRANSFORMERS

    def correlate(
        self,
        profile_a: CorrelationProfile,
        profile_b: CorrelationProfile,
    ) -> CorrelationResult:
        """
        Produce a pairwise correlation result between two profiles.
        """
        signals = [
            self._signal_username(profile_a, profile_b),
            self._signal_stylometry(profile_a, profile_b),
            self._signal_timing(profile_a, profile_b),
            self._signal_network(profile_a, profile_b),
            self._signal_avatar(profile_a, profile_b),
        ]

        fused = 0.0
        for signal in signals:
            weight = self.weights.get(signal.name, 0.0)
            fused += signal.raw_score * signal.confidence * weight

        contradiction_note, penalty = self._check_contradiction(
            profile_a, profile_b, signals
        )
        fused = max(0.0, fused - penalty)
        fused = min(1.0, fused)

        rationale = self._build_rationale(signals)
        is_lead = fused >= self.lead_threshold

        return CorrelationResult(
            profile_a=profile_a.profile_id,
            profile_b=profile_b.profile_id,
            correlation_strength=fused,
            is_lead=is_lead,
            signals=signals,
            rationale=rationale,
            contradiction_note=contradiction_note,
            scored_at=datetime.now(timezone.utc).isoformat(),
        )

    # ─────────────────────────────────────────────
    # Signal: username
    # ─────────────────────────────────────────────

    def _signal_username(self, a, b) -> SignalResult:
        if not a.username or not b.username:
            return SignalResult(
                "username", 0.0, 0.0,
                "one or both profiles have no username to compare",
            )

        similarity = fuzz.ratio(a.username.lower(), b.username.lower()) / 100.0

        rarity_a = handle_rarity(a.username)
        rarity_b = handle_rarity(b.username)
        rarity = (rarity_a + rarity_b) / 2.0

        weighted = similarity * rarity

        if similarity > 0.85 and rarity > 0.6:
            rationale = (
                f"handles {a.username} and {b.username} are highly similar "
                f"and distinctive, which is strong evidence"
            )
        elif similarity > 0.85:
            rationale = (
                "handles are similar but common, which is weak evidence "
                "because many accounts share this style of name"
            )
        elif similarity > 0.5:
            rationale = "handles share a partial pattern"
        else:
            rationale = "handles are dissimilar"

        return SignalResult("username", weighted, 1.0, rationale)

    # ─────────────────────────────────────────────
    # Signal: stylometry (style fused with semantic embedding)
    # ─────────────────────────────────────────────

    def _signal_stylometry(self, a, b) -> SignalResult:
        count_a = len(a.messages)
        count_b = len(b.messages)

        if count_a == 0 or count_b == 0:
            return SignalResult(
                "stylometry", 0.0, 0.0,
                "one or both profiles have no messages for style analysis",
            )

        vec_a = stylometric_vector(a.messages)
        vec_b = stylometric_vector(b.messages)
        style_sim = vector_similarity(vec_a, vec_b)

        semantic_sim = None
        if self.use_semantic:
            emb_a = semantic_embedding(a.messages)
            emb_b = semantic_embedding(b.messages)
            if emb_a is not None and emb_b is not None:
                semantic_sim = _cosine_numpy(emb_a, emb_b)

        if semantic_sim is not None:
            fused_sim = style_sim * STYLE_BLEND + semantic_sim * SEMANTIC_BLEND
            blend_note = (
                "style features blended with semantic embedding, "
                "style weighted higher to avoid topic-driven false matches"
            )
        else:
            fused_sim = style_sim
            blend_note = "style features only, semantic embedding unavailable"

        min_count = min(count_a, count_b)
        interval = confidence_interval_for_sample(fused_sim, min_count)

        if min_count < STYLOMETRY_MIN_MESSAGES:
            confidence = min_count / STYLOMETRY_MIN_MESSAGES * 0.5
            rationale = (
                f"writing style shows similarity but the sample is small "
                f"({min_count} messages), so confidence is limited and the "
                f"interval is wide; {blend_note}"
            )
        else:
            confidence = 1.0
            if fused_sim > 0.9:
                rationale = (
                    "writing style fingerprints are highly consistent across "
                    f"function words, punctuation, and message structure; "
                    f"{blend_note}"
                )
            elif fused_sim > 0.7:
                rationale = (
                    f"writing style fingerprints are broadly consistent; "
                    f"{blend_note}"
                )
            else:
                rationale = f"writing style fingerprints differ; {blend_note}"

        return SignalResult(
            "stylometry", fused_sim, confidence, rationale,
            confidence_interval=interval,
        )

    # ─────────────────────────────────────────────
    # Signal: timing
    # ─────────────────────────────────────────────

    def _signal_timing(self, a, b) -> SignalResult:
        if not a.active_hours or not b.active_hours:
            return SignalResult(
                "timing", 0.0, 0.0,
                "one or both profiles have no activity timing data",
            )

        hours_a = set(a.active_hours)
        hours_b = set(b.active_hours)
        shared = hours_a & hours_b

        if not shared:
            return SignalResult(
                "timing", 0.0, 1.0,
                "no shared activity hours between profiles",
            )

        weighted_overlap = sum(hour_rarity(h) for h in shared)
        max_possible = sum(hour_rarity(h) for h in (hours_a | hours_b))
        score = weighted_overlap / max_possible if max_possible > 0 else 0.0

        overnight_shared = [h for h in shared if h in {0, 1, 2, 3, 4, 5}]
        if overnight_shared:
            rationale = (
                f"profiles share distinctive overnight activity hours "
                f"{sorted(overnight_shared)}, which is meaningful"
            )
        else:
            rationale = (
                "profiles share common activity hours, which is weak evidence "
                "because most accounts are active at these times"
            )

        return SignalResult("timing", score, 1.0, rationale)

    # ─────────────────────────────────────────────
    # Signal: network overlap
    # ─────────────────────────────────────────────

    def _signal_network(self, a, b) -> SignalResult:
        if not a.connections or not b.connections:
            return SignalResult(
                "network", 0.0, 0.0,
                "one or both profiles have no connection data",
            )

        shared = a.connections & b.connections
        if not shared:
            return SignalResult(
                "network", 0.0, 1.0,
                "no shared connections between profiles",
            )

        weighted = 0.0
        distinctive = []
        for conn in shared:
            degree = max(
                a.connection_degrees.get(conn, 1),
                b.connection_degrees.get(conn, 1),
            )
            weight = inverse_degree_weight(degree)
            weighted += weight
            if degree <= 20:
                distinctive.append(conn)

        union = a.connections | b.connections
        normalizer = math.log2(len(union) + 1) or 1.0
        score = min(1.0, weighted / normalizer)

        if distinctive:
            rationale = (
                f"profiles share {len(shared)} connections including "
                f"{len(distinctive)} in small distinctive groups, which is "
                f"strong evidence"
            )
        else:
            rationale = (
                f"profiles share {len(shared)} connections but all are large "
                f"public accounts, which is weak evidence"
            )

        return SignalResult("network", score, 1.0, rationale)

    # ─────────────────────────────────────────────
    # Signal: avatar
    # ─────────────────────────────────────────────

    def _signal_avatar(self, a, b) -> SignalResult:
        if not (a.avatar_phash and b.avatar_phash):
            return SignalResult(
                "avatar", 0.0, 0.0,
                "one or both profiles have no avatar hash",
            )

        if (a.avatar_phash in DEFAULT_AVATAR_HASHES
                or b.avatar_phash in DEFAULT_AVATAR_HASHES):
            return SignalResult(
                "avatar", 0.0, 0.0,
                "one or both avatars are platform defaults and excluded",
            )

        phash_distance = self._hamming(a.avatar_phash, b.avatar_phash)

        dhash_distance = None
        if a.avatar_dhash and b.avatar_dhash:
            dhash_distance = self._hamming(a.avatar_dhash, b.avatar_dhash)

        phash_match = phash_distance is not None and phash_distance <= 8

        if dhash_distance is not None:
            dhash_match = dhash_distance <= 8
            if phash_match and dhash_match:
                return SignalResult(
                    "avatar", 1.0, 1.0,
                    "avatars match across two hash algorithms, which is "
                    "strong evidence",
                )
            if phash_match or dhash_match:
                return SignalResult(
                    "avatar", 0.5, 0.7,
                    "avatars match on one hash algorithm but not both",
                )
            return SignalResult(
                "avatar", 0.0, 1.0, "avatars do not match",
            )

        if phash_match:
            return SignalResult(
                "avatar", 0.7, 0.7,
                "avatars match on perceptual hash, single algorithm only",
            )
        return SignalResult("avatar", 0.0, 1.0, "avatars do not match")

    def _hamming(self, hash_a: str, hash_b: str) -> Optional[int]:
        """
        Hamming distance between two hex hash strings. Returns None if the
        hashes are not comparable.
        """
        if not hash_a or not hash_b or len(hash_a) != len(hash_b):
            return None
        try:
            int_a = int(hash_a, 16)
            int_b = int(hash_b, 16)
        except ValueError:
            return None
        return bin(int_a ^ int_b).count("1")

    # ─────────────────────────────────────────────
    # Contradiction logic
    # ─────────────────────────────────────────────

    def _check_contradiction(self, a, b, signals) -> tuple:
        """
        Look for evidence that argues against a shared identity and return
        a note plus a confidence penalty. Negative evidence is part of what
        makes the output defensible. The clearest contradiction is
        simultaneous sustained high activity on both profiles in a pattern
        one person could not easily produce.
        """
        notes = []
        penalty = 0.0

        if a.active_hours and b.active_hours:
            hours_a = set(a.active_hours)
            hours_b = set(b.active_hours)
            overlap = hours_a & hours_b
            if len(overlap) >= 8 and len(hours_a) >= 10 and len(hours_b) >= 10:
                notes.append(
                    "both profiles show sustained near-identical all-day "
                    "activity, a pattern difficult for a single person to "
                    "produce, which argues against shared identity"
                )
                penalty += 0.15

        return (
            "; ".join(notes) if notes else "no contradictions detected",
            penalty,
        )

    # ─────────────────────────────────────────────
    # Rationale builder
    # ─────────────────────────────────────────────

    def _build_rationale(self, signals) -> list[str]:
        contributing = [
            s for s in signals if s.raw_score * s.confidence > 0.0
        ]
        contributing.sort(
            key=lambda s: s.raw_score * s.confidence, reverse=True
        )
        return [f"{s.name}: {s.rationale}" for s in contributing[:5]]

    # ─────────────────────────────────────────────
    # Entity clustering
    # ─────────────────────────────────────────────

    def cluster_identities(
        self,
        profiles: list[CorrelationProfile],
    ) -> ClusterResult:
        """
        Resolve identities across N profiles at once. Runs pairwise
        correlation on every pair, feeds the leads as weighted edges into a
        graph, and groups profiles by connected component. This scales the
        pairwise layer to a full case file with many accounts.

        Falls back to a simple union-find grouping if NetworkX is not
        installed, so the engine remains usable in any environment.
        """
        edges = []
        for i in range(len(profiles)):
            for j in range(i + 1, len(profiles)):
                result = self.correlate(profiles[i], profiles[j])
                if result.is_lead:
                    edges.append({
                        "profile_a": profiles[i].profile_id,
                        "profile_b": profiles[j].profile_id,
                        "strength": round(result.correlation_strength, 4),
                    })

        if _HAS_NETWORKX:
            groups = self._cluster_with_networkx(profiles, edges)
        else:
            groups = self._cluster_with_unionfind(profiles, edges)

        return ClusterResult(
            groups=groups,
            edges=edges,
            scored_at=datetime.now(timezone.utc).isoformat(),
        )

    def _cluster_with_networkx(self, profiles, edges) -> list[set]:
        graph = nx.Graph()
        for profile in profiles:
            graph.add_node(profile.profile_id)
        for edge in edges:
            graph.add_edge(
                edge["profile_a"], edge["profile_b"],
                weight=edge["strength"],
            )
        return [set(component) for component in nx.connected_components(graph)]

    def _cluster_with_unionfind(self, profiles, edges) -> list[set]:
        parent = {p.profile_id: p.profile_id for p in profiles}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x, y):
            parent[find(x)] = find(y)

        for edge in edges:
            union(edge["profile_a"], edge["profile_b"])

        groups = {}
        for pid in parent:
            root = find(pid)
            groups.setdefault(root, set()).add(pid)

        return list(groups.values())