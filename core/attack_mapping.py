"""
WhisperWard — MITRE ATT&CK Mapping
Platform Phase 4, Milestone 2
Pixora Inc.

ATT&CK models adversary behavior against computer systems. Most of what
WhisperWard detects — the interpersonal manipulation of a minor — is not in
ATT&CK's scope, and pretending otherwise would make every mapped report less
trustworthy. This module therefore does two things with equal weight: it maps
the technical observations that genuinely correspond to ATT&CK techniques, and
it states explicitly which findings have no honest ATT&CK home and where their
documentation actually lives (the WhisperWard behavioral-indicator taxonomy,
docs/BEHAVIORAL_INDICATORS.md).

Every mapping carries an applicability grade. "direct" means the observed
behavior is the behavior the technique describes. "analogue" means ATT&CK
defined the technique for a different actor model (typically C2
infrastructure) and WhisperWard applies it as the closest standard vocabulary
for the same technical act; the justification states the difference. Nothing
is mapped at all unless the underlying signal actually fired.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ATTACK_DOMAIN = "MITRE ATT&CK Enterprise"

SCOPE_STATEMENT = (
    "ATT&CK mappings cover technical observations only. Behavioral findings "
    "concerning the manipulation of a minor are outside ATT&CK's scope by "
    "design and are documented in the WhisperWard behavioral-indicator "
    "taxonomy (docs/BEHAVIORAL_INDICATORS.md) instead. An 'analogue' grade "
    "marks a technique ATT&CK defined for a different actor model, applied "
    "as the closest standard vocabulary for the same technical act."
)


@dataclass
class TechniqueMapping:
    signal: str
    technique_id: str
    technique_name: str
    tactic: str
    applicability: str  # "direct" or "analogue"
    justification: str

    def to_dict(self) -> dict:
        return {
            "signal": self.signal,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "applicability": self.applicability,
            "justification": self.justification,
        }


@dataclass
class UnmappedFinding:
    signal: str
    reason: str
    documented_in: str = "docs/BEHAVIORAL_INDICATORS.md"

    def to_dict(self) -> dict:
        return {"signal": self.signal, "reason": self.reason,
                "documented_in": self.documented_in}


TOR_MAPPING = TechniqueMapping(
    signal="anonymization_tor",
    technique_id="T1090.003",
    technique_name="Proxy: Multi-hop Proxy",
    tactic="Command and Control",
    applicability="analogue",
    justification=(
        "Tor usage was flagged by IP enrichment. ATT&CK defines multi-hop "
        "proxying as adversary command-and-control tradecraft; here it is "
        "applied as the closest standard vocabulary for a subject routing "
        "activity through Tor to conceal network origin."),
)

VPN_MAPPING = TechniqueMapping(
    signal="anonymization_vpn",
    technique_id="T1090",
    technique_name="Proxy",
    tactic="Command and Control",
    applicability="analogue",
    justification=(
        "VPN usage was flagged by IP enrichment. ATT&CK defines proxying as "
        "adversary infrastructure tradecraft; here it is applied as the "
        "closest standard vocabulary for origin obfuscation through a "
        "commercial VPN."),
)

PERSONA_MAPPING = TechniqueMapping(
    signal="cross_platform_personas",
    technique_id="T1585.001",
    technique_name="Establish Accounts: Social Media Accounts",
    tactic="Resource Development",
    applicability="direct",
    justification=(
        "Corroborated presence of the same actor across multiple platform "
        "accounts. Establishing social media personas is precisely the "
        "behavior this technique describes; the correlation evidence for "
        "each account link is preserved in the identity graph."),
)

NEW_ACCOUNT_MAPPING = TechniqueMapping(
    signal="new_account_velocity",
    technique_id="T1585.001",
    technique_name="Establish Accounts: Social Media Accounts",
    tactic="Resource Development",
    applicability="direct",
    justification=(
        "Recently created account observed in combination with contact "
        "behavior. Freshly established personas are the behavior this "
        "technique describes; account age is taken from platform metadata."),
)

BEHAVIORAL_UNMAPPED_REASON = (
    "Grooming-pattern findings describe interpersonal manipulation of a "
    "minor. ATT&CK models adversary behavior against computer systems and "
    "has no technique for this conduct; forcing a mapping would misstate "
    "both the finding and the framework.")

HISTORICAL_UNMAPPED_REASON = (
    "Prior case flags and platform history are investigation context, not a "
    "technique. They carry weight in the risk engine and are documented in "
    "the case record; no ATT&CK technique describes them.")


def map_risk_result(result: dict, is_tor: bool = False,
                    is_vpn: bool = False) -> dict:
    """Maps one scored risk result to ATT&CK, honestly.

    result: RiskResult.to_dict(). is_tor / is_vpn: the anonymization flags
    that produced the anonymization component, so the mapping can distinguish
    Tor from VPN rather than guessing from a combined score.

    Returns mapped techniques (only for components that actually scored above
    zero), the explicitly unmapped findings with reasons, and the scope
    statement. A result with nothing to map returns empty lists — never a
    padded mapping.
    """
    components = {c.get("name"): c for c in result.get("components", [])}
    mapped: list[TechniqueMapping] = []
    unmapped: list[UnmappedFinding] = []

    grooming = components.get("grooming_classifier")
    if grooming and grooming.get("raw_score", 0) > 0:
        unmapped.append(UnmappedFinding(
            signal="grooming_classifier",
            reason=BEHAVIORAL_UNMAPPED_REASON))

    cross = components.get("cross_platform_correlation")
    if cross and cross.get("raw_score", 0) > 0:
        mapped.append(PERSONA_MAPPING)

    anonymization = components.get("anonymization_ip")
    if anonymization and anonymization.get("raw_score", 0) > 0:
        if is_tor:
            mapped.append(TOR_MAPPING)
        if is_vpn:
            mapped.append(VPN_MAPPING)

    velocity = components.get("behavioral_velocity")
    if velocity and velocity.get("raw_score", 0) > 0:
        mapped.append(NEW_ACCOUNT_MAPPING)

    historical = components.get("historical_signals")
    if historical and historical.get("raw_score", 0) > 0:
        unmapped.append(UnmappedFinding(
            signal="historical_signals",
            reason=HISTORICAL_UNMAPPED_REASON,
            documented_in="case record (analysis_results, evidence_log)"))

    return {
        "attack_domain": ATTACK_DOMAIN,
        "mapped": [m.to_dict() for m in mapped],
        "unmapped": [u.to_dict() for u in unmapped],
        "scope_statement": SCOPE_STATEMENT,
    }


def taxonomy_reference() -> dict:
    """The static mapping table, for documentation and review: which signals
    can ever map, to what, at which applicability grade, and which findings
    are permanently out of ATT&CK scope."""
    return {
        "attack_domain": ATTACK_DOMAIN,
        "mappable": [m.to_dict() for m in
                     (TOR_MAPPING, VPN_MAPPING, PERSONA_MAPPING,
                      NEW_ACCOUNT_MAPPING)],
        "out_of_scope": [
            UnmappedFinding(signal="grooming_classifier",
                            reason=BEHAVIORAL_UNMAPPED_REASON).to_dict(),
            UnmappedFinding(
                signal="historical_signals",
                reason=HISTORICAL_UNMAPPED_REASON,
                documented_in="case record (analysis_results, evidence_log)"
            ).to_dict(),
        ],
        "scope_statement": SCOPE_STATEMENT,
    }
