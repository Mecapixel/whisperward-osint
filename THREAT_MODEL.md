# WhisperWard Threat Model

**Scope:** the WhisperWard platform itself — its data, its integrity guarantees, and its operators
**Companion documents:** [POLICY_BOUNDARY.md](POLICY_BOUNDARY.md), [ethical_governance.md](ethical_governance.md), [docs/BEHAVIORAL_INDICATORS.md](docs/BEHAVIORAL_INDICATORS.md)

## Why an investigation tool needs its own threat model

WhisperWard produces material that may inform consequential decisions about
real people. That makes the platform itself a target and a risk surface: an
attacker who can tamper with evidence, an operator who oversteps policy, or a
subtle bug that inflates a score can each cause harm that no amount of
downstream review fully undoes. This document names the assets worth
protecting, the adversaries and failure modes considered, and the mitigations
actually built, so a reviewer can judge whether the protections match the
stakes.

## Assets

The assets, in the order they matter: the integrity of collected evidence and
its chain of custody; the correctness and explainability of every score and
correlation the system emits; the confidentiality of case data, which concerns
minors and investigation subjects; the identity and accountability of the
analysts who make decisions; and the policy boundary itself — the guarantee
that the system only ever does what its governance documents say it does.

## Adversaries and failure modes considered

**A tampering actor with file or database access.** Someone who can write to
the case database or evidence files and wants to alter, insert, or delete
evidence after the fact. Mitigated by the hash-chained, tamper-evident custody
log covering the full case lifecycle (case creation, target addition, artifact
saves, analysis saves, entity promotions), SHA-256 manifests sealed inside
every evidence package, append-only analyst notes that land in the custody
chain, and deterministic serialization of graph and STIX exports so identical
content is byte-identical and any alteration changes the hash. Verification
and tamper detection are covered by tests.

**An overreaching operator.** An analyst, or someone with an analyst's access,
pushing the system past its policy boundary: reaching for private data,
activating hash-matching without authorization, or letting the machine's
output stand in for a human judgment. Mitigated structurally rather than by
trust: the collectors only implement public-signal sources, so out-of-scope
collection has no code path; the CSAM hash module is approval-gated and
disabled by default; Tier 2 and Tier 3 outputs require human review before any
evidence package or referral is produced; entity resolution requires a named
analyst and refuses to run unattributed; and every consequential action is
attributed in the custody chain, so overreach leaves a record.

**A false-confidence failure.** Not an attacker but the most likely source of
real-world harm: the system asserting more certainty than the evidence
supports. Mitigated by design decisions that run through every analytical
layer — scores decompose into weighted, explained components; every component
and result carries a confidence level with enumerated reasons, and confidence
never alters a score; the correlation engine detects contradictions and a
contradiction blocks entity candidacy rather than being averaged away; the
identity graph has no unexplained edges; graph corroboration can lower an
overclaimed cross-platform count; the ATT&CK mapping refuses to map findings
the framework does not cover; and STIX exports never emit adversary-assertion
object types. Calibration is enforced by a precision/recall harness in CI over
synthetic corpora.

**A network-position adversary.** Someone observing or interfering with the
platform's outbound collection or the operator's environment. Mitigated by a
local-first architecture (analysis, AI, and the knowledge base run locally;
nothing case-related leaves the machine by default), rate-limited collection
against official public APIs with retry and circuit breakers, offline IP
enrichment, and deployment guidance that keeps the dashboard behind
authenticated, HMAC-signed sessions.

**A supply-chain or environment failure.** Compromised dependencies or a
hostile execution environment. Partially mitigated: dependencies are pinned by
requirements policy and reviewed on change, the demo deployment runs with
synthetic data only, and the containerized runtime narrows the surface.
Residual risk is acknowledged: WhisperWard inherits the integrity of the
Python ecosystem it builds on, and operators handling live casework should
run it on hardware and networks they control.

## Non-goals restated as security properties

The policy non-goals double as attack-surface reductions. Because there is no
private-message interception, no device monitoring, and no street-address
geolocation, the platform cannot leak what it never collects. Because there is
no autonomous CyberTipline filing, a compromised or malfunctioning instance
cannot generate legal-process traffic on its own; a human stands between the
system and every external consequence.

## Residual risks

Honest accounting of what remains: a root-level compromise of the operator's
machine defeats local integrity controls, since the attacker holds the same
keys the platform does; the custody chain proves tampering occurred but cannot
recover pre-tamper state without external backups; synthetic-data calibration
bounds but does not eliminate false-positive risk on live data, which is why
human review is mandatory rather than advisory; and the correctness of
third-party platform APIs is trusted at collection time, mitigated by
recording raw responses verbatim under hash so later disputes can be examined
against the original material.
