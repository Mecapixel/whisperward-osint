# WhisperWard Behavioral-Indicator Taxonomy

**Status:** documented and versioned to the shipped classifier
**Scope:** public-signal, text-based behavioral indicators only
**Governing policy:** [POLICY_BOUNDARY.md](../POLICY_BOUNDARY.md) and [ethical_governance.md](../ethical_governance.md)

## Purpose

This document is the human-readable specification of what WhisperWard's
behavioral classifier actually detects. It exists so that a reviewer, an
analyst, or an oversight body can read the detection logic without reading the
code, and so that every finding a report surfaces can be traced to a named,
weighted, defensible indicator. The taxonomy is not a diagnostic instrument and
does not determine that grooming has occurred. It surfaces linguistic patterns
associated in the literature with grooming behavior, weighted by how strongly
each pattern discriminates, for a qualified human to evaluate.

Every category below carries a fixed weight. The weights are the classifier's
actual `PATTERN_WEIGHTS`, reproduced here so the document and the code cannot
silently drift; a test asserts they match.

## Design principles

The classifier is rule-based and explainable by construction. There is no
opaque model between an input message and a finding: a pattern either matched
or it did not, at a known position, under a known category, with a known
weight. Three properties protect against the obvious failure modes.

Negation handling means a message that explicitly rejects a pattern is not
scored as exhibiting it — "I would never ask you to keep secrets from your
parents" is not secrecy solicitation. Sequence awareness means the classifier
recognizes that certain categories appearing in progression is more concerning
than the same categories in isolation, because grooming is a process rather
than a single utterance. And a bounded contribution per category means no
single category, and no repetition of one pattern, can saturate the score on
its own; corroboration across categories is what moves a score materially.

## Categories

### Secrecy solicitation — weight 0.24
The highest-weighted category. Language pressing for concealment of the
conversation or relationship from parents, guardians, or friends, and framing
of the interaction as a shared secret. Weighted highest because solicited
secrecy is among the most discriminating indicators: it has few benign
explanations in an adult-to-minor context and is a load-bearing step in
isolating a target.

### Platform migration — weight 0.18
Pressure to move the conversation off the platform where it began, typically
toward a channel with less moderation, weaker age controls, or ephemeral
messaging. Weighted heavily because migration off a monitored surface is both
common in grooming progressions and a point at which platform-side protection
is deliberately defeated.

### Age probing — weight 0.16
Persistent or contextually inappropriate solicitation of the target's age,
grade, or developmental markers, distinguished from ordinary conversational
familiarity by insistence and framing. Weighted substantially because age
targeting is definitional to the harm the platform exists to surface.

### Isolation language — weight 0.14
Language working to separate the target from their support network or to
establish exclusivity of the relationship — "just the two of us," discouraging
outside friendships, positioning the contact as the only one who understands
the target.

### Identity probing — weight 0.10
Solicitation of identifying or locating information: full name, school,
neighborhood, routine, or when the target is home alone. Distinct from age
probing in that it seeks to locate or contact rather than to establish
targetability.

### Gift incentive — weight 0.10
Offers of money, in-platform currency, game items, subscriptions, or physical
goods, particularly when tied to continued contact, secrecy, or compliance.
Captures the material-inducement lever documented across grooming case studies.

### Compliment escalation — weight 0.05
A progression from ordinary friendliness toward personal, appearance-focused,
or intimacy-presuming compliments. Weighted low on its own because early stages
are indistinguishable from benign warmth; it earns weight through sequence,
when it precedes higher-weight categories.

### Trust building — weight 0.03
The lowest-weighted category. Rapport and alliance language — shared secrets
framed positively, "you can always talk to me," positioning against parents or
authority as the understanding confidant. Weighted lowest because it is the
least specific: the same language saturates healthy supportive relationships.
It contributes almost nothing alone and matters only as connective tissue in a
sequence.

## How categories become a score

Each category contributes its weight scaled by a bounded function of how many
distinct messages matched it, so a category caps rather than accumulating
without limit. A sequence bonus applies when multiple distinct categories
appear in progression, reflecting that grooming is a staged process. The
classifier returns, for every finding, the category, the matched span, the
message index, and the running category scores — the same explainable payload
the risk engine and the evidence package consume.

The classifier's output is a Tier-1 signal into the central risk engine, where
it carries the largest single weight (0.40). It never independently escalates a
case; escalation is a function of the whole weighted assessment under mandatory
human review.

## What this taxonomy is not

It is not a clinical or forensic determination. It does not process private
messages, only public or platform-surfaced text within policy scope. It does
not map to MITRE ATT&CK, which models adversary behavior against computer
systems and has no vocabulary for interpersonal manipulation of a minor; the
ATT&CK mapping module documents that boundary explicitly rather than forcing a
false correspondence. Findings are leads for a qualified human, and nothing in
this taxonomy changes that.
