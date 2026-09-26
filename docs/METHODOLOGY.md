# Risk Scoring Methodology

This document states how WhisperWard computes a risk score, where each parameter came from, what has and has not been validated, and how the model behaves under perturbation and deliberate evasion. Every number below is produced by `modules/child_safety/eval/methodology.py` and checked by `tests/test_methodology.py`, so the document and the code cannot drift apart without a test failing.

## The model

The risk score is a weighted linear combination of five component scores, plus a bounded interaction term, scaled to a ten-point range.

```
risk = min(10, 10 × ( Σ wᵢ · xᵢ  +  s ))

    xᵢ ∈ [0, 1]      raw score for component i
    wᵢ               component weight, Σ wᵢ = 1
    s  ∈ [0, 0.15]   synergy term for co-occurring signals
```

| Component | Weight | Raw score is driven by |
|---|---|---|
| Grooming language | 0.40 | Lexical pattern hits across eight tactic categories, plus a sequence bonus |
| Cross-platform correlation | 0.25 | Platforms observed, or graph-corroborated platforms when identity-graph inputs exist: 1 → 0, 2 → 0.4, 3 → 0.7, 4+ → 1.0 |
| Anonymization | 0.15 | Tor 0.6, VPN 0.4, capped at 1.0 |
| Behavioral velocity | 0.10 | Account age bands, friends per day, late-night activity, flagged game history |
| Historical signals | 0.10 | Prior case flags: 1 → 0.4, 2 → 0.7, 3+ → 1.0 |

The synergy term adds 0.05 for each of three co-occurrence patterns: grooming language across two or more platforms; three or more active components; and grooming language on a new, anonymized, multi-platform account. It is capped at 0.15, or 1.5 points.

Scores map to tiers at inclusive lower bounds: Tier 1 below 2.0, Tier 2 from 2.0, Tier 3 from 7.0. Escalation to Tier 3 additionally requires corroboration, meaning presence on two or more platforms (or two or more graph-corroborated platforms when identity-graph inputs exist) or at least one prior case flag. A score at or above 7.0 without corroboration is held at Tier 2 with the reason stated. The hold never changes the score itself.

The case page displays every component, the synergy term with the co-occurrence patterns that produced it, and their sum, so the parts shown always add up to the score shown.

### Why a linear additive model

A linear model was chosen for explainability rather than predictive power. Every point in the final score decomposes into a named contribution a reviewer can check, which is the property the domain requires: a score that may inform a referral has to be defensible line by line. A model that learned interactions from data might rank subjects better, but it would trade away that decomposition and would need labeled training data the project cannot lawfully hold. The synergy term is the one concession to interaction, kept small, capped, and itemized with its reasons so it stays auditable.

## Where the parameters came from

It matters to be precise here, because the parameters have three different origins and only one of them is empirical.

**Tier thresholds are calibrated.** The Tier 2 boundary was set by a threshold sweep against a seed-42 balanced synthetic dataset of fifty safe, fifty threat, and ten edge profiles, choosing 2.0 as the point holding recall at 0.85 with zero false positives while leaving a full point of margin for real-world noise the synthetic safe profiles do not exhibit.

**Category weights inside the classifier are literature-ordered.** `docs/BEHAVIORAL_INDICATORS.md` documents the eight tactic weights against published grooming research, with secrecy solicitation weighted highest and trust building lowest.

**The five component weights are an expert-judgment prior.** They are ordered by how directly each component observes the behavior of concern. Grooming language is weighted highest because it is the only component that observes conduct directly; the others observe circumstance, which is suggestive but shared by many benign users. Cross-platform presence is second because platform migration is itself a documented grooming tactic. They are not fitted to data, and this document does not claim they are.

## What the validation does and does not show

The synthetic evaluation harness reports precision, recall, and F1. Those figures should be read narrowly. The threat profiles draw their messages from a list authored alongside the classifier's patterns, so a high recall largely confirms that the patterns match the sentences they were written to match. It establishes internal consistency, not detection ability against real subjects.

Real validation requires labeled case outcomes. Those involve material an independent researcher cannot lawfully obtain, so empirical accuracy claims are out of reach for this project by construction rather than by omission. The weights are kept in one declared constant precisely so they can be replaced by fitted values when a partner organization able to hold ground truth can supply it.

What can be established without ground truth is how the scoring function behaves: its ceilings, its sensitivity to its own parameters, and its response to deliberate evasion. None of the analyses below needs labels, because each interrogates the function rather than the world.

## Test population

Sensitivity is measured over a full factorial grid of 1,536 profiles: six grooming levels, four platform counts, four anonymization states, four velocity profiles, and four prior-flag levels. Every component reaches both zero and its maximum somewhere in the grid, which a test enforces. Velocity is set through account age, friend count, and late-night activity together, because account age alone only reaches half of the component's range. A sample from the synthetic generator was deliberately not used. Generated profiles cluster wherever the generator places its mass, often far from tier boundaries, which would make flip rates look smaller than they are. The grid spans the whole input space including the boundaries, so the rates below are the conservative ones.

The grid is uniform over levels, not weighted by how often real subjects occupy each region. Flip rates therefore describe the function, not an expected caseload. Grooming is injected as classifier output rather than produced from chat, so the grid measures the scoring layer alone. Tiers in every analysis apply the engine's corroboration rule, and a test confirms the harness assigns exactly the tier the engine does for every profile in the grid.

## Monotonicity

More evidence on any one axis, with everything else fixed, never lowers the score. This holds for all five components and is checked by tests. A violation would mean a subject could reduce their score by doing more of what the engine looks for, so it is the first property a scoring function has to satisfy before any sensitivity figure means anything.

## Weight sensitivity

Each weight was moved by a stated fraction, with the other four rescaled proportionally so the total stays at 1.0. Holding the total fixed isolates the effect of shifting emphasis between components from the trivial effect of inflating every score.

| Component | ±10% tier flips | ±25% tier flips | Largest score shift at ±25% |
|---|---|---|---|
| Grooming language | 2.5–2.7% | 6.1–6.2% | 1.00 |
| Cross-platform | 1.6–2.1% | 4.4–4.6% | 0.62 |
| Anonymization | 1.2–1.3% | 2.3–3.0% | 0.38 |
| Behavioral velocity | 0.7–1.6% | 1.6–2.5% | 0.25 |
| Historical signals | 1.0% | 1.8–2.1% | 0.25 |

A ten percent reallocation of any single weight changes the tier of at most 2.7% of profiles across the whole input space. A quarter-sized reallocation changes at most 6.2%, and never moves any score by more than one point. This is the actual defense of hand-set weights: tier output is not sensitive to their exact values, so the precise choice of 0.40 over 0.35 has little effect on which cases reach a reviewer. Grooming is the most influential weight, as intended, which confirms the model's emphasis is where it was designed to be.

## Threshold sensitivity

| Boundary | Moved ±0.25 | Moved ±0.5 | Profiles within 0.5 points |
|---|---|---|---|
| Tier 2 at 2.0 | 0.7–1.1% | 1.7–2.1% | 55 |
| Tier 3 at 7.0 | 4.1% | 7.4–8.5% | 227 |

The Tier 3 boundary is roughly four times as sensitive as Tier 2, because far more of the input space sits near 7.0 than near 2.0. The practical meaning is that escalation decisions are where calibration carries the most weight, and where the requirement for human sign-off matters most.

## Adversarial evasion

The scenarios below are authored, including the reference phrasing, so they demonstrate mechanisms rather than measure rates. A reference subject was built to exhibit the pattern the engine targets: direct grooming language across three platforms on a new, high-velocity account behind a VPN. Each scenario then changes one thing the subject could plausibly do to avoid detection.

| Scenario | What the subject does | Score | Tier |
|---|---|---|---|
| Reference | Nothing to evade | 8.00 | 3 |
| Dilution | Buries grooming in eight times as much benign chat | 8.00 | 3 |
| Clean network | Drops the VPN | 6.90 | 2 |
| Aged account | Uses an established account at a normal friend rate, in daytime | 6.50 | 2 |
| Slow burn | Uses each tactic once, never repeating | 6.62 | 2 |
| Account split | Keeps each account on one platform, never linked | 5.25 | 2 |
| Paraphrase | Expresses the same intent in unmatched phrasing | 3.92 | 2 |
| Full evasion | Paraphrase, single platform, aged account, clean network | 0.07 | 1 |

One result is a clear strength. Dilution has no effect, because category hits are counted rather than averaged against message volume, so a subject cannot hide in noise.

Three single evasions each move the subject out of escalation but not out of review. Dropping the VPN, using an established account, or spacing tactics out one at a time each lands in Tier 2, between 6.5 and 6.9. None reaches monitor-only, so a human reviewer still sees the case. An earlier version of this analysis reported that dropping the VPN and the slow-burn approach both still escalated. That apparent robustness came from account age being counted twice, which inflated grooming scores; with the double count removed (see Findings), those two scenarios fall just below escalation. The weights were deliberately not re-tuned to restore the earlier result, because adjusting a model until it passes scenarios its author wrote is fitting the test rather than the problem.

Three results are limitations, stated here rather than left for a reviewer to discover. The classifier is lexical: it matches phrasing, not intent. In the illustrative paraphrase set used here, rewording the same tactics removed nearly all of the grooming signal. That is one hand-written set, not a measured evasion rate, and a larger adversarial corpus would be needed to estimate how often real paraphrase succeeds. Account splitting defeats cross-platform scoring whenever correlation fails to link the accounts, which is the case the persistence and identity graphs exist to address. And a subject who combines these techniques is not detected at all.

That last result defines the engine's scope. It is a triage aid for patterns it models, surfacing cases for human review. It is not a detector of adversaries who understand it, and it should not be presented as one. Every escalation still requires a named human reviewer for this reason among others.

## Findings, and how they were resolved

The first pass of this analysis found two places where the engine behaved differently from its own documentation. Both have been corrected in the engine, and `tests/test_methodology.py` and `tests/test_scoring_integrity.py` now assert the corrected behavior, so a regression fails the build.

**The single-platform ceiling equalled the Tier 3 threshold.** The calibration note stated that Tier 3 at 7.0 sat above the ceiling reachable from single-platform signals alone. Computed against the real engine, a single-platform subject with no history reached exactly 7.0: 4.0 from grooming, 1.5 from anonymization, 1.0 from velocity, and 0.5 of synergy. Because the tier rule is inclusive, that subject escalated, and the same result reproduced through the real classifier on ordinary chat. The weights happened to leave no margin, so the documented guarantee was an accident of arithmetic. The requirement is now an explicit rule: escalation requires cross-platform presence or prior history, and a score that reaches 7.0 without it is held at Tier 2 with the reason recorded. The score itself is unchanged, so the explanation still accounts for every point.

**Account age was counted in two components.** Account age and friend rate scored in the velocity component, and also raised the grooming component through the classifier's behavior boost. Velocity's stated ten percent weight understated its real influence, and the components were not independent in the way a linear model's weights imply. The engine now passes only chat content to the classifier, so the grooming component measures language alone and account behavior is scored once. The classifier keeps its boost when used on its own, outside the engine.

**What the correction changed.** The severe demonstration case had reached the maximum grooming score of 1.0 partly because its account carried 280 friends, which says nothing about its language. Scored on its words alone, grooming is 0.85, and the case score moves from 8.2 to 7.59. It remains Tier 3, because it is corroborated across four platforms. The moderate demonstration case, with 90 friends, never triggered the boost and is unchanged at 4.83. The lower number is the more defensible one.

**The breakdown now sums to the score.** Separately, the case page had displayed the five weighted components but not the synergy term, so the visible parts fell a full point short of the displayed score in both demonstration cases. The synergy term is now itemized with its reasons and shown on the page with an explicit total.

## Reproducing

```
python -m modules.child_safety.eval.methodology
python -m pytest tests/test_methodology.py tests/test_scoring_integrity.py -q
```

The first command prints the full report as JSON: population, ceilings, weight and threshold sensitivity, boundary density, and every evasion scenario. The second checks the properties, bounds, and resolved findings above.
