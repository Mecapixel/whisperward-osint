# WhisperWard OSINT — Ethical & Governance Framework

**Version:** 2.2 | **Last Updated:** June 2026 | **Maintainer:** Pixora Inc.

This document governs all data collection, analysis, escalation, and retention decisions made by WhisperWard. It is a required artifact for ROOST grant compliance, NCMEC-aligned partnership reviews, and Roblox Trust & Safety evaluations. It is a living document updated with each major release.

## 1. Human-in-the-Loop Mandate

WhisperWard generates intelligence. It does not make autonomous decisions about individuals.

All Tier 2 and Tier 3 cases require a qualified human analyst to review, assess, and explicitly approve any escalation action before it is taken. The tool cannot and will not file a CyberTipline report, generate a law enforcement referral package, or initiate any external contact autonomously.

Reviewer qualification requirement: background-checked analyst with documented ICAC task force experience, Trust and Safety certification, or law enforcement digital forensics training. Reviewer credentials are embedded in the case manifest at the time of sign-off.

## 2. Reviewer Workflow

Tier thresholds were calibrated in June 2026 against a seed-42 balanced synthetic evaluation dataset via threshold sweep, and are recalibrated with each major release. Calibration reports are retained in the reports directory and version history is maintained in the GitHub commit log.

Tier 1 (Score 0.0 to 1.9) is logged for monitoring only, scheduled for re-scan per retention policy, and generates no notification.

Tier 2 (Score 2.0 to 6.9) triggers immediate human reviewer notification. The reviewer must acknowledge within 24 hours. The assessment is logged with operator ID and UTC timestamp. No escalation occurs without explicit reviewer approval. Re-assessment is scheduled if the reviewer does not escalate.

Tier 3 (Score 7.0 to 10.0) generates an evidence package automatically. Human sign-off is required before the package is filed. Reviewer credentials and acknowledgment are embedded in the PDF manifest. The NCMEC CyberTipline format is pre-populated for reviewer completion. All reviewer actions are logged with operator ID and UTC timestamp. An immutable audit trail is preserved from scan to referral. The Tier 3 boundary is intentionally set above the maximum score reachable from single-platform signals alone, so evidence-package generation requires corroborating cross-platform or historical evidence.

## 3. Data Retention Policy

WhisperWard collects behavioral intelligence about individuals. Retention of that data is minimized and governed by this policy.

Standard retention: case data is auto-purged after 90 days unless the case has been escalated to law enforcement.

Escalated cases are retained for the duration of any active law enforcement engagement plus 30 days after engagement closes.

The retention window is jurisdiction-configurable and adjustable per deployment requirements. Configuration is documented in .env and must be reviewed before any non-US deployment.

All purge events are logged with UTC timestamp, operator ID, and case ID. Deletion cannot be undone. The audit log of the deletion is itself retained for 1 year.

## 4. Bias & Fairness Testing

The grooming classifier and age estimation module are audited for demographic bias on each major release.

Bias testing evaluates performance across gender, geography, and linguistic register proxies available through public behavioral metadata. No protected-class data is collected directly — proxies only.

If any demographic proxy group shows a false positive rate more than 5 percentage points above the baseline rate, the release is blocked until the disparity is resolved.

Audit results are documented in this file and in the transparency report. Results are available to institutional partners on request.

## 5. Transparency Report Template

Pixora Inc. will publish a quarterly transparency report covering WhisperWard operational statistics. Required fields include scans performed total and per platform, Tier 1 through Tier 3 cases triggered, false positive rate from the test suite updated per release, CyberTipline referral packages generated but not filed without human approval, data retention purge events by count not case detail, and bias audit status for the current release.

## 6. CSAM Hash Detection Policy

WhisperWard includes a CSAM hash detection module governed by the following constraints.

The module uses local perceptual hashing via the imagehash library as a baseline fallback for avatar and media cross-reference.

PhotoDNA and NCMEC hash list integrations are approval-gated, disabled by default, and may remain disabled during development. Adapter stubs are documented in csam_hash_detector.py.

No matched image content is ever stored. The module records only the hash value, match result, database source, and UTC timestamp. Image content is never written to disk, database, or log.

Human reviewer approval is required before any hash match result triggers a CyberTipline submission. This constraint is enforced in code and cannot be bypassed through configuration.

Registration status as of June 2026: NCMEC outreach sent to techcoalition@ncmec.org, response pending. PhotoDNA Microsoft registration pending organizational credential review.

## 7. Approved Data Sources

WhisperWard collects data only from public Roblox and Discord profiles and metadata via official platform APIs, public game and server discovery signals surfaced through platform APIs, platform-surfaced chat content through authorized Trust and Safety integrations only, public friend and follower graphs and activity timing patterns, public IP metadata surfaced by platforms enriched at city-level only via MaxMind GeoLite2, perceptual hashes of public profile avatars, and public Sherlock-indexed platform username presence signals.

## 8. Non-Goals & Prohibited Uses

The following are explicitly out of scope and will never be implemented: private message interception or communication surveillance of any kind, keystroke capture or device-level monitoring, street-address or precise geolocation of any individual, autonomous CyberTipline filing or autonomous law enforcement action, storage of matched CSAM image content, any direct interaction with accounts showing signs of belonging to real minors, real-time active monitoring or engagement within predatory spaces, and profiling based on race, religion, gender, sexual orientation, or national origin.

## 9. Synthetic Data Policy

All testing, validation, and development work uses entirely fabricated synthetic profiles generated by synthetic_profile_generator.py.

Real children's accounts, real predator accounts, and any real user data are never used in test sets, demos, or development environments under any circumstances.

Synthetic profiles are tagged with a seed value for reproducibility. LLM-generated chat content in synthetic profiles is fabricated entirely and never derived from real conversations.

## 10. Threat Model for WhisperWard Itself

WhisperWard must be hardened against abuse by bad actors attempting to weaponize the tool against innocent users.

All username and account inputs are sanitized before API calls. SQL injection and prompt injection vectors are explicitly tested in the test suite.

LLM components are hardened against adversarial inputs designed to manipulate risk score output. System prompts are not user-modifiable.

Token-bucket rate limiting on all FastAPI endpoints prevents bulk automated abuse of the scanning interface.

The web UI requires authenticated analyst login before any scan can be initiated. Unauthenticated access returns no data.

A documented channel exists for platforms and researchers to report false positives or request signal review. Contact information is in README.md.

## 11. Grooming Classifier Governance

WhisperWard's grooming pattern classifier (`behavioral_classifier.py`) detects communication patterns associated with online child exploitation. This section documents its design constraints, data sourcing, and governance boundaries.

### Pattern Sources

All grooming patterns in the classifier are derived exclusively from public domain sources:

- Federal ICAC prosecution records (public court documents)
- NCMEC published research on online enticement patterns
- Thorn technical reports on predator communication methodology
- Internet Watch Foundation behavioral documentation

No real chat logs, no real victim communications, and no private law enforcement databases were used in classifier development.

### False Positive Policy

The classifier is a first-pass signal generator, not a decision-making system. Every positive classification must pass through human review before any action is taken. The classifier explicitly returns a Decision value of ALLOW, REVIEW, or ESCALATE — escalation never triggers autonomous action.

If any demographic proxy group shows a false positive rate more than 5 percentage points above the baseline rate in bias testing, the release is blocked.

### Negation Filtering

The classifier applies negation context filters to reduce false positives on educational content, safety training materials, moderation logs, and research documentation. Messages matching negation patterns are excluded from scoring.

### Sequence Awareness

Grooming is a process, not a single phrase. The classifier applies a sequence bonus when multiple pattern categories appear across a conversation, reflecting the multi-step nature of grooming behavior documented in NCMEC and Thorn research.

### Classifier Limitations

The classifier is a rule-based heuristic. It is not a probabilistic model and its scores are not probabilities. It is designed to surface cases for human review, not to make enforcement decisions autonomously. It should be paired with AI behavioral analysis, cross-platform correlation, and human analyst judgment before any escalation action is taken.

---

*This framework is reviewed and updated with each major release. Version history is maintained in the GitHub commit log.*