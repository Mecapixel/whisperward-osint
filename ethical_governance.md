# WhisperWard OSINT — Ethical & Governance Framework

**Version:** 2.3 | **Last Updated:** June 2026 | **Maintainer:** Pixora Inc.

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

WhisperWard collects data only from public Roblox and Discord profiles and metadata via official platform APIs, public game and server discovery signals surfaced through platform APIs, platform-surfaced chat content through authorized Trust and Safety integrations only, public friend and follower graphs and activity timing patterns, public IP metadata surfaced by platforms enriched entirely offline via local databases as described in Section 12, perceptual hashes of public profile avatars, and public Sherlock-indexed platform username presence signals.

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

## 12. IP Enrichment Data Flow and Privacy Boundary

This section governs the IP enrichment capability introduced in Milestone 4. It documents exactly what data is and is not transmitted to any third party at each stage of the process, so that the privacy posture can be verified rather than taken on trust. The governing principle is that during active casework, an IP address under investigation never leaves the analyst's machine.

### Intake Boundary

The enrichment module operates only on IP addresses that an investigator has deliberately entered into a case. It does not harvest addresses on its own, and the public Roblox and Discord interfaces that WhisperWard consumes do not expose them. Every address reaching enrichment arrives by explicit analyst action, which is why the capability does not expand the tool's collection scope.

### Local-Only Enrichment

All enrichment lookups are performed offline against local databases. Geolocation is resolved from local MaxMind GeoLite2 City and ASN database files. Anonymization signals are drawn from a local IP2Proxy LITE database, a cached copy of the Tor Project's public exit node list, and a curated ASN authority file maintained by the operator. No suspect address is transmitted to any external service during enrichment. If a database is absent the affected source is recorded as unavailable and enrichment continues with whatever remains, so a missing database lowers completeness without ever sending data off the machine to compensate.

### The Single Outbound Call

The only network activity associated with this capability lives in a separate maintenance script (update_threat_lists.py) that refreshes the Tor exit list between cases. That script is never run during an active lookup. When it runs it downloads a public list by its own request and sends no case data of any kind. It transmits nothing about any subject, any address under investigation, or any case. The refresh is a one-directional download of public information. The credentialed MaxMind and IP2Proxy databases are never downloaded automatically, because doing so would require handling account credentials; the operator obtains those files manually and the script only reports whether they are present and current.

### Per-Stage Data Flow

The table below states, for each stage, what leaves the machine. The honest summary is that during casework nothing leaves it.

| Stage | Action | Data sent to a third party |
| --- | --- | --- |
| Intake | Investigator enters an IP into a case | None |
| Geolocation lookup | Local GeoLite2 City and ASN database query | None |
| Proxy and VPN lookup | Local IP2Proxy LITE database query | None |
| Tor exit detection | Comparison against the locally cached exit list | None |
| ASN classification | Comparison against the local curated authority file | None |
| Custody logging | Record written locally with database hashes | None |
| Threat list refresh | Maintenance script downloads the public Tor list between cases | The request is made, but no case data, no subject data, and no investigated address is included |

### Provenance and Auditability

Every enrichment lookup produces a chain of custody record capturing the UTC timestamp, the input address, the complete structured output, and the version, age, and SHA-256 hash of every database consulted, along with any sources that were absent. The Tor list refresh additionally records the fetch time, the validation time, the source URL, the entry count, and the SHA-256 of the installed list. Because the enricher independently hashes the same file when it loads it, the custody record and the refresh metadata can be checked against each other, giving two independent confirmations of which threat list snapshot produced a given result.

### Authority File Discipline

The curated ASN file is treated as an authority rather than a reference list. The enrichment engine asserts only two categories, known-vpn and hosting-datacenter. A file containing any other category, a missing required field, or a duplicate entry is rejected. In the default strict configuration this rejection prevents the pipeline from starting, so a case is never run against malformed authority data. The operator is expected to validate the file after every edit using the refresh script, which surfaces any problem before the next case rather than during it. Entries in the file are seed classifications subject to analyst review, and the engine outputs a confidence score with a written rationale rather than asserting that any individual address is anonymizing. A qualified human confirms every conclusion.

---

*This framework is reviewed and updated with each major release. Version history is maintained in the GitHub commit log.*