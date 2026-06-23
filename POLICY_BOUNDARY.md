# WhisperWard OSINT — Policy Boundary & Scope

**Version:** 1.1 | **Last Updated:** June 2026 | **Maintainer:** Pixora Inc.

WhisperWard is a public-signal threat-hunting and case-preparation intelligence tool focused on protecting minors on platforms like Roblox and Discord. This document defines what WhisperWard is, what it is not, and the non-negotiable operational constraints that govern every aspect of its design and use.

---

## Core Scope

WhisperWard processes only publicly accessible or platform-surfaced data. It is designed for Roblox Trust & Safety style analysis, OSINT research, and law enforcement case-preparation handoff.

All Tier 2 and Tier 3 outputs require mandatory human review before any evidence package generation or referral template use. WhisperWard generates intelligence. A qualified analyst makes the determination.

Synthetic data is used for all testing and validation. Fabricated profiles only, never real children's accounts or real predator accounts in any test, demo, or development context.

---

## Approved Data Sources

The following sources are in scope for WhisperWard data collection:

- Public Roblox and Discord profiles and metadata via official platform APIs
- Public game and server discovery signals surfaced through platform APIs
- Platform-surfaced chat content through authorized Trust and Safety integrations only
- Public friend and follower graphs and activity timing patterns
- Public IP metadata surfaced by platforms, enriched entirely offline against local databases (city-level geolocation, ASN, proxy, and Tor classification) with no investigated address ever transmitted to a third party
- Perceptual hashes of public profile avatars using local processing only
- Public Sherlock-indexed platform username presence signals

---

## Non-Goals — Explicitly Out of Scope

The following capabilities are outside WhisperWard's design scope and will never be implemented:

- Private message interception or any form of communication surveillance
- Keystroke capture or device-level monitoring of any kind
- Street-address or precise geolocation of any individual
- Autonomous CyberTipline filing or any autonomous law enforcement action
- Storage of matched CSAM image content (hashes and metadata only — never image content)
- Any direct interaction with accounts that show signs of belonging to real minors
- Real-time active monitoring or engagement within predatory spaces
- Profiling based on race, religion, gender, sexual orientation, or national origin

---

## Human-in-the-Loop Mandate

WhisperWard is an intelligence generation tool, not an autonomous decision system.

Tier 1 cases are logged for monitoring. No immediate action is taken.

Tier 2 cases require a human reviewer to acknowledge and assess within 24 hours. No auto-escalation occurs under any circumstances.

Tier 3 cases trigger automatic evidence package generation, but the package is never filed autonomously. A qualified human analyst with documented ICAC or Trust and Safety training must review and sign off before any referral template, CyberTipline submission, or law enforcement contact is initiated.

All reviewer actions are logged with operator ID and UTC timestamp. The audit trail is immutable.

---

## Reviewer Workflow

Tier thresholds reflect the June 2026 calibration against the seed-42 balanced synthetic evaluation dataset and are kept in sync with the values enforced in code and documented in the Ethical & Governance Framework.

```
Tier 1 (Score 0.0 – 1.9)
  └── Logged for monitoring only
  └── Scheduled for re-scan
  └── No notification generated

Tier 2 (Score 2.0 – 6.9)
  └── Human reviewer notified
  └── Reviewer must acknowledge within 24 hours
  └── Reviewer assessment logged with operator ID + timestamp
  └── No escalation without explicit reviewer approval

Tier 3 (Score 7.0 – 10.0)
  └── Evidence package generated automatically
  └── Human sign-off required before any referral template is used
  └── Reviewer credentials and acknowledgment embedded in package manifest
  └── NCMEC CyberTipline format pre-populated — never auto-submitted
```

---

## IP Enrichment Network Boundary

WhisperWard's IP enrichment capability is offline by design. The following boundary is enforced in code and verified by the test suite.

During active casework, an IP address under investigation never leaves the machine. All geolocation, proxy, VPN, and Tor detection is performed against local database files. No address, no subject information, and no case data is transmitted to any third party at any stage of enrichment.

The capability enriches only addresses an investigator has deliberately entered into a case. It does not harvest addresses, and it does not expand collection scope.

The single exception to offline operation is a separate maintenance script that refreshes the public Tor exit node list between cases. This script is never run during a lookup. When it runs it downloads a public list and sends no case data, no subject data, and no investigated address. It is a one-directional download of public information.

The credentialed geolocation and proxy databases are never downloaded automatically by the tool, because doing so would require handling account credentials. The operator obtains those files manually and places them in the local data directory. The tool reports whether they are present and current but never fetches them.

---

## CSAM Hash Detection

WhisperWard includes a CSAM hash detection module built on the following principles:

Local perceptual hashing via the imagehash library is always available as a fallback for avatar and media cross-reference.

PhotoDNA (Microsoft) and NCMEC hash list integrations are approval-gated. These integrations may remain disabled during development. The architectural adapter stubs are documented in `csam_hash_detector.py` and the approval registration process is documented in this repository under `01_Docs/`.

No matched image content is ever stored. The module records only the hash value, match result, database source, and UTC timestamp. Chain of custody is preserved from the moment of collection.

Human reviewer approval is required before any hash match result triggers a CyberTipline submission. This is non-negotiable.

---

## Compliance Posture

WhisperWard is licensed under AGPL-3.0.

Case data is auto-purged after 90 days unless escalated to law enforcement. Escalated cases are retained for the duration of active law enforcement engagement plus 30 days.

All purge events are logged with timestamp and operator ID.

Bias and fairness audits on the grooming classifier are conducted on each major release, evaluating performance across demographic proxies available through public behavioral metadata. Any demographic proxy group showing a false positive rate more than 5 percentage points above baseline blocks the release until resolved.

---

## Suggested Usage Contexts

WhisperWard is appropriate for use by:

- Roblox and Discord Trust and Safety teams with platform API authorization
- ICAC task force analysts preparing case documentation for law enforcement referral
- Academic and nonprofit researchers studying online child safety with IRB oversight or equivalent
- Technology hiring reviewers evaluating ICAC-aligned portfolio work

WhisperWard is not appropriate for use by:

- Private investigators or individuals conducting surveillance without law enforcement authorization
- Any entity seeking to identify, locate, or contact individuals in the field
- Any use case involving real-time monitoring, active engagement, or deceptive identity

---

*This document is a living artifact and will be updated with each major release. Questions about scope or appropriate use should be directed to the project maintainer before deployment.*