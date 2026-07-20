# WhisperWard OSINT - Development Roadmap

## Project Vision
A robust, ethical, and technically excellent defensive OSINT toolkit for online safety investigations, focused on public-signal threat hunting on platforms like Roblox.

## Scope & Ethical Boundaries
See **[POLICY_BOUNDARY.md](POLICY_BOUNDARY.md)** for the full policy document.

WhisperWard is a **public-signal threat-hunting and case-preparation tool** for Roblox and related platforms. It processes **only publicly accessible or platform-surfaced data**. All Tier 2 and Tier 3 outputs require **mandatory human review** before any evidence package is generated or any referral template is used. Synthetic data is used exclusively for all testing and validation.

**Approved sources**: public profiles, public chat surfaced through authorized platform integrations, public game metadata, public social graph signals, and public API data only.

**Non-goals**: no private message interception, no keystroke capture, no device-level monitoring, no street-address geolocation, no autonomous CyberTipline filing.

---
## Shipped

### Phase 1: Foundation — complete, May 2026
- [x] Core CLI with Typer + Rich (`whisperward.py`)
- [x] SQLite database schema (`schema.sql`) and DatabaseManager
- [x] `BaseOSINTModule` abstract class
- [x] Evidence Packager with chain-of-custody logging (SHA-256 manifests, UTC timestamps, immutable logs)
- [x] Project documentation (README, DISCLAIMER, ACCEPTABLE_USE, POLICY_BOUNDARY.md)

### Phase 2: Core Capabilities — complete, May 2026
- [x] Roblox OSINT Module (official public API only)
- [x] Sherlock username correlation + variant generation
- [x] Metadata extraction (ExifTool + imagehash)
- [x] Rule-based behavioral pattern matching (Tier 1)
- [x] Evidence export (ZIP + signed PDF reports)

### Phase 3: Intelligence Layer — complete, May 2026
- [x] Local Ollama / Qwen2.5 AI integration (Tier 2 behavioral analysis)
- [x] ChromaDB RAG knowledge base
- [x] Hybrid risk analysis pipeline
- [x] Identity relationship graph visualization

### Phase 4: Expansion — complete, June 2026 (Milestones 0–8)
- [x] Platform plugin architecture via `platform_plugin.py` (Roblox live; Discord contract defined)
- [x] Docker containerization + token-bucket rate limiting with circuit breakers
- [x] Central weighted Risk Engine with per-component explainability and calibrated tier thresholds
- [x] Grooming-pattern behavioral classifier with negation handling and sequence awareness
- [x] Cross-platform correlation engine (username, stylometry, timing, network, avatar signals; NetworkX clustering)
- [x] IP enrichment and anonymization detection, fully offline
- [x] NCMEC-aligned referral export, PII redaction engine, retention enforcer
- [x] CSAM hash detection architecture (approval-gated, disabled by default)

### Phase 5: Polish & Release — complete, June 2026
- [x] Comprehensive test suite with synthetic data + precision/recall metrics (408 tests)
- [x] Architecture and workflow documentation
- [x] CRT-surveillance web UI (FastAPI + D3.js), deployed to Render with a synthetic demo seeder
- [x] Public GitHub release with full documentation and case study

---
### Platform Phase 1: Core Extraction — complete, July 2026
- [x] Codebase split into `core/` (reusable investigation engine) and `modules/` (specializations); child-safety logic under `modules/child_safety/`
- [x] Stable contracts defined in `core/contracts.py` (Decision, ClassifierVerdict, BehavioralClassifier, Evidence, Entity, Case, RiskSignal, Explanation)
- [x] Registration seam in `core/registry.py`: a specialization declares its classifier and behavioral-indicator taxonomy without the core importing it
- [x] Risk engine decoupled from the child-safety classifier (resolved through the registry; core carries no static import of any specialization)
- [x] All 424 tests pass against the new layout with import-path updates only

### Platform Phase 2: Evidence & Explainability Engine — complete, July 2026
- [x] Evidence model (`core/evidence.py`): every artifact carries UUID, SHA-256, UTC timestamp, source, and collector; chain-of-custody manifest sealed inside every evidence package
- [x] Confidence engine: every score component and overall result carries a confidence level with enumerated reasons; confidence never alters a score
- [x] Explanation objects (`core/explanation.py`): findings link reasoning, confidence, and evidence references as queryable data
- [x] Analyst notes (`core/analyst_notes.py`): append-only annotations attached to cases, targets, and findings; every note lands in the custody chain and travels in the manifest
- [x] Audit trail hardening: case creation, target addition, artifact saves, and analysis saves all land in the tamper-evident hash chain; full-lifecycle verification and tamper detection covered by tests
- [x] Suite grown from 424 to 456 tests, green at every milestone

### Platform Phase 3: Entity Resolution & Identity Graph — complete, July 2026
- [x] Unified entity model (`core/entity.py`): the resolver proposes candidates from correlation output with full per-membership justification; a contradiction on every supporting edge excludes an account with the reason recorded
- [x] Analyst-gated promotion: converting a candidate to a resolved entity requires a named analyst and lands in the tamper-evident chain of custody; unattributed resolution refuses to run
- [x] Identity graph (`core/identity_graph.py`): accounts as nodes, every edge carrying its complete justification (strength, signals, rationale, contradiction note); evidence-bearing path queries; deterministic, byte-stable serialization with a D3-shaped export
- [x] Investigation timeline (`core/timeline.py`): strictly reconstructive per-case event stream; every event names its source table and row; no event is inferred
- [x] Graph-aware risk: the cross-platform component reasons over graph-corroborated platforms (contradiction-free lead edges) when graph inputs are present; contradictions cap confidence and never alter a score; calibration harness green
- [x] Surfacing: `propose-entities`, `promote-entity`, `entities`, `identity-graph`, and `timeline` CLI commands; entities, identity-graph, and investigation-timeline API routes

### Platform Phase 4: Standards-Aware Intelligence — complete, July 2026
- [x] STIX 2.1 export (`core/stix_export.py`): user-account observables, correlation relationships with confidence and rationale, analyst-resolved entities, and a suspicious-activity grouping; never emits adversary-assertion object types; byte-stable output sealed into the evidence store (`stix` CLI command)
- [x] Honest MITRE ATT&CK mapping (`core/attack_mapping.py` + `attack-map` CLI): maps only fired technical signals, grades each mapping direct or analogue, and states explicitly which findings are outside ATT&CK's scope and where they are documented instead
- [x] Behavioral-indicator taxonomy documented at pattern level (`docs/BEHAVIORAL_INDICATORS.md`), weights versioned to the shipped classifier
- [x] Platform threat model (`THREAT_MODEL.md`): assets, adversaries, failure modes, mitigations, and residual risks stated honestly
- [x] Suite grown from 456 to 552 tests, green at every milestone

## Next

- [x] Wire the correlation engine into the CLI pipeline as a first-class `correlate` command — complete, July 2026
- [x] Discord public OSINT module implementing the existing plugin contract (invite + widget, tokenless) — complete, July 2026
- [ ] Additional platform modules via `platform_plugin.py` (public data only)
- [ ] Demo video / walkthrough (synthetic data only)
- [ ] PhotoDNA / NCMEC adapter activation, pending external authorization

---
## Success Criteria
- All operations remain local-first and privacy-respecting
- Strong, auditable legal and ethical guardrails throughout
- Clean, maintainable, extensible codebase (plugin architecture)
- Portfolio-quality documentation and technical depth
- Reproducible performance (<45s full scan target) and low false positive rate

---
**Built with purpose.**  
Meca Dismukes | Pixora Inc. | June 2026
