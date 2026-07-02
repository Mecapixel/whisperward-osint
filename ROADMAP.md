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
## Next

- [ ] Wire the correlation engine into the CLI pipeline as a first-class `correlate` command
- [ ] Discord public OSINT module implementing the existing plugin contract (widget API + manual assist only)
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
