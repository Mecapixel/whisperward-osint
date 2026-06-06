# WhisperWard OSINT - Development Roadmap

## Project Vision
A robust, ethical, and technically excellent defensive OSINT toolkit for online safety investigations, focused on public-signal threat hunting on platforms like Roblox.

## Scope & Ethical Boundaries
See **[POLICY_BOUNDARY.md](POLICY_BOUNDARY.md)** for the full policy document.

WhisperWard is a **public-signal threat-hunting and case-preparation tool** for Roblox and related platforms. It processes **only publicly accessible or platform-surfaced data**. All Tier 2 and Tier 3 outputs require **mandatory human review** before any evidence package is generated or any referral template is used. Synthetic data is used exclusively for all testing and validation.

**Approved sources**: public profiles, public chat surfaced through authorized platform integrations, public game metadata, public social graph signals, and public API data only.

**Non-goals**: no private message interception, no keystroke capture, no device-level monitoring, no street-address geolocation, no autonomous CyberTipline filing.

External hash integrations (PhotoDNA / NCMEC) are approval-gated and may remain disabled during development. The architecture is fully documented. See `csam_hash_detector.py` and POLICY_BOUNDARY.md.

---
## Phase 1: Foundation (Current Focus)
- [ ] Core CLI with Typer + Rich (`whisperward.py`)
- [ ] SQLite database schema (`schema.sql`) and DatabaseManager
- [ ] `BaseOSINTModule` abstract class
- [ ] Evidence Packager with chain-of-custody logging (SHA-256 manifests, UTC timestamps, immutable logs)
- [ ] Project documentation (README, DISCLAIMER, ACCEPTABLE_USE, POLICY_BOUNDARY.md)

**Target:** May/June 2026

---
## Phase 2: Core Capabilities
- [ ] Roblox OSINT Module (official public API only)
- [ ] Sherlock username correlation + variant generation
- [ ] Metadata extraction (ExifTool + imagehash)
- [ ] Rule-based behavioral pattern matching (Tier 1)
- [ ] Evidence export (ZIP + signed PDF reports)

---
## Phase 3: Intelligence Layer
- [ ] Local Ollama / Qwen2.5 AI integration (Tier 2 behavioral analysis)
- [ ] ChromaDB RAG knowledge base
- [ ] Hybrid risk analysis pipeline
- [ ] Identity relationship graph visualization

---
## Phase 4: Expansion (Detailed in Phase4_BuildReference)
- [ ] Discord public OSINT (widget API + manual assist only)
- [ ] Additional platform modules via `platform_plugin.py` (public data only)
- [ ] Docker containerization + rate limiting
- [ ] Central weighted Risk Engine + Explainability
- [ ] Grooming classifier, cross-platform correlation, IP enrichment
- [ ] NCMEC-aligned evidence packaging + CSAM hash detection stub

---
## Phase 5: Polish & Release
- [ ] Comprehensive test suite with fictional/synthetic data + precision/recall metrics
- [ ] Architecture diagrams and workflow documentation
- [ ] Cyberpunk-themed web UI (FastAPI + Render deployment)
- [ ] Demo video / walkthrough (fictional data only)
- [ ] Public GitHub release with full documentation

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