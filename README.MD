# WhisperWard OSINT

**AI-Powered Defensive OSINT Toolkit for Online Child Safety Investigations**

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Tests](https://img.shields.io/badge/tests-115%2B%20passing-brightgreen)
![Status](https://img.shields.io/badge/status-active%20development-success)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A modular, local-first platform that helps authorized investigators triage public signals of predatory behavior targeting minors on platforms like Roblox and Discord. It processes only publicly accessible data, runs AI analysis entirely on the local machine, and requires human review before any escalation.

Built by **Meca Dismukes (Pixora Inc.)** as both an active investigative tool and a portfolio project for ICAC-aligned and Trust & Safety work.

---

## Why WhisperWard Exists

WhisperWard was built in direct response to a real incident involving an adult attempting to target a minor family member through Discord. It exists to give investigators and platform safety teams a faster, defensible, ethically bounded way to triage public-signal reports before they reach a human reviewer — not to replace that human judgment.

---

## Ethical Boundaries

Full policy: see [`POLICY_BOUNDARY.md`](POLICY_BOUNDARY.md) and [`ethical_governance.md`](ethical_governance.md).

- Public data only — no private message interception, no device monitoring, no unauthorized access
- Local AI — investigative data is never sent to any third-party API
- Human review required for all Tier 2 and Tier 3 escalations
- Synthetic data used for all testing and demonstration — no real suspect accounts are processed for portfolio purposes
- No autonomous CyberTipline filing — the system produces analysis only; a qualified human confirms every escalation
- CSAM hash detection (PhotoDNA / NCMEC) is approval-gated and disabled by default pending external authorization

---

## Screenshots

**Boot sequence** — live case count pulled from the database
![Boot screen](docs/screenshots/boot.png)

**Operator authentication**
![Authentication](docs/screenshots/auth.png)

**Case registry** — active cases sorted by risk score
![Case registry dashboard](docs/screenshots/dashboard.png)

**Subject dossier** — risk assessment, artifacts, and intel log with live Roblox avatar
![Subject dossier](docs/screenshots/dossier.png)

**Classified case file** — quick-view popup
![Classified case file](docs/screenshots/case_file.png)

---

## Key Features

**Completed**
- Full command-line interface built with Typer and Rich
- Modular OSINT architecture via a shared `BaseOSINTModule` base class — new platforms add in under 100 lines
- Live Roblox public API integration with retry logic and avatar collection
- Cross-platform username correlation via Sherlock across 8 platforms
- Local AI analysis using Ollama (qwen2.5-coder:7b) with a ChromaDB retrieval-augmented knowledge base
- Explainable, weighted risk-scoring engine that surfaces the top contributing signals
- Grooming-pattern behavioral classifier (isolation, secrecy, age probing, platform-migration pressure, gift incentives, and more) with negation handling
- Evidence packaging with SHA-256 hashing and chain-of-custody logging
- FastAPI web dashboard with live case data, risk visualization, and Roblox avatar rendering
- 115+ passing pytest tests and structured logging

**In active development (Phase 4)**
- Cross-platform correlation engine fusing username, stylometry, timing, network, and avatar signals
- IP enrichment and anonymization (Tor / VPN) detection
- NCMEC-format evidence package export
- CSAM hash detection module — architecture complete, approval-gated and disabled by default

---

## Architecture

WhisperWard is a modular pipeline. Each platform collector inherits from a shared base class, feeds a central evidence store, and is scored by a weighted, explainable risk engine before reaching any human-facing output. AI analysis runs entirely locally. Every step logs its actions for auditability.

```
CLI / Dashboard
      |
OSINT Collectors  (Roblox, Discord, Sherlock)
      |
Evidence Store  (SQLite + SHA-256 chain of custody)
      |
Local AI + RAG  (Ollama + ChromaDB)
      |
Risk Engine  (weighted, explainable scoring)
      |
Human Review + Export
```

---

## Tech Stack

Python · Typer · Rich · FastAPI · SQLite · ChromaDB · Ollama (qwen2.5-coder:7b) · pytest · Loguru · structlog

---

## Installation

```bash
git clone https://github.com/Mecapixel/whisperward-osint.git
cd whisperward-osint

pip install -r requirements.txt

# Optional: Sherlock for username correlation
git clone https://github.com/sherlock-project/sherlock.git

# Optional: local AI analysis (one-time model pull)
ollama pull qwen2.5-coder:7b

# Initialize the database
python whisperward.py init-db
```

---

## Usage

WhisperWard runs as a command-line pipeline. A typical investigation:

```bash
# Create a case
python whisperward.py new-case --name "Investigation-2026"

# Add a target to the case (use the CASE-XXXX id returned above)
python whisperward.py add-target --case CASE-XXXXXXXX --username someusername --platform roblox

# Collect public OSINT for the case
python whisperward.py scan --case CASE-XXXXXXXX

# Run AI + RAG behavioral analysis
python whisperward.py analyze --case CASE-XXXXXXXX --ai

# Generate the identity relationship graph
python whisperward.py graph --case CASE-XXXXXXXX

# Package evidence with SHA-256 manifest
python whisperward.py export --case CASE-XXXXXXXX

# Or run the full pipeline end to end
python whisperward.py run --case CASE-XXXXXXXX
```

Launch the web dashboard:

```bash
python webapp/main.py
# then open http://localhost:8003
```

---

## Portfolio Highlights

For recruiters and hiring managers:

- Built a complete end-to-end investigative pipeline from raw public data to triaged, human-reviewable intelligence
- Production-grade engineering practices: 115+ tests, structured logging, rate limiting with circuit breakers, and SHA-256 evidence integrity
- Responsible local AI with explainable, decomposable risk scoring
- Strong emphasis on ethics, documentation, and defensibility — directly relevant to Trust & Safety, purple-team, and detection-engineering work

This project demonstrates skills transferable to offensive (OSINT tooling), purple-team (detection engineering and evasion-resistance), and defensive security roles.

---

## License

MIT License — see [`LICENSE`](LICENSE). This tool is for authorized investigative and defensive use only. All use must comply with platform terms of service and applicable law.

---

Built and maintained by Meca Dismukes — Pixora Inc.