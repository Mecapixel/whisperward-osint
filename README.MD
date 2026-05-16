# WhisperWard OSINT

**Defensive OSINT Platform for Online Safety & Investigation Support**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Status](https://img.shields.io/badge/Status-In%20Development-orange)

---

## About

WhisperWard OSINT is a modular, local-first Python toolkit designed to help parents,
educators, researchers, and authorized investigators collect, correlate, and organize
publicly available online information for online safety investigations.

**Whisper** the quiet, subtle signals in public online activity.
**Ward** to protect and guard.

---

## What WhisperWard Is

- A defensive OSINT and evidence organization platform
- Focused exclusively on publicly accessible data
- Built with chain-of-custody principles for investigative integrity
- Local-first: everything runs on your machine

## What WhisperWard Is Not

- Not a vigilante tool
- Not a self-bot or private data scraper
- Not for unauthorized access, doxxing, or confrontation
- Not a replacement for law enforcement or certified forensic tools

---

## Key Features

- Roblox Public OSINT Module (official API endpoints only)
- Cross-Platform Username Correlation via Sherlock + variant generation
- Hybrid Behavioral Analysis (rule-based + local Ollama AI)
- Metadata Extraction (ExifTool + perceptual hashing)
- Evidence Packager with SHA-256 chain-of-custody logging
- Identity Relationship Graph Visualization
- Local AI via Ollama — no data leaves your machine
- Rich CLI with full pipeline command

---

## Installation

```bash
git clone https://github.com/Mecapixel/whisperward-osint.git
cd whisperward-osint
pip install -r requirements.txt
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock && pip install -r requirements.txt && cd ..
ollama pull qwen2.5-coder:7b
python3 whisperward.py init-db
```

---

## Quick Start

```bash
# Create a case
python3 whisperward.py new-case --name 'Investigation-001'

# Add a target
python3 whisperward.py add-target --case CASE-XXXX --username 'targetname' --platform roblox

# Run full pipeline (scan + analyze + graph + export)
python3 whisperward.py run --case CASE-XXXX

# Or step by step
python3 whisperward.py scan     --case CASE-XXXX
python3 whisperward.py analyze  --case CASE-XXXX --ai
python3 whisperward.py graph    --case CASE-XXXX
python3 whisperward.py export   --case CASE-XXXX
python3 whisperward.py status   --case CASE-XXXX
```

---

## Demo

Run the included demo script to see the full pipeline with fictional test data:

```bash
python3 demo.py
```

---

## Legal & Ethical Use

> This tool is released for **educational and authorized investigative purposes only**.

- Comply with all platform Terms of Service and applicable laws including CFAA
- Only collect publicly available information
- Never use it for harassment, vigilantism, or unauthorized access
- See DISCLAIMER.md and ACCEPTABLE_USE.md for full details

**Mandatory Reporting**: If you discover evidence of child exploitation, report
immediately to NCMEC CyberTipline (report.cybertip.org) or local law enforcement.

---

**Built with purpose.**
Meca Dismukes · Pixora Inc. May 2026
