# WhisperWard OSINT

**Defensive OSINT Platform for Online Safety & Investigation Support**

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Status](https://img.shields.io/badge/Status-Phase%201%20Complete-brightgreen)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## About

WhisperWard OSINT is a **modular, local-first** Python toolkit designed to help parents, educators, researchers, and authorized investigators collect, correlate, and organize publicly available online information for online safety investigations.

**Whisper** — the quiet, subtle signals in public online activity.  
**Ward** — to protect and guard.

---

## What WhisperWard Is

- A defensive OSINT and evidence organization platform
- Focused **exclusively** on publicly accessible data
- Built with chain-of-custody principles for investigative integrity
- Completely local-first: nothing leaves your machine

## What WhisperWard Is Not

- Not a vigilante tool
- Not for private data scraping or unauthorized access
- Not for doxxing, harassment, or confrontation
- Not a replacement for law enforcement or professional forensic tools

---

## Key Features (Phase 1 Complete)

- ✅ Full CLI with Typer + Rich interface
- ✅ SQLite database with 5-table schema
- ✅ Modular OSINT architecture (`BaseOSINTModule`)
- ✅ Roblox and Discord OSINT stubs (ready for expansion)
- ✅ Evidence packaging with SHA-256 hashing
- ✅ Behavioral analysis framework (AI-ready)
- ✅ Identity relationship graph generation
- ✅ Chain-of-custody logging

---

## Installation

```bash
git clone https://github.com/Mecapixel/whisperward-osint.git
cd whisperward-osint

pip install -r requirements.txt

# Optional: Sherlock for username correlation
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock && pip install -r requirements.txt && cd ..

# Initialize database
python whisperward.py init-db