# WhisperWard — Live Demo Guide

**Audience:** ICAC / Trust & Safety / digital forensics reviewers and hiring managers
**Duration:** 6 to 8 minutes
**Goal:** Show the investigative flow, the technical depth, the evidence integrity, and the ethical safeguards that make WhisperWard defensible.

This guide doubles as a reviewer walkthrough (read it to understand the tool) and a presenter script (follow it to demo the tool without fumbling). Narration lines are written as suggestions, not a script to read word for word.

---

## Before the demo

Have these ready so nothing is improvised live.

```bash
# From the repository root
pip install -r requirements.txt

# Initialize the database (creates tables; safe to run repeatedly)
python whisperward.py init-db

# Launch the web dashboard
python webapp/main.py
# then open http://localhost:8003
```

Open a second terminal for the command-line portion so the web server keeps running in the first.

A note on data: the dashboard shows whatever real cases exist in the local database. When the database is empty it falls back to clearly labeled demo cases, so the interface is never blank. All cases used in this demo are investigator-created test accounts, never real minors or real suspects.

---

## Demo flow

### 1. Boot and authentication — 30 seconds

Open `http://localhost:8003`.

Show the boot screen. Point out that the active-case count is pulled live from the database, not hard-coded.

Click through to the authentication screen.

> "WhisperWard opens on an operator authentication step. The framing throughout is a classified-system aesthetic, but the point underneath it is real: every action in the tool is tied to an operator identity, because chain of custody starts with who is doing the work."

### 2. Dashboard overview — 60 seconds

After authenticating, you land on the case registry.

Point to the threat-distribution chart at the top.

> "This is a live D3 visualization reading from the API. It breaks every active case into governance risk tiers — monitor, review, escalate, or not yet scored. A reviewer sees the shape of the caseload in one glance."

Point to the case grid below.

> "Cases are sorted by risk score, highest first. Each card is a real case with a real platform, target count, and score. Nothing here is mocked — it is the same data the reports and the API serve."

### 3. Case detail deep dive — 2 to 3 minutes (the core)

Click a case to open its dossier.

Walk through, top to bottom:

- The subject panel, with the live Roblox avatar pulled from the platform API.
- The metadata: username, platform, analyst, target and artifact counts.
- The threat assessment bar and risk score.

> "The risk score is explainable by design. It is a weighted sum of signals, and the engine can surface the top contributors rather than handing a reviewer a black-box number. For a Trust and Safety or ICAC context that explainability is not optional — a human has to be able to defend why a case was flagged."

Point to the risk timeline and the radial gauge.

> "The timeline shows risk over time. With a single scan it shows one marked point, honestly labeled, rather than faking a trend. As a case is re-scanned it becomes a real line. The gauge gives the current tier at a glance, colored to the same thresholds used everywhere else in the system."

Scroll to the terminal intel log.

> "Every collection and analysis step is logged. This is the human-facing view of an audit trail that is also written, hashed, into the evidence store."

### 4. The collection pipeline — 90 seconds

Switch to the second terminal. Show that the same investigation runs from the command line.

```bash
# Create a case
python whisperward.py new-case --name "Demo-Investigation"

# Add a target (use the CASE id printed above)
python whisperward.py add-target --case CASE-XXXXXXXX --username someusername --platform roblox

# Collect public OSINT
python whisperward.py scan --case CASE-XXXXXXXX

# Run behavioral and AI analysis
python whisperward.py analyze --case CASE-XXXXXXXX --ai

# Check case status
python whisperward.py status --case CASE-XXXXXXXX
```

> "Collection is public-data only — public Roblox profile and avatar data through the official API, and optional cross-platform username correlation. The AI analysis runs entirely on the local machine. No investigative data leaves the box."

### 5. Evidence integrity and the human-in-the-loop — 90 seconds

Generate the evidence package:

```bash
python whisperward.py export --case CASE-XXXXXXXX
```

> "Export produces an evidence package with a SHA-256 manifest, written under a hash-chained chain-of-custody log. The chain is tamper-evident — it detects edits and deletions, so the integrity of the record can be proven, not just asserted."

Then describe the evidence subsystem that backs this, which is covered by the test suite:

> "Behind the export sit several governed capabilities: cryptographically signed PDF case reports, a redaction engine that produces a separate shareable copy without ever touching the sealed original, a CyberTipline-aligned referral export that is redacted by default, and a ninety-day retention enforcer that purges on a dry-run-by-default basis while always preserving the audit chain. These are built and tested, and they all hold the same line — the tool prepares evidence, it never files autonomously."

If asked to prove it, run the suite:

```bash
pytest -q
```

> "The whole system is covered by over four hundred tests, including the evidence-integrity and tamper-detection paths."

### 6. Close — 30 seconds

> "Three things define WhisperWard. It is local-first, so investigative data never leaves the machine. It is human-in-the-loop — every Tier 2 and Tier 3 case requires a qualified human to review and sign off, and the tool will never file a referral on its own. And it is built for defensibility, with explainable scoring and tamper-evident evidence from collection through export. It was built in response to a real attempt to target a minor in my own family, and every design choice reflects that the output has to hold up to a human reviewer and, ultimately, to a court."

---

## Reproducible command appendix

The exact commands, in order, for a clean end-to-end run:

```bash
pip install -r requirements.txt
python whisperward.py init-db

python whisperward.py new-case --name "Demo-Investigation"
# note the CASE-XXXXXXXX id that is printed

python whisperward.py add-target --case CASE-XXXXXXXX --username someusername --platform roblox
python whisperward.py scan    --case CASE-XXXXXXXX
python whisperward.py analyze --case CASE-XXXXXXXX --ai
python whisperward.py status  --case CASE-XXXXXXXX
python whisperward.py export  --case CASE-XXXXXXXX

# Or the full pipeline end to end
python whisperward.py run --case CASE-XXXXXXXX

# Web dashboard (separate terminal)
python webapp/main.py
# http://localhost:8003

# Full test suite
pytest -q
```

---

## Notes for the presenter

- If a live network call is slow or rate-limited during `scan`, fall back to an existing case in the dashboard rather than waiting. The web walkthrough does not depend on a fresh scan.
- The local AI step (`analyze --ai`) requires the Ollama model to be pulled. If it is not available on the demo machine, describe it rather than running it, and run `analyze` without `--ai` to show the rule-based behavioral classifier.
- Keep the ethical framing in front. For this audience the safeguards are not a footnote — they are the reason the tool is credible. The single strongest line is that the system prepares evidence and a human files it, never the other way around.