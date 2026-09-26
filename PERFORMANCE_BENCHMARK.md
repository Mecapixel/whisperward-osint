# WhisperWard OSINT — Performance Benchmark

**Version:** 4.1 | **Last Updated:** June 2026 | **Reference hardware:** see specification below

---

## Hardware Specification

| Component | Specification |
|---|---|
| Machine | HP Victus gaming laptop (development reference machine) |
| CPU | Intel i5-12450H |
| RAM | 64GB Kingston Fury DDR4-3200 |
| GPU | NVIDIA RTX 3050 4GB VRAM |
| Storage | 2TB SSD |
| OS | Windows 11 Home 25H2 |

---

## Performance Targets

| Metric | Target | Measured | Status |
|---|---|---|---|
| Full scan latency | Under 45 seconds | 28–47 seconds | Documented below |
| False positive rate, safe profiles | Under 15% | 0% (0 of 50) | Enforced by `tests/test_benchmark_targets.py` |
| Recall, threat profiles | 85% or higher | 90% (45 of 50) | Enforced by `tests/test_benchmark_targets.py` |
| Precision | 0.75 or higher | 1.00 | Enforced by `tests/test_benchmark_targets.py` |
| F1 score | 0.70 or higher | 0.87 | Enforced by `tests/test_benchmark_targets.py` |
| Recall, edge profiles | Recorded, not targeted | 10% (1 of 10) | Known limitation |

Measured by scoring the seed-42 synthetic set (50 safe, 50 threat, 10 edge) end to end through the risk engine. Those profiles are drawn from message lists authored alongside the classifier, so these figures establish internal consistency, not real-world detection; see [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md). Edge profiles are ambiguous by construction, and the engine leaves most of them below review rather than raise its false positive rate on safe profiles, which is held at zero. An earlier version of this table listed a false negative target under 5% as enforced; no test enforced it, and the engine does not meet it.

---

## Benchmark Results

### Full Pipeline Scan Latency

Measured from username input to evidence package output on the reference hardware above.

| Component | Avg Latency | Notes |
|---|---|---|
| Roblox API profile fetch | 2-4 seconds | Public API, 3 retry max |
| Sherlock username scan (8 platforms) | 15-25 seconds | 90 second timeout ceiling |
| AI behavioral analysis (Ollama) | 8-15 seconds | qwen2.5-coder:7b, temp=0.3 |
| RAG context retrieval | Under 1 second | ChromaDB cosine similarity |
| Evidence package generation | Under 2 seconds | SHA-256 manifest + ZIP |
| **Total full pipeline** | **28-47 seconds** | Within 45s target on average |

### Rate Limiter Performance

| Platform | Configured Limit | Actual Throughput |
|---|---|---|
| Roblox API | 10 req/60s | Compliant |
| Discord API | 10 req/60s | Compliant |
| Sherlock | 10 req/60s | Compliant |

---

## Test Suite Performance Metrics

Run automatically on each release via `pytest` and `precision_recall_reporter.py`.

| Metric | Result | Target | Pass |
|---|---|---|---|
| Total tests | 659 | N/A | N/A |
| Test execution time | Under 20 seconds | N/A | Yes |
| False positive rate, safe profiles | 0% | Under 15% | Yes |
| Recall, threat profiles | 90% | 85% or higher | Yes |

---

## Reproduction Instructions

To reproduce these benchmarks on any machine:

```bash
python whisperward.py init-db
python whisperward.py new-case --name "Benchmark Test" --analyst "Meca Dismukes"
python whisperward.py add-target --case <CASE-ID> --username synthetic_benchmark_user
python whisperward.py run --case <CASE-ID>
```

Time the `run` command (PowerShell shown; use `time` on Linux/macOS):

```powershell
Measure-Command { python whisperward.py run --case <CASE-ID> }
```

---

*Benchmarks updated with each major release. Results reflect the reference hardware above and will vary on other systems.*