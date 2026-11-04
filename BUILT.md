# BUILT: Prompt-Injection Tripwire

**What:** an interception proxy (FastAPI and an in-process engine) that sits between a ReAct agent and its tools. It taints every tool result, plants invisible canaries in it, and checks every outgoing call with four detectors: canary/taint leak, heuristics, a TF-IDF+LR classifier, and an exfiltration-sink detector (destination provenance, secrets, image beacons). A YAML policy turns the scores into allow / block / require_approval, and every decision goes to a SQLite audit log. Around it: a 68-attack / 62-benign corpus plus a 12 + 12 hold-out set, a mock attacker server for `*.test` domains, sandboxed mock tools with fake secrets, an on/off benchmark with ablation, a Streamlit dashboard with an approval queue, and 67 pytest tests including hypothesis fuzzing.

## Measured metrics

Measured on 2026-11-05 with `docker compose up -d` and then `make bench` (HTTP transport). Full report: `results/report.md`.

| Metric | OFF | ON | Target | Result |
|---|---|---|---|---|
| Attack success rate | 97.1% | **5.9%** | < 10% | PASS |
| Detection rate on harmful high-risk calls | – | **93.8%** (64 calls) | ≥ 90% | PASS |
| False-positive rate (benign scenarios) | 0.0% | **3.2%** (2/62) | ≤ 5% | PASS |
| Benign task completion | 100% | **96.8%** | drop ≤ 5 pp | PASS (3.2 pp) |
| Added latency p95 (no LLM judge) | – | **6.43 ms** | < 50 ms | PASS |
| Hold-out (written after tuning) | 100% ASR | 8.3% ASR, 0% FPR | – | – |

How the numbers held up across runs:
* The in-process run and the all-Docker run (`docker compose run --rm bench`) gave identical detection numbers. Their p95 latency was 4.6–5.8 ms.
* A fresh `git clone` gave the same numbers too (p95 5.0 ms in-process). The classifier is retrained from the committed dataset in that case.

Ablation shows the exfil/destination detector does most of the work: without it, ASR goes to 82.4%. Without the heuristics it is 10.3%; without the canary or the classifier it is 8.8%.

What it still misses or flags:
* **Attacks that still succeed:** the 4 content-manipulation cases (attacker-chosen text sent to a legitimate destination).
* **False positives:** the 2 "email the author named on the page" tasks. These are held for approval by design.

## How to run

```bash
make install && make test && make bench          # local, Python 3.11+
docker compose up -d --build && make bench       # Docker stack (proxy :8080, attacker :8081, dashboard :8501)
docker compose run --rm bench                    # benchmark entirely inside Docker
make demo / python examples/quickstart.py        # traces / library usage
```

## Caveats

* The agent is a deterministic scripted "gullible LLM", not a real model. An optional Ollama backend exists but was not benchmarked.
* Detectors were tuned on the main corpus; the hold-out set is the overfitting check.
* Compared with the brief: the classifier is TF-IDF+LR by default (DistilBERT is an optional path, not run). Neither the LLM judge nor the DistilBERT path was exercised. There is no demo GIF, MCP packaging or adaptive attacker.
* An `engine.py` module and a 10th attack category (content manipulation) were added.

See the README's Limitations section.
