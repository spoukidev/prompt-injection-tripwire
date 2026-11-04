"""Run every attack and benign scenario with the tripwire OFF and ON.

    python -m eval.run_benchmark                 # auto: HTTP if a proxy answers, else in-process
    python -m eval.run_benchmark --transport inprocess --no-ablation
    TRIPWIRE_URL=http://localhost:8080 python -m eval.run_benchmark --transport http

Writes ``results/runs.jsonl`` (one line per scenario x mode), ``results/metrics.json``
and then calls :mod:`eval.report` to produce ``results/report.md`` + charts.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

from agent.agent import Agent, ScriptedLLM
from eval import metrics
from eval.scenarios import attack_scenarios, benign_scenarios, make_client

ROOT = Path(__file__).resolve().parents[1]
ABLATIONS = ["canary_leak", "heuristics", "classifier", "exfil"]


def proxy_alive(url: str) -> bool:
    try:
        import httpx

        return httpx.get(url.rstrip("/") + "/health", timeout=1.5).status_code == 200
    except Exception:
        return False


def run_mode(scenarios: list[dict], on: bool, *, proxy_url: str | None, disabled: set[str] | None = None,
             audit_db: str | None = None, label: str | None = None) -> list[dict]:
    tw = None
    if on and not proxy_url:
        from tripwire.audit import AuditLog
        from tripwire.engine import Tripwire

        audit = AuditLog(f"sqlite:///{audit_db}") if audit_db else False
        tw = Tripwire(audit=audit, disabled=disabled, approval_mode="auto_deny")
    llm = ScriptedLLM()
    recs = []
    for sc in scenarios:
        client, sandbox, _ = make_client(on, sc, proxy_url=proxy_url, tripwire=tw)
        trace = Agent(client, llm).run(sc)
        recs.append(metrics.scenario_record(sc, trace, label or ("on" if on else "off")))
        if sandbox is not None:
            sandbox.close()
    return recs


def main(argv: list[str] | None = None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transport", choices=["auto", "inprocess", "http"], default=os.environ.get("BENCH_TRANSPORT", "auto"))
    ap.add_argument("--proxy-url", default=os.environ.get("TRIPWIRE_URL", "http://localhost:8080"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--no-ablation", action="store_true")
    ap.add_argument("--latency-runs", type=int, default=3, help="repeat the ON run to collect more latency samples")
    a = ap.parse_args(argv)

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    proxy_url = None
    if a.transport == "http" or (a.transport == "auto" and proxy_alive(a.proxy_url)):
        if not proxy_alive(a.proxy_url):
            sys.exit(f"proxy not reachable at {a.proxy_url}")
        proxy_url = a.proxy_url
    transport = "http" if proxy_url else "inprocess"
    print(f"[bench] transport={transport}" + (f" proxy={proxy_url}" if proxy_url else ""))

    from tripwire.detectors.classifier import ClassifierDetector

    if not ClassifierDetector().available:
        print("[bench] classifier model missing -> training it first (python -m classifier.train)")
        from classifier import train

        train.main([])

    scenarios = attack_scenarios() + benign_scenarios()
    audit_db = str(out / "bench_audit.db")
    for f in (audit_db, audit_db + "-wal", audit_db + "-shm"):
        if os.path.exists(f):
            os.remove(f)
    t0 = time.time()
    off = run_mode(scenarios, False, proxy_url=proxy_url)
    print(f"[bench] OFF done ({len(off)} scenarios)")
    on = run_mode(scenarios, True, proxy_url=proxy_url, audit_db=audit_db)
    print("[bench] ON done")
    extra_lat: list[float] = []
    for _ in range(max(0, a.latency_runs - 1)):
        extra = run_mode(scenarios, True, proxy_url=proxy_url, audit_db=audit_db)
        extra_lat += [x for r in extra for x in r["overheads_ms"]]

    result = {
        "meta": {"transport": transport, "python": platform.python_version(), "platform": platform.platform(),
                 "generated": time.strftime("%Y-%m-%d %H:%M:%S %z"), "duration_s": None,
                 "agent": "ScriptedLLM (deterministic, compliance=" + json.dumps(ScriptedLLM().compliance) + ")"},
        "off": metrics.summarize(off),
        "on": metrics.summarize(on),
        "ablation": {},
    }
    lat_all = [x for r in on for x in r["overheads_ms"]] + extra_lat
    result["on"]["latency_ms"] = {"n": len(lat_all), "mean": sum(lat_all) / len(lat_all), "p50": metrics.pct(lat_all, 50),
                                  "p95": metrics.pct(lat_all, 95), "p99": metrics.pct(lat_all, 99), "max": max(lat_all)}
    # Ablations always run in-process (they need to switch detectors off inside the engine).
    if not a.no_ablation:
        for det in ABLATIONS:
            recs = run_mode(scenarios, True, proxy_url=None, disabled={det}, label=f"no-{det}")
            s = metrics.summarize(recs)
            result["ablation"][f"without {det}"] = {k: s.get(k) for k in ("asr", "detection_rate_high_risk", "fpr_scenarios", "utility")}
            print(f"[bench] ablation without {det}: ASR={s['asr']:.3f} FPR={s['fpr_scenarios']:.3f}")
    # Hold-out set: written after tuning, never tuned on. Reported separately.
    hold = attack_scenarios("holdout") + benign_scenarios("holdout")
    if hold:
        h_off = run_mode(hold, False, proxy_url=proxy_url)
        h_on = run_mode(hold, True, proxy_url=proxy_url)
        result["holdout"] = {"off": metrics.summarize(h_off), "on": metrics.summarize(h_on)}
        hs = result["holdout"]
        print(f"[bench] hold-out: ASR off={hs['off']['asr']:.1%} on={hs['on']['asr']:.1%} FPR={hs['on']['fpr_scenarios']:.1%}")
        off += [dict(r, split="holdout") for r in h_off]
        on += [dict(r, split="holdout") for r in h_on]
    result["meta"]["duration_s"] = round(time.time() - t0, 1)

    with open(out / "runs.jsonl", "w", encoding="utf-8") as fh:
        for r in off + on:
            fh.write(json.dumps(r) + "\n")
    with open(out / "metrics.json", "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    from eval import report

    report.write_report(result, out)
    o, n = result["off"], result["on"]
    print(f"[bench] ASR off={o['asr']:.1%} on={n['asr']:.1%} | detection(high-risk)={n['detection_rate_high_risk']:.1%} | "
          f"FPR={n['fpr_scenarios']:.1%} | utility off={o['utility']:.1%} on={n['utility']:.1%} | "
          f"p95 overhead={n['latency_ms']['p95']:.2f} ms")
    print(f"[bench] report: {out / 'report.md'}")
    return result


if __name__ == "__main__":
    main()
