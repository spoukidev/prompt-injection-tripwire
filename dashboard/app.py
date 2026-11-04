"""Streamlit dashboard: live tool calls, verdicts, taint highlights, approval queue.

    streamlit run dashboard/app.py          # TRIPWIRE_URL defaults to http://localhost:8080
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import streamlit as st

API = os.environ.get("TRIPWIRE_URL", "http://localhost:8080")
RESULTS = Path(os.environ.get("RESULTS_DIR", Path(__file__).resolve().parents[1] / "results"))
COLORS = {"allow": "🟢", "block": "🔴", "require_approval": "🟠"}

st.set_page_config(page_title="Prompt-Injection Tripwire", layout="wide")
st.title("🪤 Prompt-Injection Tripwire")


def get(path: str, **params):
    try:
        r = httpx.get(API + path, params=params, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.warning(f"Proxy not reachable at {API}{path}: {e}")
        return None


health = get("/health")
if health:
    st.caption(f"proxy {API} - v{health['version']} - approval mode `{health['approval_mode']}` - "
               f"detectors: {', '.join(health['detectors'])} - classifier loaded: {health['classifier']}")

tab_calls, tab_approvals, tab_bench = st.tabs(["Tool calls", "Approval queue", "Benchmark"])

with tab_calls:
    st.button("Refresh")
    only_flagged = st.checkbox("Only flagged calls", value=False)
    rows = get("/audit", limit=300) or []
    if only_flagged:
        rows = [r for r in rows if r["decision"] != "allow"]
    st.write(f"{len(rows)} calls")
    for r in rows[:150]:
        head = f"{COLORS.get(r['decision'], '')} `{r['tool']}` - **{r['decision']}** ({r['rule']}) - score {r['score']:.2f} - {r['latency_ms']:.1f} ms - session {r['session_id']}"
        with st.expander(head):
            st.json(r["args"], expanded=False)
            for d in r["detectors"]:
                st.markdown(f"**{d['name']}** score `{d['score']:.2f}` - " + "; ".join(d["reasons"][:6]))
                for h in d.get("highlights", [])[:5]:
                    st.markdown(f"> `{h['field']}` ({h['why']}): {h['text']}")

with tab_approvals:
    pend = get("/approvals", status="pending") or []
    if not pend:
        st.info("No pending approvals.")
    for a in pend:
        st.markdown(f"**{a['tool']}** - session `{a['session_id']}` - id `{a['id']}`")
        st.json(json.loads(a["args_json"]), expanded=False)
        st.write("Reasons: " + "; ".join(json.loads(a["reasons_json"])[:6]))
        c1, c2 = st.columns(2)
        if c1.button("Approve", key="ap" + a["id"]):
            httpx.post(f"{API}/approvals/{a['id']}/approve", timeout=10)
            st.rerun()
        if c2.button("Deny", key="dn" + a["id"]):
            httpx.post(f"{API}/approvals/{a['id']}/deny", timeout=10)
            st.rerun()

with tab_bench:
    m = RESULTS / "metrics.json"
    if m.exists():
        res = json.loads(m.read_text())
        c = st.columns(5)
        c[0].metric("ASR off -> on", f"{res['off']['asr']:.0%} -> {res['on']['asr']:.1%}")
        c[1].metric("Detection (harmful calls)", f"{res['on']['detection_rate_high_risk']:.1%}")
        c[2].metric("FPR", f"{res['on']['fpr_scenarios']:.1%}")
        c[3].metric("Utility on", f"{res['on']['utility']:.1%}")
        c[4].metric("p95 overhead", f"{res['on']['latency_ms']['p95']:.2f} ms")
        for img in ("asr_before_after.png", "ablation.png", "latency_hist.png"):
            if (RESULTS / img).exists():
                st.image(str(RESULTS / img))
    else:
        st.info("Run `make bench` to produce results/metrics.json.")
