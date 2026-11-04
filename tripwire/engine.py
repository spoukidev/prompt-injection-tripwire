"""The Tripwire engine: inspect -> decide -> (execute) -> taint -> audit.

This module is transport-agnostic. ``tripwire.server`` wraps it in FastAPI and
the benchmark can call it in-process; both paths run exactly the same code.

Pipeline for one tool call::

    agent ──call──▶ inspect(call)              detectors + YAML policy -> Verdict
                     │ allow                    │ block / require_approval
                     ▼                          ▼
                 executor(tool, args)        error result (+ approval queue)
                     │
                     ▼
                 ingest(result)               normalize, score, taint, plant canary
                     │
    agent ◀──result (with canary)─┘           audit log written for every call
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from tripwire import canary as canary_mod
from tripwire.audit import AuditLog
from tripwire.detectors.base import DetectionContext, path_matches
from tripwire.detectors.canary_leak import CanaryLeakDetector
from tripwire.detectors.classifier import ClassifierDetector
from tripwire.detectors.exfil import ExfilDetector
from tripwire.detectors.heuristics import HeuristicsDetector, noisy_or
from tripwire.detectors.llm_judge import LLMJudgeDetector
from tripwire.normalize import normalize
from tripwire.policy import combined_score, decide, load_policy, signals_from, tool_config
from tripwire.schemas import Decision, ToolCall, ToolResult, Verdict
from tripwire.taint import SessionState, TaintRecord, TaintStore, extract_indicators, shingles

Executor = Callable[[str, dict[str, Any]], str]


class Tripwire:
    def __init__(self, policy: dict | str | None = None, *, audit: AuditLog | None | bool = None,
                 disabled: set[str] | None = None, approval_mode: str | None = None) -> None:
        self.policy = policy if isinstance(policy, dict) else load_policy(policy)
        self.approval_mode = approval_mode or self.policy.get("approval_mode", "queue")
        self.disabled = set(disabled or ())
        dcfg = self.policy.get("detectors", {})
        thr = float(self.policy.get("injection_threshold", 0.5))
        self.injection_threshold = thr
        self.heuristics = HeuristicsDetector(dcfg.get("heuristics"))
        self.classifier = ClassifierDetector(dcfg.get("classifier"))
        self.detectors = [d for d in (
            CanaryLeakDetector(dcfg.get("canary_leak")),
            self.heuristics,
            self.classifier,
            ExfilDetector(dcfg.get("exfil"), injection_threshold=thr),
        ) if d.name not in self.disabled and dcfg.get(d.name, {}).get("enabled", True)]
        self.judge = LLMJudgeDetector(dcfg.get("llm_judge"))
        self.sessions = TaintStore()
        self.audit = AuditLog() if audit is None or audit is True else (audit or None)
        self.pending: dict[str, tuple[ToolCall, Executor | None]] = {}
        ccfg = self.policy.get("canary", {})
        self.canary_visible = bool(ccfg.get("visible", False))
        self.canary_every = int(ccfg.get("every_chars", 160))

    # ------------------------------------------------------------- sessions
    def new_session(self, system_prompt: str = "", user_turn: str | None = None, session_id: str | None = None) -> str:
        return self.sessions.create(system_prompt, user_turn, session_id).id

    def add_user_turn(self, session_id: str, text: str) -> None:
        self.sessions.get(session_id).add_trusted(text)

    def session(self, session_id: str) -> SessionState:
        return self.sessions.get(session_id)

    # -------------------------------------------------------------- scoring
    def score_content(self, text: str, flags: list[str]) -> tuple[float, list[str]]:
        """Ingest-time injection score for untrusted content (heuristics + classifier)."""
        scores, reasons = [], []
        if "heuristics" not in self.disabled:
            h = self.heuristics.score_text(text, flags)
            scores.append(h.score)
            reasons += h.reasons
        if "classifier" not in self.disabled and self.classifier.available:
            c = self.classifier.score_text(text, flags)
            scores.append(c.score)
            reasons += c.reasons
        # Agreement between the two raises confidence; either alone is capped by itself.
        return (round(max(max(scores, default=0.0), noisy_or([s * 0.6 for s in scores])), 4), reasons)

    # -------------------------------------------------------------- inspect
    def inspect(self, call: ToolCall) -> Verdict:
        t0 = time.perf_counter()
        s = self.sessions.get(call.session_id)
        tcfg = tool_config(self.policy, call.tool)
        ctx = DetectionContext.build(s, call.tool, call.args, tcfg, self.policy)
        results = [d.inspect(ctx) for d in self.detectors]
        extra = {
            "memory_write": 1.0 if call.tool == "write_file" and ctx.is_memory_path(str(call.args.get("path", ""))) else 0.0,
            "sensitive_read": 1.0 if call.tool == "read_file" and ctx.is_sensitive_path(str(call.args.get("path", ""))) else 0.0,
            "session_injection": s.max_injection_score(),
        }
        signals = signals_from(results, extra)
        decision, rule = decide(self.policy, call.tool, signals)
        if decision != Decision.ALLOW and self.judge.config.get("enabled") and "llm_judge" not in self.disabled:
            jr = self.judge.inspect(ctx)
            results.append(jr)
            signals = signals_from(results, extra)
            decision, rule = decide(self.policy, call.tool, signals)
        reasons = [f"{r.name}: {why}" for r in results for why in r.reasons if r.score > 0 or r.name == "exfil"]
        v = Verdict(call_id=call.call_id, session_id=call.session_id, tool=call.tool, decision=decision, rule=rule,
                    risk=str(tcfg.get("risk", "high")), score=combined_score(results, self.policy.get("weights", {})),
                    detectors=results, reasons=reasons, latency_ms=(time.perf_counter() - t0) * 1000)
        return v

    # --------------------------------------------------------------- ingest
    def ingest(self, session_id: str, tool: str, args: dict[str, Any], output: str) -> str:
        """Taint a tool result, score it, plant a canary. Returns what the agent should see."""
        s = self.sessions.get(session_id)
        n = normalize(output)
        inj, inj_reasons = self.score_content(n.text, n.flags)
        token = canary_mod.new_token()
        source = f"{tool}:{args.get('url') or args.get('path') or args.get('folder') or args.get('id') or ''}"
        rec = TaintRecord(id=uuid.uuid4().hex[:10], tool=tool, source=source, raw=output, norm=n.text, canary=token,
                          shingles=shingles(n.text), indicators=extract_indicators(n.text), injection_score=inj,
                          injection_reasons=inj_reasons, flags=n.flags)
        s.add_record(rec)
        if tool == "read_email":
            s.contacts |= _email_senders(output)
        if tool == "read_file" and path_matches(str(args.get("path", "")), self.policy.get("sensitive_paths", [])):
            s.add_sensitive(output)
        if "canary_leak" in self.disabled:
            return output
        return self._plant(output, token)

    def _plant(self, output: str, token: str) -> str:
        """Plant canaries. JSON results get canaries inside their string values so they stay valid JSON."""
        stripped = output.lstrip()
        if stripped[:1] in "{[":
            try:
                data = json.loads(output)
            except ValueError:
                data = None
            if data is not None:
                def walk(v: Any) -> Any:
                    if isinstance(v, str) and len(v) >= 20:
                        return canary_mod.plant(v, token, every=self.canary_every, visible=self.canary_visible)
                    if isinstance(v, dict):
                        return {k: walk(x) for k, x in v.items()}
                    if isinstance(v, list):
                        return [walk(x) for x in v]
                    return v
                return json.dumps(walk(data), ensure_ascii=False)
        return canary_mod.plant(output, token, every=self.canary_every, visible=self.canary_visible)

    # --------------------------------------------------------------- handle
    def handle(self, call: ToolCall, executor: Executor) -> ToolResult:
        """Full pipeline for one call. ``executor(tool, args) -> str`` runs the real tool."""
        t0 = time.perf_counter()
        verdict = self.inspect(call)
        approval_id = None
        if verdict.decision == Decision.REQUIRE_APPROVAL:
            if self.approval_mode == "auto_allow":
                verdict.reasons.append("approval auto-granted (auto_allow mode)")
            elif self.approval_mode == "queue":
                approval_id = uuid.uuid4().hex[:10]
                verdict.approval_id = approval_id
                self.pending[approval_id] = (call, executor)
        allowed = verdict.decision == Decision.ALLOW or (
            verdict.decision == Decision.REQUIRE_APPROVAL and self.approval_mode == "auto_allow")
        if self.audit:
            self.audit.record(call, verdict, executed=allowed)
            if approval_id:
                self.audit.add_approval(approval_id, call, verdict)
        if not allowed:
            msg = (f"Tool call blocked by Prompt-Injection Tripwire (rule '{verdict.rule}')" if verdict.decision == Decision.BLOCK
                   else f"Tool call held for human approval (rule '{verdict.rule}', approval id {approval_id or 'n/a'})")
            return ToolResult(call_id=call.call_id, tool=call.tool, executed=False, ok=False, error=msg, verdict=verdict,
                              overhead_ms=(time.perf_counter() - t0) * 1000)
        pre = time.perf_counter() - t0
        t1 = time.perf_counter()
        try:
            output = executor(call.tool, call.args)
            ok, err = True, None
        except Exception as e:  # tool errors are returned to the agent, not raised
            output, ok, err = None, False, f"{type(e).__name__}: {e}"
        tool_ms = (time.perf_counter() - t1) * 1000
        t2 = time.perf_counter()
        if ok and output is not None:
            output = self.ingest(call.session_id, call.tool, call.args, str(output))
        post = time.perf_counter() - t2
        return ToolResult(call_id=call.call_id, tool=call.tool, executed=True, ok=ok, output=output, error=err,
                          verdict=verdict, overhead_ms=(pre + post) * 1000, tool_ms=tool_ms)

    # ------------------------------------------------------------ approvals
    def resolve(self, approval_id: str, approve: bool) -> ToolResult | None:
        item = self.pending.pop(approval_id, None)
        if item is None:
            return None
        call, executor = item
        if not approve or executor is None:
            if self.audit:
                self.audit.set_approval(approval_id, "denied")
            return ToolResult(call_id=call.call_id, tool=call.tool, executed=False, ok=False, error="denied by human reviewer")
        output = executor(call.tool, call.args)
        output = self.ingest(call.session_id, call.tool, call.args, str(output))
        if self.audit:
            self.audit.set_approval(approval_id, "approved", {"output": output[:2000]})
            self.audit.mark_executed(call.call_id)
        return ToolResult(call_id=call.call_id, tool=call.tool, executed=True, ok=True, output=output)


def _email_senders(output: str) -> set[str]:
    """Sender addresses from the structured (JSON) read_email result -- headers only, never bodies."""
    try:
        data = json.loads(output)
    except (ValueError, TypeError):
        return set()
    msgs = data.get("messages", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    out = set()
    for m in msgs:
        if isinstance(m, dict) and isinstance(m.get("from"), str):
            out |= {e.lower() for e in extract_indicators(m["from"])["emails"]}
    return out
