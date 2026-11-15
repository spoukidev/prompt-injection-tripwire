"""FastAPI proxy: ``/tool/{name}`` endpoints in front of the (sandboxed) tools.

    uvicorn tripwire.server:app --port 8080

Endpoints
---------
``POST /session``                 create a session (system prompt + first user turn)
``POST /session/{id}/turn``       add a trusted user turn
``POST /tool/{name}``             inspect -> (execute) -> taint; returns ToolResult
``GET  /audit``                   recent audit records
``GET  /approvals``               approval queue; ``POST /approvals/{id}/approve|deny``
``GET  /policy`` / ``GET /health``

Environment
-----------
``TRIPWIRE_POLICY``        policy YAML path (default config/policy.yaml)
``TRIPWIRE_DB``            SQLAlchemy URL for the audit DB (default sqlite:///results/audit.db)
``TRIPWIRE_APPROVAL_MODE`` queue | auto_deny | auto_allow (overrides the policy file)
``TRIPWIRE_BENCH_MODE=1``  allow per-session sandbox fixtures (benchmark only)
``TRIPWIRE_ALLOW_BYPASS=1`` honour ``X-Tripwire-Bypass: 1`` to measure the bare agent
                           (benchmark only -- never enable in a real deployment)
"""

from __future__ import annotations

import json
import os
import time
from collections import OrderedDict

from fastapi import FastAPI, Header, HTTPException

from agent.tools import Sandbox
from tripwire import __version__
from tripwire.engine import Tripwire
from tripwire.schemas import SessionCreate, ToolCall, ToolRequest, ToolResult, UserTurn

app = FastAPI(title="Prompt-Injection Tripwire", version=__version__,
              description="Interception proxy that detects indirect prompt injection in tool-using agents.")
TW = Tripwire(approval_mode=os.environ.get("TRIPWIRE_APPROVAL_MODE"))
BENCH = os.environ.get("TRIPWIRE_BENCH_MODE") == "1"
ALLOW_BYPASS = os.environ.get("TRIPWIRE_ALLOW_BYPASS") == "1"
MAX_SESSIONS = 1000
SANDBOXES: "OrderedDict[str, Sandbox]" = OrderedDict()


def _sandbox(sid: str) -> Sandbox:
    if sid not in SANDBOXES:
        raise HTTPException(404, f"unknown session {sid}")
    return SANDBOXES[sid]


@app.get("/health")
def health() -> dict:
    return {"ok": True, "version": __version__, "sessions": len(SANDBOXES), "approval_mode": TW.approval_mode,
            "classifier": TW.classifier.available, "detectors": [d.name for d in TW.detectors]}


@app.get("/policy")
def policy() -> dict:
    return TW.policy


@app.post("/session")
def create_session(body: SessionCreate) -> dict:
    fx = (body.fixtures or {}) if BENCH else {}
    sid = TW.new_session(body.system_prompt, body.user_turn, body.session_id)
    old_sb = SANDBOXES.pop(sid, None)
    if old_sb is not None:  # session id reused: don't leak the previous sandbox's temp dir
        old_sb.close()
    SANDBOXES[sid] = Sandbox(mailbox=fx.get("mailbox"), files=fx.get("files"))
    while len(SANDBOXES) > MAX_SESSIONS:
        old, sb = SANDBOXES.popitem(last=False)
        sb.close()
        TW.sessions.drop(old)
    return {"session_id": sid}


@app.post("/session/{sid}/turn")
def user_turn(sid: str, body: UserTurn) -> dict:
    _sandbox(sid)
    TW.add_user_turn(sid, body.text)
    return {"ok": True}


@app.get("/session/{sid}/sandbox")
def sandbox_state(sid: str) -> dict:
    sb = _sandbox(sid)
    return {"outbox": sb.outbox, "posts": sb.posts, "executed": sb.executed}


@app.get("/session/{sid}/taint")
def taint_state(sid: str) -> dict:
    s = TW.session(sid)
    return {"trusted": {k: sorted(v) for k, v in s.trusted.items()}, "contacts": sorted(s.contacts),
            "records": [{"id": r.id, "source": r.source, "injection_score": r.injection_score,
                         "reasons": r.injection_reasons, "flags": r.flags, "excerpt": r.norm[:300]} for r in s.records]}


@app.post("/tool/{name}", response_model=ToolResult)
def tool(name: str, body: ToolRequest, x_tripwire_bypass: str | None = Header(default=None)) -> ToolResult:
    sb = _sandbox(body.session_id)
    if x_tripwire_bypass == "1":
        if not ALLOW_BYPASS:
            raise HTTPException(403, "bypass is disabled (set TRIPWIRE_ALLOW_BYPASS=1 for benchmarks only)")
        t0 = time.perf_counter()
        try:
            out = sb.call(name, body.args)
            return ToolResult(call_id="bypass", tool=name, executed=True, ok=True, output=out, tool_ms=(time.perf_counter() - t0) * 1000)
        except Exception as e:
            return ToolResult(call_id="bypass", tool=name, executed=True, ok=False, error=str(e))
    call = ToolCall(session_id=body.session_id, tool=name, args=body.args, **({"call_id": body.call_id} if body.call_id else {}))
    return TW.handle(call, sb.call)


@app.get("/audit")
def audit(limit: int = 200, session_id: str | None = None) -> list[dict]:
    if not TW.audit:
        return []
    out = []
    for r in TW.audit.recent(limit, session_id):
        d = r.model_dump()
        for k in ("args_json", "detectors_json", "reasons_json"):
            d[k.replace("_json", "")] = json.loads(d.pop(k))
        out.append(d)
    return out


@app.get("/approvals")
def approvals(status: str | None = "pending") -> list[dict]:
    return [a.model_dump() for a in TW.audit.approvals(status)] if TW.audit else []


@app.post("/approvals/{approval_id}/{action}")
def resolve(approval_id: str, action: str) -> dict:
    if action not in ("approve", "deny"):
        raise HTTPException(400, "action must be approve or deny")
    res = TW.resolve(approval_id, approve=action == "approve")
    if res is None:
        raise HTTPException(404, "no pending approval with that id (already resolved or proxy restarted)")
    return res.model_dump()
