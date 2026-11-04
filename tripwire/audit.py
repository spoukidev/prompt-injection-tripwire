"""SQLite audit log (SQLModel) plus structured JSON-lines logging.

Every inspected tool call becomes an :class:`AuditRecord` with its arguments,
per-detector scores, taint highlights and the decision. ``require_approval``
calls also get an :class:`Approval` row that the dashboard can approve/deny.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from sqlmodel import Field, Session, SQLModel, create_engine, select

from tripwire import canary as canary_mod
from tripwire.schemas import ToolCall, Verdict

log = logging.getLogger("tripwire")
if not log.handlers:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    log.setLevel(os.environ.get("TRIPWIRE_LOG_LEVEL", "WARNING"))


class AuditRecord(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ts: float = Field(index=True)
    session_id: str = Field(index=True)
    call_id: str = Field(index=True)
    tool: str
    risk: str
    decision: str = Field(index=True)
    rule: str
    score: float
    args_json: str
    detectors_json: str
    reasons_json: str
    latency_ms: float
    executed: bool = False


class Approval(SQLModel, table=True):
    id: str = Field(primary_key=True)
    ts: float
    session_id: str
    call_id: str
    tool: str
    args_json: str
    reasons_json: str
    status: str = Field(default="pending", index=True)  # pending | approved | denied
    decided_ts: float | None = None
    result_json: str | None = None


def _safe_args(args: dict[str, Any]) -> str:
    """Store args with canaries made visible ("⟦canary⟧") so humans can see them."""
    def fix(v: Any) -> Any:
        if isinstance(v, str):
            out = v
            for h in reversed(canary_mod.find_tokens(v)):
                out = out[: h.start] + f"⟦canary:{h.token}⟧" + out[h.end :]
            return out
        if isinstance(v, dict):
            return {k: fix(x) for k, x in v.items()}
        if isinstance(v, list):
            return [fix(x) for x in v]
        return v
    return json.dumps(fix(args), ensure_ascii=False, default=str)[:20000]


class AuditLog:
    def __init__(self, db_url: str | None = None) -> None:
        url = db_url or os.environ.get("TRIPWIRE_DB", "sqlite:///results/audit.db")
        if url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:"):
            Path(url[len("sqlite:///"):]).parent.mkdir(parents=True, exist_ok=True)
        kw = {"poolclass": StaticPool} if ":memory:" in url else {}
        self.engine = create_engine(url, connect_args={"check_same_thread": False}, **kw)

        @event.listens_for(self.engine, "connect")
        def _pragmas(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

        SQLModel.metadata.create_all(self.engine)

    def record(self, call: ToolCall, verdict: Verdict, executed: bool) -> None:
        rec = AuditRecord(
            ts=time.time(), session_id=call.session_id, call_id=call.call_id, tool=call.tool, risk=verdict.risk,
            decision=verdict.decision.value, rule=verdict.rule, score=verdict.score, args_json=_safe_args(call.args),
            detectors_json=json.dumps([d.model_dump() for d in verdict.detectors], default=str),
            reasons_json=json.dumps(verdict.reasons), latency_ms=verdict.latency_ms, executed=executed)
        with Session(self.engine) as s:
            s.add(rec)
            s.commit()
        log.info(json.dumps({"event": "tool_call", "session": call.session_id, "tool": call.tool,
                             "decision": verdict.decision.value, "rule": verdict.rule, "score": verdict.score,
                             "reasons": verdict.reasons[:5], "latency_ms": round(verdict.latency_ms, 2)}))

    def mark_executed(self, call_id: str) -> None:
        with Session(self.engine) as s:
            for r in s.exec(select(AuditRecord).where(AuditRecord.call_id == call_id)):
                r.executed = True
                s.add(r)
            s.commit()

    # ------------------------------------------------------------ approvals
    def add_approval(self, approval_id: str, call: ToolCall, verdict: Verdict) -> None:
        with Session(self.engine) as s:
            s.add(Approval(id=approval_id, ts=time.time(), session_id=call.session_id, call_id=call.call_id,
                           tool=call.tool, args_json=json.dumps(call.args, default=str),
                           reasons_json=json.dumps(verdict.reasons)))
            s.commit()

    def set_approval(self, approval_id: str, status: str, result: dict | None = None) -> Approval | None:
        with Session(self.engine) as s:
            a = s.get(Approval, approval_id)
            if a is None:
                return None
            a.status, a.decided_ts = status, time.time()
            if result is not None:
                a.result_json = json.dumps(result, default=str)
            s.add(a)
            s.commit()
            s.refresh(a)
            return a

    def approvals(self, status: str | None = None) -> list[Approval]:
        with Session(self.engine) as s:
            q = select(Approval).order_by(Approval.ts.desc())
            if status:
                q = q.where(Approval.status == status)
            return list(s.exec(q))

    def recent(self, limit: int = 200, session_id: str | None = None) -> list[AuditRecord]:
        with Session(self.engine) as s:
            q = select(AuditRecord).order_by(AuditRecord.id.desc()).limit(limit)
            if session_id:
                q = q.where(AuditRecord.session_id == session_id)
            return list(s.exec(q))
