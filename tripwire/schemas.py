"""Pydantic models shared by the proxy, the agent and the benchmark."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _id() -> str:
    return uuid.uuid4().hex[:12]


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class ToolCall(BaseModel):
    """A tool call the agent wants to make."""

    session_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    call_id: str = Field(default_factory=_id)


class Highlight(BaseModel):
    """A span of an argument that matched something (taint, canary, pattern)."""

    field: str
    text: str
    why: str
    source_record: str | None = None


class DetectorResult(BaseModel):
    """Output of one detector: a score in [0, 1] plus human-readable reasons."""

    name: str
    score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    highlights: list[Highlight] = Field(default_factory=list)
    features: dict[str, float] = Field(default_factory=dict)


class Verdict(BaseModel):
    """The proxy's decision about a tool call."""

    call_id: str
    session_id: str
    tool: str
    decision: Decision
    rule: str
    risk: str
    score: float
    detectors: list[DetectorResult] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    approval_id: str | None = None

    def detector(self, name: str) -> DetectorResult | None:
        return next((d for d in self.detectors if d.name == name), None)


class ToolResult(BaseModel):
    """What the agent gets back from the proxy."""

    call_id: str
    tool: str
    executed: bool
    ok: bool
    output: str | None = None
    error: str | None = None
    verdict: Verdict | None = None
    overhead_ms: float = 0.0
    tool_ms: float = 0.0


class SessionCreate(BaseModel):
    system_prompt: str = ""
    user_turn: str | None = None
    session_id: str | None = None
    fixtures: dict[str, Any] | None = None  # benchmark-only sandbox fixtures


class UserTurn(BaseModel):
    text: str


class ToolRequest(BaseModel):
    session_id: str
    args: dict[str, Any] = Field(default_factory=dict)
    call_id: str | None = None
