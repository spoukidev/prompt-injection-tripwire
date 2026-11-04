"""Detector interface.

A detector receives a :class:`DetectionContext` describing one outgoing tool call
(raw and normalized argument values, which fields are *destinations* and which
are *data*, the session's taint state, and the loaded policy) and returns a
:class:`~tripwire.schemas.DetectorResult` with a score in ``[0, 1]``.

Detectors must be fast (the whole pipeline has a p95 budget of 50 ms) and must
not perform network I/O, except the optional LLM judge.
"""

from __future__ import annotations

import fnmatch
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from tripwire import canary as canary_mod
from tripwire.normalize import Normalized, normalize
from tripwire.schemas import DetectorResult
from tripwire.taint import SessionState


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return "\n".join(_flatten(v) for v in value)
    return "" if value is None else str(value)


def path_matches(path: str, patterns: list[str]) -> bool:
    p = path.lower().lstrip("./")
    return any(fnmatch.fnmatch(p, pat.lower()) or fnmatch.fnmatch("/" + p, pat.lower()) for pat in patterns)


@dataclass
class DetectionContext:
    session: SessionState
    tool: str
    args: dict[str, Any]
    tool_cfg: dict[str, Any]
    policy: dict[str, Any]
    raw: dict[str, str] = field(default_factory=dict)
    norm: dict[str, Normalized] = field(default_factory=dict)

    @classmethod
    def build(cls, session: SessionState, tool: str, args: dict[str, Any], tool_cfg: dict, policy: dict) -> "DetectionContext":
        raw = {k: _flatten(v) for k, v in args.items()}
        # Our own canaries are zero-width runs; strip them so they don't look like obfuscation.
        norm = {k: normalize(canary_mod.strip_tokens(v)) for k, v in raw.items()}
        return cls(session, tool, args, tool_cfg, policy, raw, norm)

    @property
    def destination_fields(self) -> list[str]:
        return [f for f in self.tool_cfg.get("destination_fields", []) if f in self.raw]

    @property
    def data_fields(self) -> list[str]:
        declared = self.tool_cfg.get("data_fields")
        if declared:
            return [f for f in declared if f in self.raw]
        # Unknown tool: every non-destination argument is data.
        return [f for f in self.raw if f not in self.destination_fields]

    def data_text(self) -> str:
        return "\n".join(self.norm[f].text for f in self.data_fields)

    def data_flags(self) -> list[str]:
        out: list[str] = []
        for f in self.data_fields:
            out += self.norm[f].flags
        return out

    def is_memory_path(self, path: str) -> bool:
        return path_matches(path, self.policy.get("memory_paths", []))

    def is_sensitive_path(self, path: str) -> bool:
        return path_matches(path, self.policy.get("sensitive_paths", []))


class Detector(ABC):
    name: str = "base"

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}

    @abstractmethod
    def inspect(self, ctx: DetectionContext) -> DetectorResult:
        """Score one outgoing tool call."""

    def score_text(self, text: str, flags: list[str] | None = None) -> DetectorResult:
        """Optional: score arbitrary text (used to score tool *results* at ingest)."""
        return DetectorResult(name=self.name)
