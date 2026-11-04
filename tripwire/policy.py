"""Policy engine: turn detector scores into allow / block / require_approval.

The YAML file (``config/policy.yaml``) lists, per tool, a risk level, which
arguments are *destinations* vs *data*, and an ordered list of rules. Each rule
has a ``when`` mapping of signal -> condition; all conditions must hold. The
first matching rule wins. A rule without ``when`` always matches (use it last).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from tripwire.schemas import Decision, DetectorResult

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "policy.yaml"
_COND_RE = re.compile(r"^\s*(>=|<=|==|!=|>|<)?\s*(-?\d+(\.\d+)?)\s*$")


def load_policy(path: str | os.PathLike | None = None) -> dict[str, Any]:
    p = Path(path or os.environ.get("TRIPWIRE_POLICY") or DEFAULT_POLICY)
    with open(p, encoding="utf-8") as fh:
        policy = yaml.safe_load(fh)
    validate_policy(policy)
    return policy


def validate_policy(policy: dict[str, Any]) -> None:
    if not isinstance(policy, dict) or "tools" not in policy:
        raise ValueError("policy must be a mapping with a 'tools' key")
    for name, cfg in list(policy["tools"].items()) + [("default_tool", policy.get("default_tool", {"rules": []}))]:
        for rule in cfg.get("rules", []):
            if rule.get("action") not in {d.value for d in Decision}:
                raise ValueError(f"{name}: rule {rule.get('name')} has invalid action {rule.get('action')!r}")
            for sig, cond in (rule.get("when") or {}).items():
                parse_condition(cond)


def parse_condition(cond: Any) -> tuple[str, float]:
    if isinstance(cond, (int, float)):
        return ">=", float(cond)
    m = _COND_RE.match(str(cond))
    if not m:
        raise ValueError(f"bad condition {cond!r}")
    return m.group(1) or ">=", float(m.group(2))


def check(value: float, cond: Any) -> bool:
    op, thr = parse_condition(cond)
    return {">=": value >= thr, "<=": value <= thr, "==": abs(value - thr) < 1e-9, "!=": abs(value - thr) >= 1e-9,
            ">": value > thr, "<": value < thr}[op]


def tool_config(policy: dict[str, Any], tool: str) -> dict[str, Any]:
    return policy["tools"].get(tool) or policy.get("default_tool") or {"risk": "high", "rules": []}


def signals_from(results: list[DetectorResult], extra: dict[str, float] | None = None) -> dict[str, float]:
    """Flatten detector scores and features into the signal dict rules are evaluated on."""
    sig: dict[str, float] = {}
    for r in results:
        sig[r.name] = r.score
        for k, v in r.features.items():
            sig.setdefault(k, v)
    sig["canary"] = sig.get("canary_leak", 0.0)
    sig["instruction"] = max(sig.get("heuristics", 0.0), sig.get("classifier", 0.0))
    if extra:
        sig.update(extra)
    return sig


def combined_score(results: list[DetectorResult], weights: dict[str, float]) -> float:
    p = 1.0
    for r in results:
        p *= 1.0 - min(1.0, r.score * weights.get(r.name, 0.5))
    return round(1.0 - p, 4)


def decide(policy: dict[str, Any], tool: str, signals: dict[str, float]) -> tuple[Decision, str]:
    """Walk the tool's rules; return (decision, rule name)."""
    for rule in tool_config(policy, tool).get("rules", []):
        when = rule.get("when") or {}
        if all(check(signals.get(k, 0.0), c) for k, c in when.items()):
            return Decision(rule["action"]), rule.get("name", "unnamed")
    return Decision.ALLOW, "no-rule-matched"
