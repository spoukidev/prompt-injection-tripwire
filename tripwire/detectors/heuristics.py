"""Rule-based instruction-likeness detector.

Ordinary text is full of imperatives ("preheat the oven", "click unsubscribe"),
so imperative mood alone is a weak signal. What distinguishes an *injection* is
text that addresses the AI agent itself, tries to change its instructions or
role, names its tools, asks for secrets, or tells it to hide things from the
user. Each pattern below has a weight; scores are combined with a noisy-OR::

    score = 1 - prod(1 - w_i)   over matched patterns (each pattern counted once)

Obfuscation found by :mod:`tripwire.normalize` (zero-width runs, Unicode tag
characters, hidden HTML) adds a small amount on its own, and more when the
decoded content itself matches an instruction pattern.
"""

from __future__ import annotations

import re

from tripwire.detectors.base import DetectionContext, Detector
from tripwire.schemas import DetectorResult

I = re.I | re.S

PATTERNS: list[tuple[str, float, re.Pattern[str]]] = [
    ("override_instructions", 0.85, re.compile(
        r"\b(ignore|disregard|forget|override|bypass|skip)\b\W+(?:\w+\W+){0,4}?(previous|prior|above|earlier|preceding|all|any|your|existing|original|system)\W+(?:\w+\W+){0,2}?"
        r"(instructions?|prompts?|rules|directives|guidelines|guardrails|constraints|policies|context|task)\b", I)),
    ("new_instructions", 0.6, re.compile(r"\b(new|updated|real|actual|revised|additional|hidden|secret|priority|urgent) (system )?(instructions?|directives?|task|orders)\b\s*[:\-]", I)),
    ("role_tag", 0.7, re.compile(r"(<\|?\s*(system|assistant|im_start|im_end|endoftext)\s*\|?>|\[/?INST\]|<<SYS>>|^\s*#{1,4}\s*(system|instruction)s?\b|(^|\n)\s*(SYSTEM|ASSISTANT|ADMIN|DEVELOPER)\s*(MESSAGE|PROMPT|NOTE|OVERRIDE)?\s*:)", re.M | re.I)),
    ("addresses_ai", 0.55, re.compile(
        r"\b(AI|A\.I\.|assistant|agent|language model|LLM|chat ?bot|GPT|copilot|automated (system|reader|tool))s?\b[^.\n]{0,80}?\b(must|should|need to|are (now )?required|will now|are instructed|has to|shall|please)\b", I)),
    ("vocative_imperative", 0.55, re.compile(
        r"\b(AI|assistant|agent|bot|chatbot|LLM|model)\s*[:),\-]\s*(?:please\s+)?(send|forward|post|append|write|delete|add|save|use|call|"
        r"email|upload|include|copy|read|reply|fetch|visit|open|run|tell|in your)\b", I)),
    ("if_you_are_ai", 0.7, re.compile(r"\b(if|when) you are (an? )?(AI|assistant|agent|language model|LLM|bot)\b|\bnote to (the )?(AI|assistant|agent|LLM|model)\b|\b(dear|hey|attention|hello) (AI|assistant|agent|LLM|model|bot)\b", I)),
    ("tool_directive", 0.6, re.compile(
        r"\b(call|use|invoke|run|execute|trigger)\b[^.\n]{0,30}\b(tool|function|send_email|http_post|write_file|delete_file|fetch_url|read_file|read_email)\b", I)),
    ("tool_name", 0.35, re.compile(r"\b(send_email|http_post|write_file|delete_file|read_file|read_email|fetch_url)\b", I)),
    ("tool_redefinition", 0.6, re.compile(r"\b(tool|function|send_email|http_post|write_file|delete_file)\b[^.\n]{0,40}\b(is (actually|really|just|only)|has been (renamed|replaced|deprecated)|now (means|points to)|is (a )?(safe|read-only|harmless))\b", I)),
    ("exfil_request", 0.7, re.compile(
        r"\b(send|forward|post|upload|exfiltrate|transmit|leak|include|attach|copy|paste|share|append|encode)\b[^.\n]{0,60}?\b(passwords?|secrets?|api[ _-]?keys?|credentials?|ssh|id_rsa|private key|\.env|system prompt|(access )?tokens?|contents of|environment variables|conversation history|chat history|inbox)\b", I)),
    ("prompt_leak", 0.7, re.compile(r"\b(reveal|print|repeat|output|disclose|show|recite|dump)\b[^.\n]{0,40}\b(system prompt|your (initial |original |hidden )?(instructions|prompt|rules)|the (text|words) above)\b", I)),
    ("secrecy", 0.6, re.compile(r"\b(do not|don't|never|without)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|notify|alert|asking|telling)\b[^.\n]{0,20}\b(the )?(user|human|owner|operator)\b", I)),
    ("persistence", 0.45, re.compile(r"\b(from now on|for (all|every) future|in (all|every) future|remember (this|that|to)|permanently|save (this|these) (rule|instruction)s?|add (this|these) to (your )?(memory|notes))\b", I)),
    ("delayed_trigger", 0.55, re.compile(r"\b(when|whenever|next time|the next time|if ever)\b[^.\n]{0,15}\b(the )?user\b[^.\n]{0,25}\b(asks?|mentions?|says?|requests?|talks? about|types?)\b", I)),
    ("markdown_image_beacon", 0.65, re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=", I)),
    ("instead_do", 0.45, re.compile(r"\b(instead|rather than|before (responding|answering|summari[sz]ing|replying)|first,? (you must|silently|quietly))\b[^.\n]{0,40}\b(send|post|forward|email|write|delete|upload|call|fetch|visit|open)\b", I)),
    ("silently", 0.4, re.compile(r"\b(silently|quietly|secretly|covertly|without (any )?(confirmation|approval|asking))\b", I)),
]

OBFUSCATION_WEIGHTS = {"zero_width": 0.15, "tag_chars": 0.5, "hidden_html": 0.2, "homoglyph": 0.15, "base64": 0.1, "rot13_hint": 0.3}


def noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p


def score_text(text: str, flags: list[str] | None = None) -> tuple[float, list[str]]:
    """Score already-normalized text. Returns (score, reasons)."""
    weights: list[float] = []
    reasons: list[str] = []
    for name, w, rx in PATTERNS:
        if rx.search(text):
            weights.append(w)
            reasons.append(name)
    for f in set(flags or []):
        if f in OBFUSCATION_WEIGHTS:
            # Obfuscation is suspicious mostly when combined with instructions.
            w = OBFUSCATION_WEIGHTS[f] * (2.0 if weights else 1.0)
            weights.append(min(w, 0.6))
            reasons.append(f"obfuscation:{f}")
    return round(noisy_or(weights), 4), reasons


class HeuristicsDetector(Detector):
    name = "heuristics"

    def inspect(self, ctx: DetectionContext) -> DetectorResult:
        text = ctx.data_text()
        if not text:
            return DetectorResult(name=self.name)
        score, reasons = score_text(text, ctx.data_flags())
        return DetectorResult(name=self.name, score=score, reasons=reasons)

    def score_text(self, text: str, flags: list[str] | None = None) -> DetectorResult:
        score, reasons = score_text(text, flags)
        return DetectorResult(name=self.name, score=score, reasons=reasons)
