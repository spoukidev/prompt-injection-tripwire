"""Taint tracking: remember everything untrusted that entered the agent's context.

Per session the proxy keeps:

* **trusted text** -- the system prompt and the user's turns. Indicators found
  there (URLs, hosts, e-mail addresses, file paths) are *trusted destinations*.
* **taint records** -- one per tool result: the raw text, its normalized form,
  word 5-gram fingerprints, the canary token planted in it, the indicators it
  mentions, and an *injection score* computed at ingest time.
* **contacts** -- sender addresses taken from e-mail *headers* (not bodies). The
  agent may legitimately reply to the person who wrote to it.
* **sensitive chunks** -- secrets the agent has read (``~/.ssh``, ``.env``) and
  the system prompt, so the exfil detector can recognise them leaving.

:meth:`SessionState.overlap` answers "how much of this outgoing text came from
untrusted content?" with n-gram containment for long text and rapidfuzz
``partial_ratio`` for short strings.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from rapidfuzz import fuzz

from tripwire.normalize import normalize

URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`)\]]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:test|com|net|org|io|dev|ai|co))\b", re.I)
PATH_RE = re.compile(r"(?:~|\.{0,2})/?(?:[\w.-]+/)+[\w.-]+|\b[\w-]+\.(?:md|txt|json|csv|yaml|yml|log|env)\b")
WORD_RE = re.compile(r"[a-z0-9]+")
NGRAM = 5


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def extract_indicators(text: str) -> dict[str, set[str]]:
    """Pull URLs, hosts, e-mail addresses and file paths out of text."""
    urls = {u.rstrip(".,;:!?").lower() for u in URL_RE.findall(text)}
    emails = {e.lower() for e in EMAIL_RE.findall(text)}
    hosts = {host_of(u) for u in urls} | {h.lower() for h in HOST_RE.findall(text)}
    hosts |= {e.split("@", 1)[1] for e in emails}
    text_wo_urls = URL_RE.sub(" ", text)
    paths = {normalize_path(p) for p in PATH_RE.findall(EMAIL_RE.sub(" ", text_wo_urls))}
    return {"urls": urls, "emails": emails, "hosts": {h for h in hosts if h}, "paths": {p for p in paths if p}}


def normalize_path(p: str) -> str:
    p = p.strip().strip("'\"`").rstrip(".,;:!?)").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lower()


def shingles(text: str, n: int = NGRAM) -> set[int]:
    words = WORD_RE.findall(text.lower())
    if len(words) < n:
        return set()
    return {hash(" ".join(words[i : i + n])) for i in range(len(words) - n + 1)}


@dataclass
class TaintRecord:
    id: str
    tool: str
    source: str
    raw: str
    norm: str
    canary: str
    shingles: set[int]
    indicators: dict[str, set[str]]
    injection_score: float = 0.0
    injection_reasons: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    created: float = field(default_factory=time.time)


@dataclass
class Overlap:
    score: float
    record_id: str | None = None
    span: str = ""


@dataclass
class SessionState:
    id: str
    system_prompt: str = ""
    trusted_texts: list[str] = field(default_factory=list)
    trusted: dict[str, set[str]] = field(default_factory=lambda: {"urls": set(), "emails": set(), "hosts": set(), "paths": set()})
    records: list[TaintRecord] = field(default_factory=list)
    contacts: set[str] = field(default_factory=set)
    sensitive_chunks: list[str] = field(default_factory=list)
    canaries: dict[str, str] = field(default_factory=dict)  # token -> record id
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ---------------------------------------------------------------- trusted
    def add_trusted(self, text: str, *, is_system: bool = False) -> None:
        self.trusted_texts.append(text)
        ind = extract_indicators(normalize(text, decode=False).text)
        for k, v in ind.items():
            self.trusted[k] |= v
        if is_system:
            self.system_prompt = text
            self.add_sensitive(text)

    def add_sensitive(self, text: str) -> None:
        """Register secret material; lines/sentences >= 12 chars become match chunks."""
        for piece in re.split(r"[\n.!?]+", text):
            piece = piece.strip()
            if len(piece) >= 12:
                self.sensitive_chunks.append(normalize(piece, decode=False).text.lower())

    # ---------------------------------------------------------------- tainted
    def add_record(self, rec: TaintRecord) -> None:
        with self.lock:
            self.records.append(rec)
            self.canaries[rec.canary] = rec.id

    def record(self, rid: str | None) -> TaintRecord | None:
        return next((r for r in self.records if r.id == rid), None)

    @property
    def tainted_indicators(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {"urls": set(), "emails": set(), "hosts": set(), "paths": set()}
        for r in self.records:
            for k, v in r.indicators.items():
                out[k] |= v
        return out

    def max_injection_score(self) -> float:
        return max((r.injection_score for r in self.records), default=0.0)

    def overlap(self, text: str, *, min_len: int = 8) -> Overlap:
        """How strongly does (normalized) ``text`` overlap with any tainted record?"""
        if not self.records or not text or len(text) < min_len:
            return Overlap(0.0)
        low = text.lower()
        best = Overlap(0.0)
        sh = shingles(low)
        for r in self.records:
            if sh and r.shingles:
                contain = len(sh & r.shingles) / len(sh)
                if contain > best.score:
                    best = Overlap(contain, r.id, text[:120])
            elif len(low) <= 400:
                if low in r.norm.lower():
                    return Overlap(1.0, r.id, text[:120])
                pr = fuzz.partial_ratio(low, r.norm.lower()) / 100.0
                # partial_ratio is generous on very short strings; damp it.
                pr *= min(1.0, len(low) / 40.0)
                if pr > best.score:
                    best = Overlap(pr, r.id, text[:120])
        return best

    def records_mentioning(self, kind: str, value: str) -> list[TaintRecord]:
        value = value.lower()
        return [r for r in self.records if value in r.indicators.get(kind, set())]


class TaintStore:
    """Thread-safe map of session id -> :class:`SessionState`."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()

    def create(self, system_prompt: str = "", user_turn: str | None = None, session_id: str | None = None) -> SessionState:
        sid = session_id or uuid.uuid4().hex[:16]
        s = SessionState(id=sid)
        if system_prompt:
            s.add_trusted(system_prompt, is_system=True)
        if user_turn:
            s.add_trusted(user_turn)
        with self._lock:
            self._sessions[sid] = s
        return s

    def get(self, sid: str) -> SessionState:
        with self._lock:
            if sid not in self._sessions:
                raise KeyError(sid)
            return self._sessions[sid]

    def drop(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def __len__(self) -> int:
        return len(self._sessions)
