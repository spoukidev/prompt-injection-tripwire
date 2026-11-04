"""Canary tokens: invisible, session-scoped markers planted in untrusted content.

Every untrusted tool result gets a fresh token. The token is encoded as a run of
zero-width characters (invisible when rendered and to most humans, but carried
along whenever text is copied verbatim)::

    U+2063 <48 bits as U+200B (0) / U+200C (1)> U+2064

If a later *outgoing* tool call contains one of the session's tokens, then text
that originated in untrusted content is being pushed into a tool, verbatim. That
is strong evidence of data flow from an untrusted source; whether it is
*malicious* depends on which argument it lands in (see ``canary_leak`` detector).

A visible form ``⟦c:0123456789ab⟧`` is also supported (``visible=True``) for demos
and for agents whose tokenizer drops zero-width characters.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

ZW0, ZW1, START, END = "\u200b", "\u200c", "\u2063", "\u2064"
TOKEN_BITS = 48
_ZW_CANARY_RE = re.compile(START + "([" + ZW0 + ZW1 + "]{" + str(TOKEN_BITS) + "})" + END)
_VISIBLE_RE = re.compile(r"⟦c:([0-9a-f]{12})⟧")


def new_token() -> str:
    """Return a fresh 12-hex-char (48-bit) token."""
    return uuid.uuid4().hex[:12]


def encode_zero_width(token: str) -> str:
    bits = bin(int(token, 16))[2:].zfill(TOKEN_BITS)
    return START + "".join(ZW1 if b == "1" else ZW0 for b in bits) + END


def decode_zero_width(run: str) -> str:
    bits = "".join("1" if c == ZW1 else "0" for c in run)
    return format(int(bits, 2), "012x")


def render(token: str, visible: bool = False) -> str:
    return f"⟦c:{token}⟧" if visible else encode_zero_width(token)


@dataclass
class CanaryHit:
    token: str
    start: int
    end: int


def find_tokens(text: str) -> list[CanaryHit]:
    """Find every canary (either encoding) in ``text``."""
    if not isinstance(text, str):
        return []
    hits = [CanaryHit(decode_zero_width(m.group(1)), m.start(), m.end()) for m in _ZW_CANARY_RE.finditer(text)]
    hits += [CanaryHit(m.group(1), m.start(), m.end()) for m in _VISIBLE_RE.finditer(text)]
    return hits


# A canary cut in half by truncation (e.g. an agent copying the first 300 chars).
_PARTIAL_RE = re.compile(START + "[" + ZW0 + ZW1 + "]*" + END + "?|[" + ZW0 + ZW1 + "]{8,}" + END)


def strip_tokens(text: str) -> str:
    """Remove canaries, including truncated fragments (for display and before normalization)."""
    return _PARTIAL_RE.sub("", _VISIBLE_RE.sub("", _ZW_CANARY_RE.sub("", text)))


def plant(text: str, token: str, *, every: int = 160, visible: bool = False) -> str:
    """Plant ``token`` at the start of ``text`` and then roughly every ``every`` chars.

    Tokens are only inserted at whitespace that is *outside* HTML tags, so the
    markup stays valid and any excerpt the agent copies is likely to carry one.
    """
    if not text:
        return render(token, visible)
    mark = render(token, visible)
    out = [mark]
    in_tag = False
    since = 0
    for ch in text:
        if ch == "<":
            in_tag = True
        elif ch == ">":
            in_tag = False
        out.append(ch)
        since += 1
        if not in_tag and since >= every and ch in " \n":
            out.append(mark)
            since = 0
    return "".join(out)
