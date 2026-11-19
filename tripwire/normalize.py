"""Text normalization applied before any detector scans text.

Attackers hide instructions with cheap obfuscation: zero-width characters,
Unicode "tag" characters (ASCII smuggling), homoglyphs (Cyrillic ``е`` for Latin
``e``), HTML entities, URL encoding, base64 and ROT13. Detectors should not need
to know about any of that, so everything they see is first passed through
:func:`normalize`, which returns a canonical text plus a list of *flags*
describing which obfuscations were found (the flags are themselves a signal).

Design rules:

* :func:`normalize` must never raise, whatever the input (fuzzed with hypothesis).
* The canonical output never contains zero-width / bidi / tag characters.
* Decoded payloads (base64, ROT13, hidden HTML) are *appended* to the canonical
  text rather than replacing it, so detectors see both the surface text and what
  it decodes to.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import string
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from urllib.parse import unquote

# Zero-width and invisible formatting characters (incl. bidi controls, BOM, soft hyphen).
ZERO_WIDTH_CHARS = (
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e"
    "\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\u206a\u206b\u206c\u206d\u206e\u206f"
    "\u3164\ufeff\uffa0"
)
_ZW_RE = re.compile("[" + re.escape(ZERO_WIDTH_CHARS) + "]")
# Unicode tag block U+E0000..U+E007F mirrors ASCII and renders invisibly.
_TAG_RE = re.compile("[\U000e0000-\U000e007f]")

# Common Cyrillic / Greek / fullwidth-ish confusables -> Latin. NFKC already folds
# fullwidth and mathematical alphanumerics; this table covers what NFKC keeps.
HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d",
    "ɡ": "g", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])")
# An unclosed comment hides everything after it, as in a browser. Matching to
# the end of input also keeps the scan linear when "<!--" repeats unclosed.
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)(?:-->|\Z)", re.S)
# Opening tags only: the matching close tag is found by _closed_elements(), which
# stays linear when an attacker repeats unclosed tags (a lazy "(.*?)</\1>" in the
# regex rescans to the end of the input for every one of them).
_OPEN_TAG_RE = re.compile(r"<(\w+)\b([^>]{0,2000})>")
# Tested against the attribute text of a single opening tag (group 2 above).
_HIDDEN_STYLE_ATTR_RE = re.compile(
    r"style\s*=\s*['\"][^'\"]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"color\s*:\s*(#fff(fff)?|white)|opacity\s*:\s*0(?![.\d]*[1-9]))[^'\"]*['\"]",
    re.I,
)
_HIDDEN_ATTR_RE = re.compile(r"\b(hidden|aria-hidden\s*=\s*['\"]true['\"])", re.I)
_SCRIPT_STYLE_OPEN_RE = re.compile(r"<(script|style)\b[^>]{0,2000}>", re.I)
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_TAG_STRIP_RE = re.compile(r"<[^>]{0,2000}>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_ROT13_HINT_RE = re.compile(r"\brot[\s_-]?13\b", re.I)


@dataclass
class Normalized:
    """Result of :func:`normalize`."""

    text: str
    """Canonical text: surface text plus any decoded/hidden segments appended."""
    surface: str
    """Canonical surface text only (no appended decodings)."""
    flags: list[str] = field(default_factory=list)
    """Obfuscation indicators found, e.g. ``zero_width``, ``base64``, ``hidden_html``."""
    decoded: list[str] = field(default_factory=list)
    """Segments recovered by decoding (base64 / ROT13 / tag chars / hidden HTML)."""


def strip_invisible(text: str) -> tuple[str, int]:
    """Remove zero-width / bidi / formatting characters. Returns (text, count_removed)."""
    out, n = _ZW_RE.subn("", text)
    return out, n


def decode_tag_chars(text: str) -> tuple[str, str]:
    """Strip Unicode tag characters; return (text_without_tags, decoded_ascii_payload)."""
    hidden = "".join(chr(ord(c) - 0xE0000) for c in _TAG_RE.findall(text) if 0x20 <= ord(c) - 0xE0000 < 0x7F)
    return _TAG_RE.sub("", text), hidden


def fold_homoglyphs(text: str) -> tuple[str, int]:
    """NFKC-normalize and map common confusables to ASCII. Returns (text, count_changed)."""
    nfkc = unicodedata.normalize("NFKC", text)
    folded = nfkc.translate(_HOMOGLYPH_TABLE)
    changed = sum(1 for a, b in zip(nfkc, folded) if a != b)
    return folded, changed


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    good = sum(1 for c in s if c.isprintable() or c in "\n\t")
    return good / len(s)


def decode_base64_segments(text: str, max_segments: int = 20) -> list[str]:
    """Find base64/base64url-looking runs and return those that decode to readable text."""
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        if len(out) >= max_segments:
            break
        seg = m.group(1)
        # Pure hex or pure alpha runs are usually identifiers, not base64 payloads.
        if seg.isalpha() and (seg.islower() or seg.isupper()):
            continue
        s = seg.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        try:
            raw = base64.b64decode(s, validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        letters = sum(c.isalpha() or c == " " for c in dec)
        if len(dec) >= 8 and _printable_ratio(dec) > 0.95 and letters / max(len(dec), 1) > 0.6:
            out.append(dec)
    return out


def _closed_elements(
    open_re: re.Pattern[str], text: str, attrs_re: re.Pattern[str] | None = None
) -> Iterator[tuple[re.Match[str], int, int]]:
    """Yield ``(open_match, close_start, close_end)`` for open tags that have a close tag.

    Like ``finditer`` with ``(.*?)</\\1>`` appended to ``open_re``, but each missing
    close tag is looked up once, so the scan is linear in ``len(text)``. When
    ``attrs_re`` is given, only opening tags whose attribute text (group 2) matches
    it are considered.
    """
    low = text.translate(_ASCII_LOWER)  # length-preserving, unlike str.lower()
    next_close: dict[str, int] = {}
    pos = 0
    while (m := open_re.search(text, pos)) is not None:
        if attrs_re is not None and not attrs_re.search(m.group(2)):
            pos = m.start() + 1
            continue
        closing = "</" + m.group(1).translate(_ASCII_LOWER) + ">"
        idx = next_close.get(closing)
        if idx is None or (idx != -1 and idx < m.end()):
            idx = low.find(closing, m.end())
            next_close[closing] = idx
        if idx == -1:
            pos = m.start() + 1
            continue
        yield m, idx, idx + len(closing)
        pos = idx + len(closing)


def extract_hidden_html(text: str) -> list[str]:
    """Return text that a browser would not show: comments, display:none, hidden attrs, white text."""
    hidden: list[str] = []
    for m in _HTML_COMMENT_RE.finditer(text):
        hidden.append(m.group(1).strip())
    for attrs_re in (_HIDDEN_STYLE_ATTR_RE, _HIDDEN_ATTR_RE):
        for m, close_start, _ in _closed_elements(_OPEN_TAG_RE, text, attrs_re):
            hidden.append(_TAG_STRIP_RE.sub(" ", text[m.end():close_start]).strip())
    return [h for h in hidden if h]


def _strip_script_style(text: str) -> str:
    parts: list[str] = []
    pos = 0
    for m, _, close_end in _closed_elements(_SCRIPT_STYLE_OPEN_RE, text):
        parts.append(text[pos:m.start()])
        parts.append(" ")
        pos = close_end
    parts.append(text[pos:])
    return "".join(parts)


def html_to_text(text: str) -> str:
    """Very small HTML -> text: keep comment bodies and hidden text (attackers hide there)."""
    t = _HTML_COMMENT_RE.sub(lambda m: " " + m.group(1) + " ", text)
    t = _strip_script_style(t)
    t = _TAG_STRIP_RE.sub(" ", t)
    return t


def normalize(text: object, *, decode: bool = True) -> Normalized:
    """Canonicalize ``text`` for scanning. Never raises.

    Steps: coerce to str -> decode Unicode tag chars -> strip zero-width chars ->
    HTML-entity and URL decoding -> NFKC + homoglyph folding -> HTML to text ->
    whitespace collapse -> (optionally) append base64 / ROT13 / hidden-HTML decodings.
    """
    try:
        return _normalize(text, decode=decode)
    except Exception:  # pragma: no cover - defensive; fuzzing should never reach this
        s = text if isinstance(text, str) else repr(text)
        s = _ZW_RE.sub("", _TAG_RE.sub("", s))
        return Normalized(text=s, surface=s, flags=["normalize_error"])


def _normalize(text: object, *, decode: bool) -> Normalized:
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    # Lone surrogates cannot be encoded / matched reliably; replace them.
    text = text.encode("utf-8", "replace").decode("utf-8", "replace") if _has_surrogates(text) else text
    flags: list[str] = []
    decoded: list[str] = []

    t, tag_payload = decode_tag_chars(text)
    if tag_payload:
        flags.append("tag_chars")
        decoded.append(tag_payload)

    t, n_zw = strip_invisible(t)
    if n_zw:
        flags.append("zero_width")

    hidden = extract_hidden_html(t) if "<" in t else []
    if hidden:
        flags.append("hidden_html")

    # Entity and percent decoding (bounded number of rounds to handle double-encoding).
    for _ in range(2):
        nt = html.unescape(t)
        if "%" in nt:
            try:
                nt = unquote(nt)
            except Exception:  # pragma: no cover
                pass
        if nt == t:
            break
        flags.append("entity_or_url_encoding") if "entity_or_url_encoding" not in flags else None
        t = nt
    # Entities can smuggle zero-width chars back in (e.g. &#8203;) -> strip again.
    t, n2 = strip_invisible(t)
    if n2 and "zero_width" not in flags:
        flags.append("zero_width")

    t, n_h = fold_homoglyphs(t)
    if n_h:
        flags.append("homoglyph")
    t, _ = strip_invisible(t)  # NFKC can produce nothing invisible, but be safe

    if "<" in t and ">" in t:
        t = html_to_text(t)
    t = _WS_RE.sub(" ", t)
    t = re.sub(r"\n\s*\n+", "\n", t).strip()
    surface = t

    if decode:
        for seg in decode_base64_segments(t):
            flags.append("base64") if "base64" not in flags else None
            decoded.append(fold_homoglyphs(strip_invisible(seg)[0])[0])
        if _ROT13_HINT_RE.search(t):
            flags.append("rot13_hint")
            decoded.append(codecs.decode(t, "rot_13"))
        for h in hidden:
            decoded.append(fold_homoglyphs(strip_invisible(html.unescape(h))[0])[0])

    if decoded:
        extra = " \n".join(_WS_RE.sub(" ", _ZW_RE.sub("", _TAG_RE.sub("", d))) for d in decoded)
        t = (t + " \n" + extra).strip()
    return Normalized(text=t, surface=surface, flags=flags, decoded=decoded)


def _has_surrogates(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def contains_invisible(text: str) -> bool:
    """True if ``text`` contains zero-width or tag characters."""
    return bool(_ZW_RE.search(text) or _TAG_RE.search(text))
