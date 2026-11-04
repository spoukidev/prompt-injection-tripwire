"""Exfiltration-sink detector.

Answers: *where* is this call sending/writing, and did the user ever authorise
that place? And: is anything secret riding along?

Signals (all exposed as features):

* ``dest_untrusted`` -- a destination (recipient, URL host, file path) that never
  appeared in trusted input (system prompt, user turns, policy allowlist).
  E-mail senders taken from message *headers* count as contacts (you may reply
  to whoever wrote to you), but not addresses found in message bodies.
* ``dest_from_injection`` -- the exact destination appears in untrusted content
  that scored as injection-like at ingest. Catches "same-origin" tricks where the
  attacker's page asks to POST back to its own (user-visited) host.
* ``sensitive`` -- secret material in any argument: chunks of the system prompt,
  of secret files the agent read, or well-known key formats. Checked on the
  normalized text, so base64/URL-encoded secrets are caught too.
* ``beacon`` -- a markdown/HTML image whose URL carries a query string to an
  untrusted host (data leaves when the image renders).
* ``query_data`` -- a GET to an untrusted host whose query string carries a long
  or high-entropy value.
"""

from __future__ import annotations

import html
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

from tripwire.detectors.base import DetectionContext, Detector, path_matches
from tripwire.schemas import DetectorResult, Highlight
from tripwire.taint import EMAIL_RE, URL_RE, host_of, normalize_path

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-(test|live|fake)?[-_]?[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\b(aws_secret_access_key|api[_-]?key|secret[_-]?key|password)\s*[=:]\s*\S{8,}", re.I),
]
IMG_RE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)|<img[^>]+src\s*=\s*['\"]?(https?://[^'\"\s>]+)", re.I)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _split_recipients(value: str) -> list[str]:
    return [e.lower() for e in EMAIL_RE.findall(value)] or [v.strip().lower() for v in re.split(r"[,;\s]+", value) if v.strip()]


class ExfilDetector(Detector):
    name = "exfil"

    def __init__(self, config: dict | None = None, injection_threshold: float = 0.5) -> None:
        super().__init__(config)
        self.thr = injection_threshold

    # ----------------------------------------------------------- trust checks
    def _host_trusted(self, ctx: DetectionContext, host: str) -> bool:
        trusted = ctx.session.trusted["hosts"] | {h.lower() for h in ctx.policy.get("trusted", {}).get("hosts", [])}
        return host in trusted

    def _email_trusted(self, ctx: DetectionContext, email: str) -> tuple[bool, bool]:
        """Returns (trusted, is_contact)."""
        trusted = ctx.session.trusted["emails"] | {e.lower() for e in ctx.policy.get("trusted", {}).get("emails", [])}
        if email in trusted:
            return True, False
        return False, email in ctx.session.contacts

    def _path_trusted(self, ctx: DetectionContext, path: str) -> bool:
        p = normalize_path(path)
        if p in ctx.session.trusted["paths"]:
            return True
        return path_matches(p, ctx.policy.get("trusted", {}).get("paths", []))

    def _from_injection(self, ctx: DetectionContext, value: str) -> bool:
        v = value.lower().rstrip("/")
        if len(v) < 6:
            return False
        for r in ctx.session.records:
            if r.injection_score >= self.thr and v in r.norm.lower():
                return True
        return False

    @staticmethod
    def _copied_from_taint(ctx: DetectionContext, url: str) -> bool:
        """True if this exact URL appears in untrusted content (link-following / quoting, not constructed)."""
        u = url.lower()
        return any(u in r.norm.lower() or u in html.unescape(r.raw).lower() for r in ctx.session.records)

    @staticmethod
    def _carries_data(url: str) -> bool:
        for _, qv in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if len(qv) >= 24 or (len(qv) >= 12 and shannon_entropy(qv) > 3.5):
                return True
        return False

    def _sensitive_hits(self, ctx: DetectionContext, text: str) -> list[str]:
        low = text.lower()
        hits = [c[:40] for c in ctx.session.sensitive_chunks if c and (c in low or (len(c) > 40 and c[:40] in low))]
        hits += [m.group(0)[:40] for rx in SECRET_PATTERNS for m in [rx.search(text)] if m]
        return hits

    # ------------------------------------------------------------------ main
    def inspect(self, ctx: DetectionContext) -> DetectorResult:
        res = DetectorResult(name=self.name)
        f = {"dest_untrusted": 0.0, "dest_from_injection": 0.0, "contact": 0.0, "sensitive": 0.0, "beacon": 0.0,
             "query_data": 0.0, "data_links_from_injection": 0.0}
        tool = ctx.tool

        # 1. Destinations ---------------------------------------------------
        for fld in ctx.destination_fields:
            value = ctx.norm[fld].surface
            if tool in ("send_email",) or fld in ("to", "cc", "bcc"):
                for addr in _split_recipients(value):
                    ok, contact = self._email_trusted(ctx, addr)
                    if contact:
                        f["contact"] = 1.0
                    if not ok and not contact:
                        f["dest_untrusted"] = 1.0
                        res.reasons.append(f"recipient {addr} never appeared in trusted input")
                        res.highlights.append(Highlight(field=fld, text=addr, why="untrusted recipient"))
                    if not ok and self._from_injection(ctx, addr):
                        f["dest_from_injection"] = 1.0
                        res.reasons.append(f"recipient {addr} comes from injection-like content")
            elif fld == "url" or value.lower().startswith("http"):
                url = value.strip()
                host = host_of(url)
                base = url.split("?", 1)[0].split("#", 1)[0].lower().rstrip("/")
                trusted_urls = {u.split("?", 1)[0].rstrip("/") for u in ctx.session.trusted["urls"]}
                host_ok = self._host_trusted(ctx, host)
                if not host_ok:
                    f["dest_untrusted"] = 1.0
                    res.reasons.append(f"host {host or '?'} never appeared in trusted input")
                    res.highlights.append(Highlight(field=fld, text=url[:120], why="untrusted host"))
                if base not in trusted_urls and self._from_injection(ctx, base):
                    f["dest_from_injection"] = 1.0
                    res.reasons.append(f"URL {base[:80]} comes from injection-like content")
                if not host_ok and self._carries_data(url) and not self._copied_from_taint(ctx, url):
                    f["query_data"] = 1.0
                    res.reasons.append("query string carries a long/high-entropy value (not a copied link) to an untrusted host")
            else:  # file paths
                if not self._path_trusted(ctx, value):
                    f["dest_untrusted"] = 1.0
                    res.reasons.append(f"path {value[:80]} not named by the user")
                    res.highlights.append(Highlight(field=fld, text=value[:120], why="untrusted path"))
                if self._from_injection(ctx, normalize_path(value)):
                    f["dest_from_injection"] = 1.0
                    res.reasons.append(f"path {value[:80]} comes from injection-like content")

        # 2. Secrets anywhere in the call -------------------------------------
        all_text = "\n".join(n.text for n in ctx.norm.values())
        hits = self._sensitive_hits(ctx, all_text)
        if hits:
            f["sensitive"] = 1.0
            res.reasons.append(f"secret material in arguments ({len(hits)} match(es))")
            res.highlights += [Highlight(field="*", text=h, why="sensitive") for h in hits[:3]]

        # 3. Image beacons and links planted from injected content -------------
        for fld in ctx.data_fields:
            text = ctx.norm[fld].text
            for m in IMG_RE.finditer(text):
                url = m.group(1) or m.group(2)
                if ("?" in url and not self._host_trusted(ctx, host_of(url)) and not self._copied_from_taint(ctx, url)
                        and (self._carries_data(url) or self._sensitive_hits(ctx, url))):
                    f["beacon"] = 1.0
                    res.reasons.append(f"image beacon with query string to {host_of(url)}")
                    res.highlights.append(Highlight(field=fld, text=url[:120], why="beacon"))
            for ind in set(URL_RE.findall(text)) | set(EMAIL_RE.findall(text)):
                ind_l = ind.lower().rstrip(".,;:")
                trusted = (ind_l in ctx.session.trusted["emails"] or ind_l in ctx.session.trusted["urls"]
                           or self._host_trusted(ctx, host_of(ind_l)))
                if not trusted and self._from_injection(ctx, ind_l.split("?", 1)[0]):
                    f["data_links_from_injection"] = 1.0
                    res.reasons.append(f"data contains {ind_l[:60]} taken from injection-like content")
                    break

        # 4. Combine -------------------------------------------------------------
        untrusted, inj = f["dest_untrusted"], f["dest_from_injection"]
        if f["beacon"]:
            score = 1.0
        elif f["sensitive"] and (untrusted or f["contact"]):
            score = 1.0
        elif untrusted and inj:
            score = 0.9
        elif inj:
            score = 0.85
        elif tool == "fetch_url":
            score = 0.85 if (untrusted and (f["query_data"] or f["sensitive"])) else 0.0
        elif f["sensitive"]:
            score = 0.6
        elif untrusted:
            score = 0.55
        else:
            score = 0.0
        res.score = score
        res.features = f
        return res
