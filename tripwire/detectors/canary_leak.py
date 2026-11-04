"""Canary / taint leak detector.

Two checks per argument:

1. **Canary tokens** (exact). A session canary inside a *destination* field (the
   e-mail recipient, the POST URL, the file path) means the agent took where to
   send/write something straight from untrusted content: score 1.0. A canary in a
   *data* field (an e-mail body) is a normal "summarise this page for me" flow,
   so it only contributes a mild 0.3 -- other detectors decide whether that data
   is dangerous.
2. **Fuzzy taint overlap** (paraphrase-tolerant). Word 5-gram containment for
   long values, rapidfuzz ``partial_ratio`` for short ones. Exposed as the
   ``taint`` feature (0..1) plus ``dest_taint`` for destination fields.
"""

from __future__ import annotations

from tripwire import canary as canary_mod
from tripwire.detectors.base import DetectionContext, Detector
from tripwire.schemas import DetectorResult, Highlight


class CanaryLeakDetector(Detector):
    name = "canary_leak"

    def inspect(self, ctx: DetectionContext) -> DetectorResult:
        res = DetectorResult(name=self.name)
        s = ctx.session
        score = 0.0
        dest_taint = 0.0
        data_taint = 0.0
        src_inj = 0.0
        for fld, raw in ctx.raw.items():
            hits = [h for h in canary_mod.find_tokens(raw) if h.token in s.canaries]
            is_dest = fld in ctx.destination_fields
            if hits:
                rid = s.canaries[hits[0].token]
                rec = s.record(rid)
                src_inj = max(src_inj, rec.injection_score if rec else 0.0)
                score = max(score, 1.0 if is_dest else 0.3)
                res.reasons.append(f"session canary from {rec.source if rec else rid} found in '{fld}'")
                snippet = canary_mod.strip_tokens(raw[max(0, hits[0].start - 40) : hits[0].end + 80])
                res.highlights.append(Highlight(field=fld, text=snippet, why="canary", source_record=rid))
            ov = s.overlap(ctx.norm[fld].text)
            if ov.score >= 0.5:
                rec = s.record(ov.record_id)
                res.highlights.append(Highlight(field=fld, text=ov.span, why=f"taint overlap {ov.score:.2f}", source_record=ov.record_id))
                if rec:
                    src_inj = max(src_inj, rec.injection_score)
            if is_dest:
                dest_taint = max(dest_taint, ov.score)
            elif fld in ctx.data_fields:
                data_taint = max(data_taint, ov.score)
        if dest_taint >= 0.8:
            res.reasons.append(f"destination copied from untrusted content (overlap {dest_taint:.2f})")
        res.score = score
        res.features = {"taint": round(data_taint, 3), "dest_taint": round(dest_taint, 3), "source_injection": round(src_inj, 3)}
        return res
