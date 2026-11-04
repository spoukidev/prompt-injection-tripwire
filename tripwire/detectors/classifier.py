"""ML instruction-likeness classifier.

The default model is a small, CPU-only scikit-learn pipeline (word + character
n-gram TF-IDF -> logistic regression) trained by ``classifier/train.py`` on data
from ``classifier/build_dataset.py``. It loads in milliseconds and scores a call
in well under a millisecond, which keeps the proxy inside its latency budget.

``train.py --backend distilbert`` can instead fine-tune a transformer; if
``model_path`` points at a directory containing a Hugging Face model, it is
loaded with ``transformers`` (optional dependency, not needed for the benchmark).

If no model file exists the detector returns 0 and says so, rather than failing.
"""

from __future__ import annotations

import os
from pathlib import Path

from tripwire.detectors.base import DetectionContext, Detector
from tripwire.schemas import DetectorResult

ROOT = Path(__file__).resolve().parents[2]


class ClassifierDetector(Detector):
    name = "classifier"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.model = None
        self.hf = None
        self.error: str | None = None
        path = Path(os.environ.get("TRIPWIRE_CLASSIFIER", self.config.get("model_path", "classifier/model.joblib")))
        if not path.is_absolute():
            path = ROOT / path
        self.path = path
        self._load()

    def _load(self) -> None:
        try:
            if self.path.is_dir():
                from transformers import pipeline  # optional dependency

                self.hf = pipeline("text-classification", model=str(self.path), truncation=True)
            elif self.path.exists():
                import joblib

                self.model = joblib.load(self.path)
            else:
                self.error = f"no classifier model at {self.path} (run `make train`)"
        except Exception as e:  # pragma: no cover - environment specific
            self.error = f"failed to load classifier: {e}"

    @property
    def available(self) -> bool:
        return self.model is not None or self.hf is not None

    def predict(self, text: str) -> float:
        if not text.strip() or not self.available:
            return 0.0
        text = text[:4000]
        if self.model is not None:
            return float(self.model.predict_proba([text])[0][1])
        out = self.hf(text)[0]  # pragma: no cover
        return float(out["score"] if out["label"].lower() in ("injection", "label_1", "1") else 1 - out["score"])

    def predict_many(self, texts: list[str]) -> list[float]:
        """Batch prediction (one vectorizer pass; much faster than a loop)."""
        if not self.available or not texts:
            return [0.0] * len(texts)
        if self.model is not None:
            return [float(p[1]) for p in self.model.predict_proba(texts)]
        return [self.predict(t) for t in texts]  # pragma: no cover

    def inspect(self, ctx: DetectionContext) -> DetectorResult:
        return self.score_text(ctx.data_text())

    def score_text(self, text: str, flags: list[str] | None = None) -> DetectorResult:
        if not self.available:
            return DetectorResult(name=self.name, reasons=[self.error or "classifier unavailable"])
        # Score sentence windows so one injected sentence in a long benign page still shows up.
        if not text.strip():
            return DetectorResult(name=self.name)
        batch = [text[:4000]] + [s for s in _windows(text) if len(s) > 25][:80]
        best = max(self.predict_many(batch))
        reasons = [f"p(injection)={best:.2f}"] if best >= 0.5 else []
        return DetectorResult(name=self.name, score=round(best, 4), reasons=reasons)


def _windows(text: str) -> list[str]:
    import re

    sents = [s.strip() for s in re.split(r"(?<=[.!?:])\s+|\n+", text) if s.strip()]
    return [" ".join(sents[i : i + 2]) for i in range(0, len(sents), 1)]
