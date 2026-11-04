"""Train the instruction-likeness classifier.

    python -m classifier.train                       # default: TF-IDF + logistic regression (CPU, ~seconds)
    python -m classifier.train --backend distilbert  # optional: fine-tune DistilBERT (needs torch+transformers)

The default model is saved to ``classifier/model.joblib`` and is what the proxy
and the benchmark use. A DistilBERT model is saved to ``classifier/model-hf/``;
point ``detectors.classifier.model_path`` (or ``TRIPWIRE_CLASSIFIER``) at that
directory to use it instead.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_rows(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def train_sklearn(rows: list[dict], out: Path) -> dict:
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import FeatureUnion, Pipeline

    X = [r["text"] for r in rows]
    y = [r["label"] for r in rows]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=0, stratify=y)
    pipe = Pipeline([
        ("feats", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=40000)),
        ])),
        ("clf", LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced")),
    ])
    pipe.fit(Xtr, ytr)
    rep = classification_report(yte, pipe.predict(Xte), output_dict=True)
    pipe.fit(X, y)  # final model on all data
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out)
    return {"heldout_accuracy": rep["accuracy"], "heldout_f1_injection": rep["1"]["f1-score"], "n": len(rows)}


def train_distilbert(rows: list[dict], out_dir: Path, epochs: int = 2) -> dict:  # pragma: no cover - optional
    import numpy as np
    from datasets import Dataset
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments)

    name = "distilbert-base-uncased"
    tok = AutoTokenizer.from_pretrained(name)
    ds = Dataset.from_list([{"text": r["text"], "label": r["label"]} for r in rows]).train_test_split(test_size=0.2, seed=0)
    ds = ds.map(lambda b: tok(b["text"], truncation=True, max_length=256), batched=True)
    model = AutoModelForSequenceClassification.from_pretrained(name, num_labels=2, id2label={0: "benign", 1: "injection"},
                                                               label2id={"benign": 0, "injection": 1})
    args = TrainingArguments(output_dir=str(out_dir / "_ckpt"), num_train_epochs=epochs, per_device_train_batch_size=16,
                             eval_strategy="epoch", save_strategy="no", report_to=[])
    trainer = Trainer(model=model, args=args, train_dataset=ds["train"], eval_dataset=ds["test"], tokenizer=tok,
                      compute_metrics=lambda p: {"accuracy": float((np.argmax(p.predictions, -1) == p.label_ids).mean())})
    trainer.train()
    res = trainer.evaluate()
    trainer.save_model(str(out_dir))
    tok.save_pretrained(str(out_dir))
    return {"heldout_accuracy": res.get("eval_accuracy"), "n": len(rows)}


def main(argv: list[str] | None = None) -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["sklearn", "distilbert"], default="sklearn")
    ap.add_argument("--data", default=str(ROOT / "data" / "dataset.jsonl"))
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    data = Path(a.data)
    if not data.exists():
        from classifier import build_dataset

        build_dataset.main(["--out", str(data)])
    rows = load_rows(data)
    if a.backend == "sklearn":
        res = train_sklearn(rows, Path(a.out or ROOT / "model.joblib"))
    else:
        res = train_distilbert(rows, Path(a.out or ROOT / "model-hf"))
    print(f"[train] {a.backend}: {res}")
    return res


if __name__ == "__main__":
    main()
