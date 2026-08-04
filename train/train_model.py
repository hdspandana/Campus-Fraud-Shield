"""
train_model.py

Regenerates the trained semantic classifier from data/scam_dataset.csv
and saves it to models/ (models/semantic_classifier.pkl,
models/training_embeddings.npy, models/training_texts.json).

These files are gitignored on purpose (trained artifacts shouldn't be
committed) — but that means this script MUST be run at least once after
cloning, or the app silently falls back to a tiny 14-example inline
training set baked into app.py, which is a much weaker model than the
one described in the README.

Usage:
    python train_model.py

Also writes data/model_metrics.json with the honest, cross-validated
accuracy (not training-set accuracy) so the README/UI can report a
real number instead of an inflated one.
"""

import json
import os
import sys

import pandas as pd

# Find the repo root (the directory that contains core/ and data/) by
# walking upward from this file, so it works whether this script lives
# at the repo root or inside a subfolder like train/.
_here = os.path.dirname(os.path.abspath(__file__))
_root = _here
while _root != os.path.dirname(_root):  # stop at filesystem root
    if os.path.isdir(os.path.join(_root, "core")):
        break
    _root = os.path.dirname(_root)
else:
    raise RuntimeError(
        "Could not find the repo root (a folder containing 'core/'). "
        "Run this script from inside the Campus-Fraud-Shield project."
    )

sys.path.insert(0, _root)
os.chdir(_root)  # so relative paths like "data/scam_dataset.csv" resolve
from core.ml_model import SemanticScamClassifier, write_model_metrics  # noqa: E402

DATA_PATH = "data/scam_dataset.csv"
METRICS_PATH = "data/model_metrics.json"


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"{DATA_PATH} not found. Run this script from the repo root."
        )

    df = pd.read_csv(DATA_PATH)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{DATA_PATH} must have 'text' and 'label' columns")

    texts = df["text"].astype(str).tolist()
    labels = df["label"].astype(int).tolist()

    n_scam = sum(labels)
    n_safe = len(labels) - n_scam
    print(f"Loaded {len(texts)} examples from {DATA_PATH} "
          f"({n_scam} scam / {n_safe} safe)")

    if len(texts) < 60:
        print(
            "⚠️  WARNING: fewer than 60 labeled examples. Any accuracy "
            "number produced here (even cross-validated) has wide error "
            "bars and should be reported as a rough estimate, not a "
            "headline metric. Consider expanding the dataset further."
        )

    clf = SemanticScamClassifier()
    clf.fit(texts, labels)
    clf.save()
    print("✅ Model saved to models/")

    # Same function core/pipeline.py's automatic training fallback uses
    # — so metrics are consistent regardless of which path trained it.
    metrics = write_model_metrics(clf, df, METRICS_PATH)

    if metrics["confusion_matrix"]:
        cm = metrics["confusion_matrix"]
        print(f"📊 Confusion matrix (out-of-fold): "
              f"TP={cm['true_positive']} TN={cm['true_negative']} "
              f"FP={cm['false_positive']} FN={cm['false_negative']}")
        print(f"📊 Precision={cm['precision']:.2%}  Recall={cm['recall']:.2%}  F1={cm['f1']:.2%}")
        if cm["false_negative"] > 0:
            print(f"⚠️  {cm['false_negative']} real scam(s) would have been missed "
                  f"(false negatives) — the metric that matters most for this "
                  f"project's stated goal.")

    if metrics["weak_categories"]:
        print(f"⚠️  Categories with < 5 examples (unreliable, need more data): "
              f"{', '.join(metrics['weak_categories'])}")

    print(f"✅ Honest metrics written to {METRICS_PATH}")


if __name__ == "__main__":
    main()