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
from core.ml_model import SemanticScamClassifier  # noqa: E402

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

    # ── Confusion matrix + precision/recall/F1 (honest, out-of-fold) ──
    # Same principle as cv_accuracy: predictions here come from
    # StratifiedKFold cross-validation, so every prediction is made on
    # a fold the model did NOT see during that fold's training — this
    # is NOT the classifier scoring its own training data.
    confusion = None
    if clf.cv_accuracy is not None:
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
        from sklearn.model_selection import StratifiedKFold, cross_val_predict

        labels_arr_full = pd.Series(labels)
        n_splits = min(5, int(labels_arr_full.value_counts().min()))
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

        oof_preds = cross_val_predict(
            LogisticRegression(
                C=getattr(clf, "best_C", 1.0) or 1.0,
                class_weight="balanced", max_iter=1000, random_state=42,
            ),
            clf.training_embeddings, labels, cv=cv,
        )

        tn, fp, fn, tp = confusion_matrix(labels, oof_preds, labels=[0, 1]).ravel()
        confusion = {
            "true_negative": int(tn),   # correctly called SAFE
            "false_positive": int(fp),  # SAFE message wrongly flagged as SCAM
            "false_negative": int(fn),  # SCAM message wrongly missed as SAFE (the dangerous one)
            "true_positive": int(tp),   # correctly caught SCAM
            "precision": round(float(precision_score(labels, oof_preds, zero_division=0)), 4),
            "recall": round(float(recall_score(labels, oof_preds, zero_division=0)), 4),
            "f1": round(float(f1_score(labels, oof_preds, zero_division=0)), 4),
        }
        print(f"📊 Confusion matrix (out-of-fold): TP={tp} TN={tn} FP={fp} FN={fn}")
        print(f"📊 Precision={confusion['precision']:.2%}  Recall={confusion['recall']:.2%}  F1={confusion['f1']:.2%}")
        if fn > 0:
            print(f"⚠️  {fn} real scam(s) would have been missed (false negatives) — "
                  f"the metric that matters most for this project's stated goal.")

    # ── Per-category example counts ─────────────────────────────────
    # Categories with very few examples are exactly where the model is
    # weakest and least trustworthy — surfacing counts turns "add more
    # data" from a guess into a targeted, evidence-based todo list.
    category_counts = {}
    weak_categories = []
    if "category" in df.columns:
        category_counts = df["category"].value_counts().to_dict()
        weak_categories = sorted(
            [cat for cat, count in category_counts.items() if count < 5 and cat != "safe"]
        )
        if weak_categories:
            print(f"⚠️  Categories with < 5 examples (unreliable, need more data): "
                  f"{', '.join(weak_categories)}")

    os.makedirs(os.path.dirname(METRICS_PATH), exist_ok=True)
    metrics = {
        "n_examples": len(texts),
        "n_scam": n_scam,
        "n_safe": n_safe,
        "cv_accuracy": clf.cv_accuracy,
        "best_C": getattr(clf, "best_C", None),
        "confusion_matrix": confusion,
        "category_counts": category_counts,
        "weak_categories": weak_categories,
        "note": (
            "cv_accuracy and confusion_matrix are stratified k-fold "
            "cross-validated / out-of-fold estimates, not training-set "
            "scores. With this small a dataset they should be treated "
            "as directional, not precise."
        ),
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"✅ Honest metrics written to {METRICS_PATH}")


if __name__ == "__main__":
    main()