# train/train_model.py
# ═════════════════════════════════════════════════════════════════
# Training Script for Semantic Scam Classifier
# Reads scam_dataset.csv → trains SemanticScamClassifier
# Saves model to models/ directory
# Run: python train/train_model.py
# ═════════════════════════════════════════════════════════════════

import os
import sys
import json
import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# ── Path setup ────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.ml_model       import SemanticScamClassifier
from core.history_engine import UnifiedHistoryEngine

# ── Config ────────────────────────────────────────────────────────
DATASET_PATH   = "data/scam_dataset.csv"
METRICS_PATH   = "data/model_metrics.json"
MODELS_DIR     = "models"
TEST_SIZE      = 0.20
RANDOM_STATE   = 42
MIN_SAMPLES    = 20


# ═════════════════════════════════════════════════════════════════
def load_dataset(path: str) -> pd.DataFrame:
    """Load and validate the scam dataset."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found at {path}.\n"
            f"Make sure data/scam_dataset.csv exists."
        )

    df = pd.read_csv(path)

    # Validate required columns
    required = {"text", "label"}
    missing  = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing columns: {missing}")

    # Clean
    df = df.dropna(subset=["text", "label"])
    df["text"]  = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)

    # Validate labels
    invalid = df[~df["label"].isin([0, 1])]
    if len(invalid) > 0:
        print(f"⚠️  Dropping {len(invalid)} rows with invalid labels")
        df = df[df["label"].isin([0, 1])]

    # Remove empty texts
    df = df[df["text"].str.len() > 10]

    return df.reset_index(drop=True)


def print_dataset_stats(df: pd.DataFrame) -> None:
    """Print dataset statistics."""
    total  = len(df)
    scams  = (df["label"] == 1).sum()
    safe   = (df["label"] == 0).sum()

    print(f"\n{'='*55}")
    print(f"  DATASET STATISTICS")
    print(f"{'='*55}")
    print(f"  Total samples : {total}")
    print(f"  Scam (1)      : {scams} ({scams/total:.1%})")
    print(f"  Safe (0)      : {safe}  ({safe/total:.1%})")

    if "category" in df.columns:
        print(f"\n  Category breakdown:")
        for cat, count in df["category"].value_counts().items():
            print(f"    {cat:<25} {count}")
    print(f"{'='*55}\n")


def train_classifier(df: pd.DataFrame) -> dict:
    """
    Train the semantic classifier and return metrics.

    Args:
        df: Dataset dataframe

    Returns:
        dict with training metrics
    """
    texts  = df["text"].tolist()
    labels = df["label"].tolist()

    # Train/test split
    (X_train, X_test,
     y_train, y_test) = train_test_split(
        texts, labels,
        test_size    = TEST_SIZE,
        random_state = RANDOM_STATE,
        stratify     = labels,
    )

    print(f"  Training samples : {len(X_train)}")
    print(f"  Test samples     : {len(X_test)}")
    print()

    # Train classifier
    clf = SemanticScamClassifier()
    start = time.time()
    clf.fit(X_train, y_train)
    elapsed = time.time() - start
    print(f"\n  Training time: {elapsed:.1f}s")

    # Evaluate on test set
    print(f"\n{'='*55}")
    print(f"  TEST SET EVALUATION")
    print(f"{'='*55}")
    report = clf.get_classification_report(X_test, y_test)
    print(report)

    # Confusion matrix
    from core.ml_model import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity

    embedder    = clf._load_embedder()
    test_embeds = embedder.encode(X_test, convert_to_numpy=True)
    predictions = clf.classifier.predict(test_embeds)
    cm          = confusion_matrix(y_test, predictions)

    print(f"  Confusion Matrix:")
    print(f"              Predicted")
    print(f"              SAFE  SCAM")
    print(f"  Actual SAFE  {cm[0][0]:4d}  {cm[0][1]:4d}")
    print(f"  Actual SCAM  {cm[1][0]:4d}  {cm[1][1]:4d}")
    print()

    # Calculate metrics
    tn, fp, fn, tp = cm.ravel()
    accuracy    = (tp + tn) / (tp + tn + fp + fn)
    precision   = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall      = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1          = (2 * precision * recall / (precision + recall)
                   if (precision + recall) > 0 else 0)

    metrics = {
        "total_samples":    len(texts),
        "train_samples":    len(X_train),
        "test_samples":     len(X_test),
        "accuracy":         round(accuracy,  4),
        "precision":        round(precision, 4),
        "recall":           round(recall,    4),
        "f1_score":         round(f1,        4),
        "true_positives":   int(tp),
        "true_negatives":   int(tn),
        "false_positives":  int(fp),
        "false_negatives":  int(fn),
        "training_time_s":  round(elapsed, 2),
    }

    # Save model
    print(f"  Saving model to {MODELS_DIR}/...")
    clf.save()
    print(f"  Model saved successfully.")

    return clf, metrics


def seed_history_engine(df: pd.DataFrame) -> int:
    """
    Seed the FAISS history engine with the dataset.

    Args:
        df: Dataset dataframe

    Returns:
        Number of records added
    """
    print(f"\n{'='*55}")
    print(f"  SEEDING FAISS HISTORY ENGINE")
    print(f"{'='*55}")

    engine = UnifiedHistoryEngine()
    added  = 0

    for _, row in df.iterrows():
        success = engine.add_report(
            text     = str(row["text"]),
            label    = int(row["label"]),
            category = str(row.get("category", "unknown")),
            source   = "training_dataset",
            score    = 80.0 if row["label"] == 1 else 10.0,
        )
        if success:
            added += 1

    print(f"  Records added to FAISS: {added}")
    print(f"  Total in index        : {engine.index.ntotal}")
    return added


def save_metrics(metrics: dict) -> None:
    """Save training metrics to JSON for display in app."""
    os.makedirs(os.path.dirname(METRICS_PATH), exist_ok=True)

    metrics["trained_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    metrics["model_name"] = "all-MiniLM-L6-v2 + LogisticRegression"

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n  Metrics saved to {METRICS_PATH}")


def run_sample_predictions(clf: SemanticScamClassifier) -> None:
    """Run a few sample predictions to verify the model."""
    print(f"\n{'='*55}")
    print(f"  SAMPLE PREDICTIONS")
    print(f"{'='*55}")

    samples = [
        ("Pay Rs.1500 registration fee to confirm internship. Send to Paytm 9876543210.", "SCAM"),
        ("Share your OTP to claim KBC prize of Rs.25 lakh. Contact kbc@gmail.com.", "SCAM"),
        ("TCS interview scheduled Monday 10AM. No fee required. Carry college ID.", "SAFE"),
        ("NSP scholarship Rs.25000 approved. Pay Rs.500 processing fee to release.", "SCAM"),
        ("Your Infosys offer letter sent to registered email. Joining date 15th March.", "SAFE"),
    ]

    correct = 0
    for text, expected in samples:
        score, reason = clf.predict_proba(text)
        predicted     = "SCAM" if score >= 50 else "SAFE"
        match         = "✅" if predicted == expected else "❌"
        correct      += 1 if predicted == expected else 0

        print(f"\n  {match} Expected: {expected} | Got: {predicted} ({score:.0f}/100)")
        print(f"     Text: {text[:65]}...")
        print(f"     Why:  {reason}")

    print(f"\n  Sample accuracy: {correct}/{len(samples)} ({correct/len(samples):.0%})")


# ═════════════════════════════════════════════════════════════════
def main():
    print(f"\n{'='*55}")
    print(f"  CAMPUS FRAUD SHIELD — MODEL TRAINING")
    print(f"{'='*55}")
    print(f"  Dataset  : {DATASET_PATH}")
    print(f"  Models   : {MODELS_DIR}/")
    print(f"  Test size: {TEST_SIZE:.0%}")
    print()

    # ── Step 1: Load dataset ──────────────────────────────────────
    print("Step 1/4 — Loading dataset...")
    df = load_dataset(DATASET_PATH)
    print_dataset_stats(df)

    if len(df) < MIN_SAMPLES:
        raise ValueError(
            f"Dataset too small ({len(df)} samples). "
            f"Need at least {MIN_SAMPLES}."
        )

    # ── Step 2: Train classifier ──────────────────────────────────
    print("Step 2/4 — Training semantic classifier...")
    clf, metrics = train_classifier(df)

    # ── Step 3: Seed history engine ───────────────────────────────
    print("Step 3/4 — Seeding FAISS history engine...")
    added = seed_history_engine(df)
    metrics["faiss_records"] = added

    # ── Step 4: Save metrics ──────────────────────────────────────
    print("Step 4/4 — Saving metrics...")
    save_metrics(metrics)

    # ── Sample predictions ────────────────────────────────────────
    run_sample_predictions(clf)

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  TRAINING COMPLETE")
    print(f"{'='*55}")
    print(f"  Accuracy  : {metrics['accuracy']:.1%}")
    print(f"  Precision : {metrics['precision']:.1%}")
    print(f"  Recall    : {metrics['recall']:.1%}")
    print(f"  F1 Score  : {metrics['f1_score']:.1%}")
    print(f"  FAISS     : {added} records indexed")
    print(f"\n  Run the app: streamlit run app.py")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()