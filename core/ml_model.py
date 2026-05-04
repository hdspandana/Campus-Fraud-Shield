# core/ml_model.py
import os
import joblib
import numpy as np
import streamlit as st
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from config import MODEL_FILE, VECTORIZER_FILE


# ─── Zero-shot intent labels ──────────────────────────────────────────────────
INTENT_LABELS = [
    "payment scam",
    "phishing attack",
    "fake job offer",
    "prize or lottery scam",
    "OTP theft attempt",
    "impersonation scam",
    "normal safe message",
]


@st.cache_resource(show_spinner="🤖 Loading ML model...")
def load_classifier():
    """Load trained sklearn pipeline (offline, fast)."""
    try:
        if os.path.exists(MODEL_FILE):
            model = joblib.load(MODEL_FILE)
            return model
        return None
    except Exception:
        return None


def get_ml_score(text: str) -> tuple[int, str, float]:
    """
    Returns (score 0-100, reason string, confidence float)
    Uses trained TF-IDF + Logistic Regression model.
    Falls back gracefully if model not found.
    """
    model = load_classifier()

    if model is None:
        # Fallback: simple keyword-based ML simulation
        return _fallback_ml(text)

    try:
        prediction  = model.predict([text])[0]
        proba       = model.predict_proba([text])[0]
        classes     = model.classes_
        confidence  = float(max(proba))

        prob_dict   = dict(zip(classes, proba))
        scam_prob   = prob_dict.get("scam", 0.0)

        if prediction == "scam":
            score  = int(scam_prob * 100)
            reason = f"🤖 ML Model: Classified as SCAM ({int(confidence*100)}% confidence)"
        else:
            score  = int(scam_prob * 30)  # Small penalty even if safe
            reason = f"🤖 ML Model: Looks legitimate ({int(confidence*100)}% confidence)"

        return score, reason, round(confidence * 100, 1)

    except Exception as e:
        return _fallback_ml(text)


def _fallback_ml(text: str) -> tuple[int, str, float]:
    """
    Offline fallback when model file not found.
    Uses weighted keyword scoring as ML proxy.
    """
    HIGH_RISK_PHRASES = [
        "otp", "verify your account", "account suspended",
        "send aadhar", "bank account", "registration fee",
        "processing fee", "click here to claim", "you have won",
        "lucky draw", "refundable deposit", "pay to activate",
    ]
    t = text.lower()
    hits = sum(1 for phrase in HIGH_RISK_PHRASES if phrase in t)

    if hits >= 3:
        score = min(hits * 20, 85)
        return score, f"🤖 ML Fallback: {hits} high-risk phrases detected", 75.0
    elif hits > 0:
        score = hits * 15
        return score, f"🤖 ML Fallback: {hits} suspicious phrase(s) found", 55.0
    else:
        return 5, "🤖 ML Fallback: No strong scam indicators", 20.0