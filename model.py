import streamlit as st
 
 
@st.cache_resource(show_spinner="🤖 Loading ML model (first time only)...")
def load_model():
    """
    Cached forever — Streamlit keeps this alive across all reruns.
    Downloads ~25MB on first run, then instant every time after.
    """
    try:
        from transformers import pipeline
        clf = pipeline(
            "text-classification",
            model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
            truncation=True,
            max_length=512,
        )
        return clf
    except Exception as e:
        return None
 
 
def get_ml_score(text: str) -> tuple[int, str, float]:
    """
    Returns (score 0–100, reason, confidence%)
    SPAM → high score | HAM → low score
    """
    clf = load_model()
 
    if clf is None:
        return 0, "⚠️ ML model unavailable — run: pip install transformers torch", 0.0
 
    try:
        result     = clf(text[:512])[0]
        label      = result["label"]
        confidence = result["score"]
 
        if label == "SPAM":
            score  = int(confidence * 100)
            reason = f"🤖 ML flagged as SPAM ({int(confidence*100)}% confidence)"
        else:
            score  = int((1 - confidence) * 20)
            reason = f"🤖 ML model: looks legitimate ({int(confidence*100)}% confidence)"
 
        return score, reason, round(confidence * 100, 1)
 
    except Exception as e:
        return 0, f"⚠️ ML error: {str(e)[:50]}", 0.0
