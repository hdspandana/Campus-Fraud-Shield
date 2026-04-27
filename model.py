_classifier = None
 
 
def load_model():
    global _classifier
    if _classifier is None:
        try:
            from transformers import pipeline
            _classifier = pipeline(
                "text-classification",
                model="mrm8488/bert-tiny-finetuned-sms-spam-detection",
                truncation=True,
                max_length=512,
            )
        except Exception:
            _classifier = None
    return _classifier
 
 
def get_ml_score(text: str) -> tuple[int, str, float]:
    """
    Returns (score 0-100, reason string, confidence %)
    SPAM  → high score | HAM → low score
    Falls back to (0, reason, 0.0) if model unavailable
    """
    try:
        clf = load_model()
        if clf is None:
            return 0, "⚠️ ML model not loaded — run: pip install transformers torch", 0.0
 
        result     = clf(text[:512])[0]
        label      = result["label"]
        confidence = result["score"]
 
        if label == "SPAM":
            score  = int(confidence * 100)
            reason = f"🤖 ML model flagged as SPAM ({int(confidence*100)}% confidence)"
        else:
            score  = int((1 - confidence) * 25)
            reason = f"🤖 ML model thinks this is legitimate ({int(confidence*100)}% confidence)"
 
        return score, reason, round(confidence * 100, 1)
 
    except Exception as e:
        return 0, f"⚠️ ML model error: {str(e)[:60]}", 0.0
 