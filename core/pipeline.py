# core/pipeline.py
# ═════════════════════════════════════════════════════════════════
# Shared detection pipeline — the single source of truth for running
# all 4 engines end-to-end.
#
# Extracted out of app.py so both the Streamlit UI (app.py) and the
# FastAPI service (api.py) call the exact same code path instead of
# each having their own copy that can drift out of sync.
#
# No Streamlit import here on purpose — this module needs to work in
# a plain Python/FastAPI process too, not just inside `streamlit run`.
# ═════════════════════════════════════════════════════════════════

import os
import sys
import time
import traceback
from functools import lru_cache

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SIMULATION_MODE = False
IMPORT_ERRORS = []

try:
    from core.scorer import FraudScorer
    from core.ml_model import get_semantic_classifier
    from core.history_engine import UnifiedHistoryEngine
    from utils.action_advisor import get_action

except Exception as e:
    SIMULATION_MODE = True
    IMPORT_ERRORS.append(str(e))
    IMPORT_ERRORS.append(traceback.format_exc())


# ────────────────────────────────────────────────────────────────
# Cached engine loaders
# ────────────────────────────────────────────────────────────────
# lru_cache(maxsize=1) instead of st.cache_resource — works the same
# way (load once, reuse for the life of the process) but has no
# Streamlit dependency, so this module is safe to import from a plain
# FastAPI process too.

@lru_cache(maxsize=1)
def load_scorer():
    return FraudScorer()


@lru_cache(maxsize=1)
def load_ml_model():
    clf = get_semantic_classifier()
    if not clf.is_trained:
        loaded = clf.load()
        if not loaded:
            # No pre-trained weights found — train from the full
            # labeled dataset (not a tiny hardcoded stand-in), so
            # behavior matches what train_model.py would produce.
            import pandas as pd
            try:
                df = pd.read_csv("data/scam_dataset.csv")
                texts = df["text"].astype(str).tolist()
                labels = df["label"].astype(int).tolist()
                clf.fit(texts, labels)
                clf.save()  # persist so next process start loads instantly
            except FileNotFoundError:
                raise RuntimeError(
                    "data/scam_dataset.csv not found — cannot train "
                    "the classifier. Run train_model.py or ensure the "
                    "dataset file is present."
                )
    return clf


@lru_cache(maxsize=1)
def load_history():
    engine = UnifiedHistoryEngine()
    if engine.index.ntotal == 0:
        engine.seed_from_dataset("data/scam_dataset.csv")
    return engine


# ────────────────────────────────────────────────────────────────
# Simulation fallback (used if real engines fail to import/load)
# ────────────────────────────────────────────────────────────────

def _simulate_scan(text: str) -> dict:
    """
    Hardcoded simulation so the app/API never crashes outright.
    Returns the SAME shape as the real pipeline (including keys that
    the real pipeline adds later, like conflict_detected) so callers
    — including the FastAPI response model — don't have to special-case
    simulation mode.
    """
    text_lower = text.lower()

    is_otp     = any(w in text_lower for w in ["otp", "one time"])
    is_lottery = any(w in text_lower for w in ["lottery", "won", "prize", "kbc", "lucky draw"])
    is_fee     = any(w in text_lower for w in ["registration fee", "pay", "₹", "rs.", "paytm", "phonepe"])
    is_safe    = any(w in text_lower for w in ["no fee", "no charges", "official website", "interview scheduled"])

    if is_otp:
        verdict, confidence, category = "SCAM", 92, "otp_fraud"
        reasons = ["Real banks NEVER ask for OTP via message/call. OTP sharing = scam",
                   "Lucky draw/lottery you never entered = guaranteed scam"]
        override = "OTP sharing detected — auto-classified as SCAM"
        breakdown = {"rules": 90, "domain": 80, "ml": 88, "campus": 95}
    elif is_lottery:
        verdict, confidence, category = "SCAM", 88, "lottery_prize"
        reasons = ["Lucky draw/lottery you never entered = guaranteed scam",
                   "Message contains fee demand"]
        override = None
        breakdown = {"rules": 85, "domain": 70, "ml": 82, "campus": 90}
    elif is_fee and not is_safe:
        verdict, confidence, category = "SCAM", 85, "internship_fee"
        reasons = ["Internshala never charges registration fee",
                   "Urgency language detected — a common scam pressure tactic"]
        override = None
        breakdown = {"rules": 88, "domain": 65, "ml": 78, "campus": 92}
    elif is_safe:
        verdict, confidence, category = "SAFE", 12, "safe"
        reasons = ["No suspicious patterns detected — message appears legitimate"]
        override = None
        breakdown = {"rules": 10, "domain": 5, "ml": 15, "campus": 8}
    else:
        verdict, confidence, category = "SUSPICIOUS", 52, "suspicious"
        reasons = ["Message contains some unusual patterns",
                   "Verify independently before acting"]
        override = None
        breakdown = {"rules": 50, "domain": 40, "ml": 55, "campus": 48}

    r = breakdown
    formula = (
        f"Rules Engine   {r['rules']:5.1f} × 0.35 = {r['rules']*0.35:5.1f}\n"
        f"Domain Check   {r['domain']:5.1f} × 0.30 = {r['domain']*0.30:5.1f}\n"
        f"Semantic AI    {r['ml']:5.1f} × 0.20 = {r['ml']*0.20:5.1f}\n"
        f"History FAISS  {r['campus']:5.1f} × 0.15 = {r['campus']*0.15:5.1f}\n"
        f"{'─'*42}\n"
        f"Final Score                   = {confidence:5.1f}"
    )

    action = {
        "steps": ["Do NOT pay any fee", "Block the sender immediately",
                  "Report at cybercrime.gov.in", "Call helpline 1930"],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "complaint_text": f"I received a suspicious message on {time.strftime('%d/%m/%Y')}.\n"
                          f"Message preview: \"{text[:120]}...\"\n"
                          f"Please investigate this fraud attempt.",
    }

    return {
        "final_score": confidence,
        "label": verdict,
        "category": category,
        "category_display": category.replace("_", " ").title(),
        "reasons": reasons,
        "breakdown": {
            "rules":   {"score": r["rules"],  "weight": 0.35, "reasons": reasons},
            "domain":  {"score": r["domain"], "weight": 0.30, "reasons": []},
            "ml":      {"score": r["ml"],     "weight": 0.20, "reason": "Simulated"},
            "history": {"score": r["campus"], "weight": 0.15, "matches": []},
        },
        "formula": formula,
        "override_applied": override,
        # Present even in simulation mode, for a consistent shape:
        "conflict_detected": False,
        "conflict_message": "",
        "entities_found": [],
        "extractions": {},
        "action": action,
    }


def get_action_safe(score: float, category: str, text: str) -> dict:
    """Wrapper so action_advisor never crashes the caller."""
    try:
        if not SIMULATION_MODE:
            return get_action(score, category, text)
    except Exception:
        pass
    return {
        "steps": ["Do NOT pay any fee", "Block the sender immediately",
                  "Report at cybercrime.gov.in", "Call helpline 1930"],
        "helpline": "1930",
        "online_url": "https://cybercrime.gov.in",
        "complaint_text": f"Suspicious message received on {time.strftime('%d/%m/%Y')}.\n"
                          f"Text: \"{text[:200]}\"",
    }


# ────────────────────────────────────────────────────────────────
# Main entrypoint — the ONE function both app.py and api.py call
# ────────────────────────────────────────────────────────────────

def run_full_pipeline(text: str) -> dict:
    """
    Run all 4 engines and return a unified result dict. Falls back to
    simulation if any engine throws — a bad scan should never take
    down the whole app/API.
    """
    if SIMULATION_MODE:
        result = _simulate_scan(text)
        result["action"] = get_action_safe(result["final_score"], result["category"], text)
        return result

    try:
        scorer = load_scorer()
        ml_clf = load_ml_model()
        history = load_history()

        ml_score, ml_reason = ml_clf.predict_proba(text)
        ml_similar = ml_clf.get_similar_training_examples(text, n=3)

        hist_result = history.search_and_explain(text, k=5)
        history_score = hist_result["score"]
        hist_matches = hist_result["matches"]

        result = scorer.calculate(
            text=text,
            ml_score=ml_score,
            ml_reason=ml_reason,
            ml_similar=ml_similar,
            history_score=history_score,
            history_matches=hist_matches,
        )

        result["action"] = get_action_safe(result["final_score"], result["category"], text)

        try:
            history.add_report(
                text=text,
                label=1 if result["label"] == "SCAM" else 0,
                category=result["category"],
                source="user_scan",
                score=result["final_score"],
            )
        except Exception:
            pass  # non-critical

        return result

    except Exception as e:
        result = _simulate_scan(text)
        result["action"] = get_action_safe(result["final_score"], result["category"], text)
        result["_fallback_error"] = str(e)
        return result