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
import logging
import traceback
from functools import lru_cache

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Logging ────────────────────────────────────────────────────────
# A library module shouldn't call logging.basicConfig() itself (that's
# an entrypoint's job — api.py / app.py decide handlers/format), it
# should just grab a named logger. If nothing configures logging,
# Python's default "handler of last resort" still prints warnings/
# errors to stderr, so this is never silent even with zero setup.
logger = logging.getLogger("campus_fraud_shield")

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
    logger.error(
        "Falling back to SIMULATION_MODE — real detection engines "
        "failed to import: %s", e, exc_info=True
    )

# Needed even in SIMULATION_MODE — the fallback formula/breakdown
# below previously hardcoded the OLD weights (0.35/0.30/0.20/0.15)
# directly as literals, so it silently went stale when the real
# weights in interfaces.py were updated based on eval evidence. This
# import has no dependency on the ML/FAISS stack that can fail above,
# so it's safe to do unconditionally, outside the try/except.
from interfaces import WEIGHT_RULES, WEIGHT_DOMAIN, WEIGHT_ML, WEIGHT_HISTORY


# ────────────────────────────────────────────────────────────────
# Cached engine loaders
# ────────────────────────────────────────────────────────────────
# lru_cache(maxsize=1) instead of st.cache_resource — works the same
# way (load once, reuse for the life of the process) but has no
# Streamlit dependency, so this module is safe to import from a plain
# FastAPI process too.

@lru_cache(maxsize=1)
def load_scorer():
    # BUG FOUND during audit: previously this called FraudScorer()
    # unconditionally, even when SIMULATION_MODE is True (meaning the
    # `from core.scorer import FraudScorer` import above already
    # failed) -- referencing a name that was never actually imported
    # raises a raw, undocumented NameError. Found via api.py's /scan
    # endpoint returning an unhandled 500 with no useful message.
    # Callers (api.py, app.py) should check SIMULATION_MODE and use
    # _simulate_scan() instead of calling this at all -- this guard is
    # a safety net for any caller that doesn't.
    if SIMULATION_MODE:
        raise RuntimeError(
            "load_scorer() called while SIMULATION_MODE is active -- "
            f"the real scorer failed to import: {IMPORT_ERRORS[:1]}. "
            "Callers should check pipeline.SIMULATION_MODE and use "
            "_simulate_scan() instead of the real engines."
        )
    return FraudScorer()


@lru_cache(maxsize=1)
def load_ml_model():
    if SIMULATION_MODE:
        raise RuntimeError(
            "load_ml_model() called while SIMULATION_MODE is active -- "
            f"the real ML classifier failed to import: {IMPORT_ERRORS[:1]}. "
            "Callers should check pipeline.SIMULATION_MODE and use "
            "_simulate_scan() instead of the real engines."
        )
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

    # Regardless of whether the model above was just freshly trained
    # OR loaded from an existing saved file (e.g. left over from an
    # earlier deploy/reboot on a host that keeps its disk between
    # restarts) — make sure data/model_metrics.json exists. This is
    # deliberately decoupled from "did we just train" above: relying
    # on that alone meant a pre-existing saved model (from before this
    # fix existed, or from a container that wasn't fully wiped on
    # reboot) would silently skip metrics generation forever, which is
    # exactly the bug that caused the dashboard to say "no metrics
    # found" even after the model itself worked fine.
    metrics_path = "data/model_metrics.json"
    if clf.is_trained and not os.path.exists(metrics_path):
        try:
            import pandas as pd
            from core.ml_model import write_model_metrics
            df = pd.read_csv("data/scam_dataset.csv")
            write_model_metrics(clf, df, metrics_path)
            logger.info("Generated missing %s from the currently loaded model.", metrics_path)
        except Exception:
            logger.warning(
                "Could not generate %s — the Model Performance "
                "dashboard may be unavailable.", metrics_path, exc_info=True,
            )

    return clf


@lru_cache(maxsize=1)
def load_history():
    if SIMULATION_MODE:
        raise RuntimeError(
            "load_history() called while SIMULATION_MODE is active -- "
            f"the real history/FAISS engine failed to import: {IMPORT_ERRORS[:1]}. "
            "Callers should check pipeline.SIMULATION_MODE and use "
            "_simulate_scan() instead of the real engines."
        )
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
        f"Rules Engine   {r['rules']:5.1f} × {WEIGHT_RULES:.2f} = {r['rules']*WEIGHT_RULES:5.1f}\n"
        f"Domain Check   {r['domain']:5.1f} × {WEIGHT_DOMAIN:.2f} = {r['domain']*WEIGHT_DOMAIN:5.1f}\n"
        f"Semantic AI    {r['ml']:5.1f} × {WEIGHT_ML:.2f} = {r['ml']*WEIGHT_ML:5.1f}\n"
        f"History FAISS  {r['campus']:5.1f} × {WEIGHT_HISTORY:.2f} = {r['campus']*WEIGHT_HISTORY:5.1f}\n"
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
            "rules":   {"score": r["rules"],  "weight": WEIGHT_RULES, "reasons": reasons},
            "domain":  {"score": r["domain"], "weight": WEIGHT_DOMAIN, "reasons": []},
            "ml":      {"score": r["ml"],     "weight": WEIGHT_ML, "reason": "Simulated"},
            "history": {"score": r["campus"], "weight": WEIGHT_HISTORY, "matches": []},
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
        logger.warning("get_action() failed, using fallback action advice", exc_info=True)
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

def run_full_pipeline(
    text: str,
    scorer=None,
    ml_clf=None,
    history=None,
) -> dict:
    """
    Run all 4 engines and return a unified result dict. Falls back to
    simulation if any engine throws — a bad scan should never take
    down the whole app/API.

    scorer / ml_clf / history are optional dependency-injection points:
    - app.py (Streamlit) calls this with no args — defaults kick in and
      call the normal cached loaders, so existing call sites don't
      need to change.
    - api.py (FastAPI) supplies these via Depends(), so tests can swap
      in fakes/mocks through app.dependency_overrides without needing
      to monkey-patch this module's internals.
    """
    if SIMULATION_MODE:
        result = _simulate_scan(text)
        result["action"] = get_action_safe(result["final_score"], result["category"], text)
        return result

    try:
        scorer  = scorer  if scorer  is not None else load_scorer()
        ml_clf  = ml_clf  if ml_clf  is not None else load_ml_model()
        history = history if history is not None else load_history()

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
            # Non-critical: failing to log this scan to history should
            # never break the scan result itself, but we do want to
            # know about it rather than silently losing the failure.
            logger.warning("Failed to record scan to history", exc_info=True)

        return result

    except Exception as e:
        logger.error("run_full_pipeline failed, falling back to simulation for this scan: %s", e, exc_info=True)
        result = _simulate_scan(text)
        result["action"] = get_action_safe(result["final_score"], result["category"], text)
        result["_fallback_error"] = str(e)
        return result