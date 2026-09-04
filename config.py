# config.py
# Central configuration for Campus Fraud Shield

import os
from dotenv import load_dotenv

load_dotenv()

# ─── API Keys ────────────────────────────────────────────────────────────────
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_KEY           = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─── Scoring Weights & Thresholds ────────────────────────────────────────────
# REMOVED: this file previously had its own WEIGHTS dict (0.35/0.20/0.25/0.20)
# and THRESHOLD_SAFE/THRESHOLD_SUSPICIOUS (30/70) that were never actually
# imported by scorer.py, app.py, or anywhere else in the codebase — dead
# code that quietly disagreed with the real values. The real, actually-used
# weights and thresholds live in interfaces.py (WEIGHT_RULES, WEIGHT_DOMAIN,
# WEIGHT_ML, WEIGHT_HISTORY, SCORE_SCAM_THRESHOLD, SCORE_SUSPICIOUS_THRESHOLD),
# validated via eval/nested_weight_validation.py. If you need the weights
# anywhere, import them from interfaces.py, not from here.

# ─── Colors ──────────────────────────────────────────────────────────────────
# REMOVED: COLOR_SAFE / COLOR_SUSPICIOUS / COLOR_SCAM — confirmed zero
# references anywhere; app.py uses its own dark-theme palette
# (#00d4ff etc.), never these.

# ─── File Paths ──────────────────────────────────────────────────────────────
# REMOVED (this week's dead-code pass): SCAM_DATASET_FILE, MODEL_FILE,
# VECTORIZER_FILE, REPORTED_SCAMS_FILE, TRUSTED_DOMAINS_FILE — confirmed
# via a full-repo grep to have zero references anywhere outside this
# file. models/scam_classifier.pkl (what MODEL_FILE pointed to) is a
# tracked-but-orphaned binary from an earlier TF-IDF-era architecture;
# the real model is core/ml_model.py's CLASSIFIER_PATH
# ("models/semantic_classifier.pkl"). If you want it gone from git
# history too: `git rm models/scam_classifier.pkl`.
#
# PAYMENT_OVERRIDE_KEYWORDS also removed — zero references; the actual,
# live fee/payment detection is core/rules_engine.py's FEE_PATTERNS
# and PAYMENT_PATTERNS, which this list never fed into.

# ─── Indian Context ──────────────────────────────────────────────────────────
HELPLINES = {
    "Cyber Crime":   "1930",
    "Police":        "100",
    "Women Helpline":"1091",
    "Bank Fraud":    "155260",
}

REPORT_PORTALS = {
    "Cyber Crime Portal": "cybercrime.gov.in",
    "Spam SMS / Call":    "sancharsaathi.gov.in",
    "Consumer Forum":     "consumerhelpline.gov.in",
}