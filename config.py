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
COLOR_SAFE       = "#22c55e"
COLOR_SUSPICIOUS = "#f59e0b"
COLOR_SCAM       = "#ef4444"

# ─── File Paths ──────────────────────────────────────────────────────────────
REPORTED_SCAMS_FILE  = "data/reported_scams.json"
TRUSTED_DOMAINS_FILE = "data/trusted_domains.json"
SCAM_DATASET_FILE    = "data/scam_dataset.csv"
MODEL_FILE           = "models/scam_classifier.pkl"
VECTORIZER_FILE      = "models/vectorizer.pkl"

# ─── Overrides ───────────────────────────────────────────────────────────────
# Trusted platform + payment keyword = force suspicious
PAYMENT_OVERRIDE_KEYWORDS = [
    "registration fee", "processing fee", "refundable deposit",
    "pay", "upi", "gpay", "phonepe", "paytm", "scan qr",
    "transfer", "send money", "₹", "rs.", "otp", "bank account",
]

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