# config.py
# Central configuration for Campus Fraud Shield

import os
from dotenv import load_dotenv

load_dotenv()

# ─── API Keys ────────────────────────────────────────────────────────────────
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_KEY           = os.getenv("VIRUSTOTAL_API_KEY", "")
ADMIN_PASSWORD           = os.getenv("ADMIN_PASSWORD", "cfs_admin_2024")

# ─── Scoring Weights ─────────────────────────────────────────────────────────
WEIGHTS = {
    "rules":   0.35,
    "domain":  0.20,
    "ml":      0.25,
    "history": 0.20,
}

# ─── Score Thresholds ────────────────────────────────────────────────────────
THRESHOLD_SAFE       = 30
THRESHOLD_SUSPICIOUS = 70

# ─── Risk Labels ─────────────────────────────────────────────────────────────
LABEL_SAFE       = "Safe"
LABEL_SUSPICIOUS = "Suspicious"
LABEL_SCAM       = "Scam"

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