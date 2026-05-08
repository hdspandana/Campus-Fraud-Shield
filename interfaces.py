# interfaces.py
# ═══════════════════════════════════════════════════════
# Shared data formats for Campus Fraud Shield v3
# Every function in every module must return
# exactly these formats. Read this before coding.
# ═══════════════════════════════════════════════════════

# ── ML Model Output ─────────────────────────────────────
# Returned by: core/ml_model.py → predict_proba()
ML_OUTPUT = {
    "score":   0.0,   # float 0-100
    "reason":  "",    # one sentence, student-friendly
    "similar": []     # list of similar past messages
    # similar item format:
    # {
    #   "text":       str,   # first 80 chars
    #   "label":      int,   # 1=scam 0=safe
    #   "similarity": float  # 0.0 to 1.0
    # }
}

# ── History Engine Output ────────────────────────────────
# Returned by: core/history_engine.py → search_and_explain()
HISTORY_OUTPUT = {
    "score":       0.0,  # float 0-100
    "matches":     [],   # list of match dicts
    "explanation": ""    # why it matched
    # match item format:
    # {
    #   "similarity":      float,
    #   "category":        str,
    #   "overlap_phrases": list,
    #   "times_reported":  int,
    #   "explanation":     str
    # }
}

# ── Rules Engine Output ──────────────────────────────────
# Returned by: core/rules_engine.py → analyze()
RULES_OUTPUT = {
    "score":   0.0,  # float 0-100
    "reasons": [],   # list of strings
    "flags":   []    # list of matched rule names
    # reason item: plain English string
    # flag item:   rule identifier string
}

# ── Domain Checker Output ────────────────────────────────
# Returned by: core/domain_checker.py → analyze()
DOMAIN_OUTPUT = {
    "score":   0.0,  # float 0-100
    "reasons": [],   # list of strings
    "domains": []    # list of domains found in text
    # reason item: plain English string
}

# ── Campus Checker Output ────────────────────────────────
# Returned by: core/campus_checker.py → analyze()
CAMPUS_OUTPUT = {
    "score":          0.0,  # float 0-100
    "reasons":        [],   # list of strings
    "violations":     [],   # list of violation names
    "entities_found": []    # list of entity names detected
    # reason item:    plain English string
    # violation item: violation identifier string
}

# ── Final Scorer Output ──────────────────────────────────
# Returned by: core/scorer.py → calculate()
SCORER_OUTPUT = {
    "final_score": 0.0,    # float 0-100
    "label":       "",     # SCAM / SUSPICIOUS / SAFE
    "category":    "",     # scam subcategory
    "breakdown": {
        "rules":     {"score": 0.0, "weight": 0.35,
                      "reasons": []},
        "domain":    {"score": 0.0, "weight": 0.30,
                      "reasons": []},
        "ml":        {"score": 0.0, "weight": 0.20,
                      "reason": "",  "similar": []},
        "history":   {"score": 0.0, "weight": 0.15,
                      "matches": []}
    },
    "formula": ""          # human-readable calculation
}

# ── Action Advisor Output ────────────────────────────────
# Returned by: utils/action_advisor.py → get_action()
ACTION_OUTPUT = {
    "steps":          [],   # list of action strings
    "helpline":       "",   # phone number string
    "online_url":     "",   # URL string
    "complaint_text": ""    # pre-filled complaint
}

# ── Scam Categories ─────────────────────────────────────
# Used across all modules for consistency
SCAM_CATEGORIES = [
    "internship_fee",      # fake internship with fee
    "job_fee",             # fake job with registration fee
    "scholarship_fee",     # fake scholarship with fee
    "otp_fraud",           # OTP stealing attempt
    "lottery_prize",       # lottery / prize winning
    "parttime_job",        # fake part-time job
    "bank_impersonation",  # fake bank message
    "gov_scheme_fraud",    # fake government scheme
    "unknown_scam",        # scam but category unclear
    "suspicious",          # not confirmed scam
    "safe"                 # legitimate message
]

# ── Risk Labels ──────────────────────────────────────────
# Score to label mapping (used in scorer.py)
# score >= 70  → SCAM
# score >= 40  → SUSPICIOUS
# score <  40  → SAFE

LABEL_SCAM       = "SCAM"
LABEL_SUSPICIOUS = "SUSPICIOUS"
LABEL_SAFE       = "SAFE"

SCORE_SCAM_THRESHOLD       = 70.0
SCORE_SUSPICIOUS_THRESHOLD = 40.0

# ── Scoring Weights ──────────────────────────────────────
# Must add up to 1.0 exactly
WEIGHT_RULES   = 0.35
WEIGHT_DOMAIN  = 0.30
WEIGHT_ML      = 0.20
WEIGHT_HISTORY = 0.15

# ── Demo Messages ────────────────────────────────────────
# Used by app.py for quick demo buttons
DEMO_MESSAGES = {
    "fake_internship": {
        "label":    "📧 Fake Internship",
        "text":     (
            "Congratulations! You have been selected for "
            "internship at our MNC partner company through "
            "Internshala. To confirm your slot, pay "
            "Rs.1500 registration fee on Paytm number "
            "9876543210. Offer expires in 24 hours. "
            "Do not miss this opportunity."
        ),
        "expected": "SCAM",
        "score":    92
    },
    "prize_scam": {
        "label":    "🏆 Prize Scam",
        "text":     (
            "Dear Student, Your mobile number has won "
            "Rs.50,000 in KBC lucky draw. To claim your "
            "prize send OTP received on your number to "
            "our agent. Contact: prizekbc@gmail.com "
            "or WhatsApp 9123456789. Limited time offer."
        ),
        "expected": "SCAM",
        "score":    88
    },
    "scholarship_scam": {
        "label":    "📚 Scholarship Scam",
        "text":     (
            "NSP Scholarship of Rs.25,000 has been "
            "approved for your application. Pay Rs.500 "
            "processing fee to release amount to your "
            "bank account. Send fee to PhonePe: "
            "8765432109. Amount will be credited in 2 hours."
        ),
        "expected": "SCAM",
        "score":    85
    },
    "real_message": {
        "label":    "✅ Real Message",
        "text":     (
            "Your application for Software Developer "
            "Internship at TCS has been received. "
            "Interview scheduled for Monday 3PM IST. "
            "Join via Microsoft Teams link sent to "
            "your registered email. No fee required."
        ),
        "expected": "SAFE",
        "score":    12
    }
}