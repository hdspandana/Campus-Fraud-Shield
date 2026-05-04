# core/scorer.py
from config import (
    WEIGHTS, THRESHOLD_SAFE, THRESHOLD_SUSPICIOUS,
    LABEL_SAFE, LABEL_SUSPICIOUS, LABEL_SCAM,
    COLOR_SAFE, COLOR_SUSPICIOUS, COLOR_SCAM,
)


def calculate_final_score(
    rule_score:    int,
    domain_score:  int,
    ml_score:      int,
    history_score: int,
    is_trusted:    bool,
    payment_found: bool,
    api_score:     int = 0,
) -> int:
    """
    Intelligent scoring with contextual overrides.
    """

    # ── Override 1: History match ─────────────────────────────────────────
    if history_score >= 80:
        return min(95, 70 + history_score // 5)

    # ── Override 2: API confirmed malicious ───────────────────────────────
    if api_score >= 80:
        return min(98, api_score)

    # ── Override 3: High domain score = scam URL ──────────────────────────
    # THIS IS THE KEY FIX
    # If domain alone is very suspicious (brand impersonation etc)
    # boost it significantly regardless of other scores
    if domain_score >= 70:
        # Domain is highly suspicious → minimum score is 65
        base = max(
            int(domain_score * 0.85),  # 85% of domain score as base
            65
        )
        # Add rule contribution on top
        final = min(base + int(rule_score * 0.15), 100)
        return final

    # ── Override 4: Trusted + Payment = Suspicious ────────────────────────
    if is_trusted and payment_found:
        rule_score = max(rule_score, 75)

    # ── Weighted calculation ──────────────────────────────────────────────
    weighted = (
        rule_score    * 0.35 +
        domain_score  * 0.30 +   # Increased from 0.20
        ml_score      * 0.20 +
        history_score * 0.15
    )

    # Add API score as bonus
    if api_score > 0:
        weighted = (weighted * 0.8) + (api_score * 0.2)

    final = int(weighted)

    # ── Override 5: Trust discount (only if clean) ────────────────────────
    if is_trusted and not payment_found and domain_score < 30:
        final = max(0, final - 25)

    return min(final, 100)


def decide(score: int) -> tuple[str, str, str]:
    if score <= THRESHOLD_SAFE:
        return (
            LABEL_SAFE, "✅",
            "This looks okay. Still verify the sender's identity officially.",
        )
    elif score <= THRESHOLD_SUSPICIOUS:
        return (
            LABEL_SUSPICIOUS, "⚠️",
            "Do NOT click links or share info. Verify with the official source.",
        )
    else:
        return (
            LABEL_SCAM, "🚫",
            "STOP! This is very likely a scam. Block and report immediately.",
        )


def get_score_color(label: str) -> str:
    return {
        LABEL_SAFE:       COLOR_SAFE,
        LABEL_SUSPICIOUS: COLOR_SUSPICIOUS,
        LABEL_SCAM:       COLOR_SCAM,
    }.get(label, "#6b7280")


def get_scam_type(text: str) -> tuple[str, str, str]:
    t = text.lower()

    TYPES = [
        ("payment",    "💸", "Payment Fraud",
         "#f59e0b",
         ["upi","qr","gpay","phonepe","paytm","₹","fee","deposit"]),

        ("job",        "🎓", "Fake Job / Internship",
         "#8b5cf6",
         ["internship","job","hiring","selected","work from home",
          "earn per day","no interview"]),

        ("phishing",   "🔐", "Phishing Attack",
         "#3b82f6",
         ["otp","verify","account","password","kyc","aadhar",
          "suspended","blocked","login"]),

        ("link",       "🔗", "Malicious Link",
         "#ef4444",
         ["bit.ly","tinyurl","click","free","prize","won",
          "lottery","giveaway"]),

        ("social",     "📱", "Social Media Scam",
         "#10b981",
         ["instagram","dm","seller","whatsapp","telegram","cod"]),

        ("investment", "📈", "Investment Scam",
         "#f43f5e",
         ["invest","returns","profit","crypto","trading",
          "3x","double","referral"]),

        ("impersonation","🎭","Brand Impersonation",
         "#ef4444",
         ["amazon","google","sbi","hdfc","paytm","flipkart",
          "microsoft","apple","nptel","whatsapp"]),
    ]

    for _, emoji, label, color, keywords in TYPES:
        if any(k in t for k in keywords):
            return emoji, label, color

    return "⚠️", "Suspicious Content", "#9ca3af"