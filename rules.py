import re

# ── Keyword weights (Indian scam context) ─────────────────────────────────────
SCAM_KEYWORDS = {
    # Urgency
    "urgent": 20,
    "limited time": 20,
    "act now": 20,
    "expires today": 25,
    "last chance": 20,
    "immediately": 15,

    # Money / rewards
    "free": 15,
    "earn": 15,
    "₹": 10,
    "rs.": 10,
    "prize": 20,
    "winner": 20,
    "reward": 15,
    "cashback": 10,
    "congratulations": 15,
    "lucky draw": 25,
    "lottery": 25,
    "gift card": 20,

    # Auth / verification
    "otp": 30,
    "verify": 15,
    "verification": 15,
    "confirm your": 20,
    "update your": 15,
    "account suspended": 30,
    "account blocked": 30,
    "kyc": 25,
    "aadhar": 20,
    "pan card": 20,
    "password": 20,

    # Payment
    "upi": 15,
    "scan qr": 25,
    "gpay": 10,
    "phonepe": 10,
    "paytm": 10,
    "registration fee": 30,
    "refundable deposit": 30,
    "processing fee": 25,

    # Fake jobs / internships
    "work from home": 15,
    "part time job": 15,
    "earn per day": 25,
    "earn per week": 25,
    "no experience": 15,
    "fresher": 5,
    "selected for internship": 20,
    "offer letter": 10,

    # Social engineering
    "do not share": 10,
    "confidential": 10,
    "only for you": 15,
    "personal offer": 15,
    "dm me": 10,
    "whatsapp me": 15,
    "call immediately": 20,
}

SHORT_LINK_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "rb.gy", "cutt.ly", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "ift.tt",
]


def check_keywords(text: str) -> tuple[int, list[str]]:
    text_lower = text.lower()
    score = 0
    reasons = []
    seen = set()

    for keyword, weight in SCAM_KEYWORDS.items():
        if keyword in text_lower and keyword not in seen:
            score += weight
            seen.add(keyword)
            reasons.append(f'Suspicious word detected: "{keyword}"')

    return min(score, 70), reasons


def check_short_links(text: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    for domain in SHORT_LINK_DOMAINS:
        if domain in text.lower():
            score += 25
            reasons.append(f"Short/masked link found ({domain})")
            break
    return score, reasons


def check_patterns(text: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    # Excessive exclamation
    if text.count("!") >= 3:
        score += 10
        reasons.append("Excessive urgency punctuation (!!!)")

    # All caps words
    caps = re.findall(r'\b[A-Z]{4,}\b', text)
    if caps:
        score += 10
        reasons.append(f"All-caps shouting detected: {', '.join(set(caps[:3]))}")

    # 10 digit phone number
    if re.search(r'\b[6-9]\d{9}\b', text):
        score += 15
        reasons.append("Contains Indian mobile number (possible vishing attempt)")

    # Sensitive info requests
    sensitive = ["aadhar", "pan card", "bank account", "password", "pin", "cvv"]
    for item in sensitive:
        if item in text.lower():
            score += 25
            reasons.append(f'Asks for sensitive info: "{item}"')

    # Money amount pattern (₹500, Rs.1000 etc)
    if re.search(r'(₹|rs\.?)\s?\d+', text.lower()):
        score += 10
        reasons.append("Specific money amount mentioned")

    # Guarantee language
    if re.search(r'(100%|guaranteed|assured)', text.lower()):
        score += 15
        reasons.append('Uses guarantee language ("100%", "guaranteed")')

    return score, reasons


def run_rules(text: str) -> tuple[int, list[str]]:
    """Run all rule checks → return (total_score, reasons)"""
    s1, r1 = check_keywords(text)
    s2, r2 = check_short_links(text)
    s3, r3 = check_patterns(text)

    total = s1 + s2 + s3
    reasons = r1 + r2 + r3

    return min(total, 100), reasons