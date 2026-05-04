# core/rules.py
import re

# ─── Scam keyword weights (Indian context) ────────────────────────────────────
SCAM_KEYWORDS = {
    # Urgency triggers
    "urgent":              20,
    "limited time":        20,
    "act now":             20,
    "expires today":       25,
    "last chance":         20,
    "immediately":         15,
    "within 2 hours":      25,
    "within 24 hours":     20,
    "today only":          20,

    # Money / rewards
    "free":                15,
    "earn":                15,
    "prize":               20,
    "winner":              20,
    "reward":              15,
    "cashback":            10,
    "congratulations":     15,
    "lucky draw":          25,
    "lottery":             25,
    "gift card":           20,
    "guaranteed":          20,
    "100%":                15,
    "3x returns":          35,
    "double":              20,
    "get rich":            30,
    "invest":              15,

    # Auth / verification
    "otp":                 35,
    "verify":              15,
    "verification":        15,
    "confirm your":        20,
    "update your":         15,
    "account suspended":   35,
    "account blocked":     35,
    "account will be":     20,
    "kyc":                 25,
    "aadhar":              20,
    "pan card":            20,
    "password":            20,
    "pin":                 20,
    "cvv":                 35,

    # Payment
    "upi":                 15,
    "scan qr":             25,
    "gpay":                10,
    "phonepe":             10,
    "paytm":               10,
    "registration fee":    35,
    "refundable deposit":  35,
    "processing fee":      30,
    "customs fee":         30,
    "training fee":        30,
    "courier charges":     25,
    "background verification fee": 35,

    # Fake jobs / internships
    "work from home":      15,
    "earn per day":        25,
    "earn per week":       25,
    "no experience":       15,
    "selected for":        10,
    "offer letter":        10,
    "no interview":        25,
    "send aadhar":         35,
    "bank details":        35,
    "bank account":        30,

    # Social engineering
    "dm me":               10,
    "whatsapp me":         15,
    "call immediately":    20,
    "strictly confidential": 15,
    "only for you":        15,
}

# ─── Short link services ──────────────────────────────────────────────────────
SHORT_LINKS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "rb.gy", "cutt.ly", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "ift.tt",
]

# ─── Sensitive information requests ──────────────────────────────────────────
SENSITIVE_INFO = [
    "aadhar", "pan card", "bank account",
    "password", "otp", "pin", "cvv",
    "credit card", "debit card",
]


def check_keywords(text: str) -> tuple[int, list[str]]:
    t = text.lower()
    score, reasons, seen = 0, [], set()

    for kw, weight in SCAM_KEYWORDS.items():
        if kw in t and kw not in seen:
            score += weight
            seen.add(kw)
            reasons.append(f'🔴 Suspicious keyword: "{kw}"')

    return min(score, 70), reasons


def check_short_links(text: str) -> tuple[int, list[str]]:
    score, reasons = 0, []
    for domain in SHORT_LINKS:
        if domain in text.lower():
            score += 30
            reasons.append(f"🔗 Short/masked link ({domain}) — hides real destination")
            break
    return score, reasons


def check_patterns(text: str) -> tuple[int, list[str]]:
    score, reasons = 0, []

    # Excessive exclamation marks
    if text.count("!") >= 3:
        score += 10
        reasons.append("❗ Excessive urgency punctuation (!!!)")

    # ALL CAPS words
    caps = re.findall(r"\b[A-Z]{4,}\b", text)
    if caps:
        score += 10
        reasons.append(f"📢 All-caps shouting: {', '.join(set(caps[:3]))}")

    # Indian mobile number
    if re.search(r"\b[6-9]\d{9}\b", text):
        score += 15
        reasons.append("📱 Contains Indian mobile number (possible vishing)")

    # Sensitive info request
    for item in SENSITIVE_INFO:
        if item in text.lower():
            score += 30
            reasons.append(f'🔐 Requests sensitive info: "{item}"')

    # Money amount pattern
    if re.search(r"(₹|rs\.?)\s?\d+", text.lower()):
        score += 10
        reasons.append("💰 Specific money amount mentioned")

    # Guarantee language
    if re.search(r"(100%|guaranteed|assured)", text.lower()):
        score += 15
        reasons.append('⚠️ Uses guarantee language ("100%", "guaranteed")')

    # IP address in URL
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", text):
        score += 40
        reasons.append("🌐 Raw IP address used in URL — very suspicious")

    return score, reasons


def check_payment_keywords(text: str) -> bool:
    """Returns True if text contains payment-related keywords."""
    payment_kws = [
        "pay", "₹", "rs.", "upi", "gpay", "phonepe",
        "paytm", "registration fee", "processing fee",
        "transfer", "send money", "scan qr", "deposit",
        "refundable", "fee", "charges",
    ]
    t = text.lower()
    return any(kw in t for kw in payment_kws)


def run_rules(text: str) -> tuple[int, list[str], bool]:
    """
    Returns:
        total_score (int)
        reasons     (list of strings)
        payment_found (bool) → used for trusted+payment override
    """
    s1, r1 = check_keywords(text)
    s2, r2 = check_short_links(text)
    s3, r3 = check_patterns(text)

    total   = min(s1 + s2 + s3, 100)
    reasons = r1 + r2 + r3
    payment = check_payment_keywords(text)

    return total, reasons, payment