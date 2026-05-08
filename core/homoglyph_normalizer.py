# core/homoglyph_normalizer.py
# Complete rewrite — Spoofed brands = GUARANTEED SCAM
# No fuzzy threshold nonsense, no partial scoring
# g00gle / gooogle / payтm = instant high score

import re
import unicodedata
from typing import List, Tuple, Dict

# ── Homoglyph Map ──────────────────────────────────────────────
HOMOGLYPH_MAP: Dict[str, str] = {
    # Digits as letters (most common in scams)
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    # Cyrillic (very common in Indian scams)
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "u", "і": "i",
    "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g",
    "т": "t", "ь": "b", "н": "n", "м": "m",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n",
    "ι": "i", "κ": "k", "μ": "m", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x",
    # Zero-width / invisible (strip completely)
    "\u200b": "", "\u200c": "", "\u200d": "",
    "\ufeff": "", "\u00ad": "",
    # Unicode accented → base
    "à": "a", "á": "a", "â": "a", "ä": "a",
    "è": "e", "é": "e", "ê": "e",
    "ì": "i", "í": "i",
    "ò": "o", "ó": "o", "ô": "o", "ö": "o",
    "ù": "u", "ú": "u", "ü": "u",
    "ñ": "n",
}

# ── All protected brands ───────────────────────────────────────
CANONICAL_BRANDS = [
    "google", "paytm", "phonepe", "gpay", "sbi", "hdfc", "icici",
    "axis", "tcs", "infosys", "wipro", "cognizant", "accenture",
    "amazon", "microsoft", "internshala", "naukri", "linkedin",
    "letsintern", "unstop", "hackerearth", "foundit", "nsp",
    "ugc", "aicte", "irctc", "uidai", "nta", "rbi", "epfo",
    "freshersworld", "apna", "monsterindia", "shine", "timesjobs",
    "hcl",
]

# ── Thresholds ─────────────────────────────────────────────────
FUZZY_THRESHOLD = 0.75   # minimum similarity to flag as spoof

# ── Scores — these are HIGH because spoofed brand = guaranteed scam
SPOOF_BASE_SCORE      = 85   # base score just for spoofing a brand name
SPOOF_WITH_FEE        = 95   # spoof + fee demand = almost certain scam
SPOOF_IN_DOMAIN       = 90   # fake domain like g00gle.com or gooogle.com
SPOOF_WITH_PAYMENT    = 95   # spoof + payment number


# ── Internal: normalize single word for detection only ─────────
def _normalize_word(word: str) -> str:
    """
    Normalize a single word for spoof detection.
    Result is ONLY used for comparison — never fed to safety checks.
    """
    result = []
    for char in word:
        mapped = HOMOGLYPH_MAP.get(char)
        if mapped is not None:
            result.append(mapped)
        else:
            nfkd = unicodedata.normalize("NFKD", char)
            ascii_char = nfkd.encode("ascii", "ignore").decode("ascii")
            result.append(ascii_char if ascii_char else char)

    normalized = "".join(result).lower()
    # gooogle → gogle (collapse 3+ repeated → 2)
    # then fuzzy match catches it
    normalized = re.sub(r"(.)\1{2,}", r"\1\1", normalized)
    return normalized


# ── Internal: LCS similarity ───────────────────────────────────
def _char_similarity(word1: str, word2: str) -> float:
    """LCS-based character similarity. Fast for short brand names."""
    if word1 == word2:
        return 1.0

    len1, len2 = len(word1), len(word2)
    if len1 == 0 or len2 == 0:
        return 0.0
    if abs(len1 - len2) > max(len1, len2) * 0.45:
        return 0.0

    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            if word1[i - 1] == word2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    return dp[len1][len2] / max(len1, len2)


# ── Public: find all spoofed brands in text ────────────────────
def find_spoofed_brands(
    text: str,
    threshold: float = FUZZY_THRESHOLD
) -> List[Dict]:
    """
    Find all words that visually spoof a known brand name.

    Returns list of:
        original      - the word as it appears in text
        normalized    - what it decodes to
        matched_brand - the real brand being impersonated
        similarity    - 0.0 to 1.0
    """
    # Extract tokens from original text (include Cyrillic/Greek ranges)
    tokens = re.findall(
        r"[a-zA-Z0-9\u0400-\u04ff\u0370-\u03ff\u00c0-\u024f@$!|+]+",
        text
    )

    spoofs  = []
    seen    = set()

    for token in tokens:
        if len(token) < 3:
            continue

        norm = _normalize_word(token)

        for brand in CANONICAL_BRANDS:
            # ── Skip if it IS the real brand ───────────────────
            # Real "google" should never be penalized
            if token.lower() == brand:
                continue
            if norm == brand:
                # normalized matches brand BUT original doesn't
                # = it IS a spoof (e.g. "g00gle" normalizes to "google")
                # only skip if original is already clean
                if token.lower() == brand:
                    continue

            sim = _char_similarity(norm, brand)

            if sim >= threshold:
                key = f"{token.lower()}:{brand}"
                if key not in seen:
                    seen.add(key)
                    spoofs.append({
                        "original":      token,
                        "normalized":    norm,
                        "matched_brand": brand,
                        "similarity":    round(sim, 3),
                    })

    spoofs.sort(key=lambda x: x["similarity"], reverse=True)
    return spoofs


# ── Public: get score + reasons ────────────────────────────────
def get_spoof_score(text: str) -> Tuple[float, List[str]]:
    """
    Main function called by campus_checker and rules_engine.

    Returns:
        (score, reasons)

    Score logic:
        Any spoof detected        → 85  (base, guaranteed scam territory)
        Spoof + fee/pay keyword   → 95
        Spoof in email/URL domain → 90
        Spoof + phone number      → 95
    """
    spoofs = find_spoofed_brands(text)

    if not spoofs:
        return 0.0, []

    reasons = []
    score   = float(SPOOF_BASE_SCORE)  # Start at 85 immediately

    # Build reasons for each spoof
    for spoof in spoofs[:3]:
        brand    = spoof["matched_brand"]
        original = spoof["original"]
        sim      = spoof["similarity"]

        if sim >= 0.95:
            # Near-perfect spoof like g00gle
            reasons.append(
                f"'{original}' is a FAKE version of '{brand.upper()}' "
                f"— scammers replace letters with similar-looking "
                f"characters to trick you. This is NOT the real "
                f"{brand.title()}."
            )
        else:
            reasons.append(
                f"'{original}' is impersonating '{brand.upper()}' "
                f"({sim:.0%} visual match) — "
                f"no legitimate company misspells its own name."
            )

    # ── Boost: spoof + fee keyword ─────────────────────────────
    fee_keywords = [
        "fee", "pay", "deposit", "send", "transfer",
        "registration", "joining", "processing", "charge",
        "rs", "₹", "paisa", "amount", "bhejo",
    ]
    has_fee = any(
        re.search(rf"\b{kw}\b", text, re.IGNORECASE)
        for kw in fee_keywords
    )
    if has_fee:
        score = max(score, float(SPOOF_WITH_FEE))
        reasons.append(
            "Spoofed brand name + payment demand = "
            "textbook impersonation scam. Real companies "
            "never misspell their own name."
        )

    # ── Boost: spoof in domain/email ──────────────────────────
    domain_matches = re.findall(
        r"@[a-zA-Z0-9.\-\u0400-\u04ff\u0370-\u03ff]+"
        r"|https?://[^\s]+"
        r"|www\.[^\s]+",
        text, re.IGNORECASE
    )
    for dm in domain_matches:
        domain_spoofs = find_spoofed_brands(dm)
        if domain_spoofs:
            score = max(score, float(SPOOF_IN_DOMAIN))
            reasons.append(
                f"Fake domain detected: '{dm[:50]}' — "
                f"scammers register lookalike domains to steal "
                f"your credentials. Do NOT click or visit."
            )
            break

    # ── Boost: spoof + phone number ────────────────────────────
    has_phone = bool(re.search(r"\b[6-9]\d{9}\b", text))
    if has_phone:
        score = max(score, float(SPOOF_WITH_PAYMENT))
        reasons.append(
            "Fake brand name + personal phone number — "
            "real companies never give personal mobile numbers. "
            "This is a scam payment collection attempt."
        )

    return min(score, 100.0), reasons


# ── Quick test ─────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        # (message, expected label)
        ("Pay Rs.2000 to g00gle hr@g00gle.com",        "SCAM"),
        ("Internship at gooogle.com pay fee 9876543210","SCAM"),
        ("payтm 9876543210 send Rs.1500 fee",          "SCAM"),
        ("ρhonepe registration fee Rs.500",            "SCAM"),
        ("amaz0n job offer pay joining fee",           "SCAM"),
        ("Apply at google.com careers page",           "SAFE"),
        ("Paytm helpline 1800-XXX-XXXX visit paytm.com","SAFE"),
    ]

    print("Spoof Detection Test")
    print("=" * 65)

    for msg, expected in tests:
        score, reasons = get_spoof_score(msg)
        label = "SCAM" if score >= 70 else "SAFE"
        status = "✅" if label == expected else "❌"

        print(f"\n{status} [{expected}] → [{label}] score={score:.0f}")
        print(f"   Message: {msg}")
        if reasons:
            print(f"   Reason:  {reasons[0][:80]}")