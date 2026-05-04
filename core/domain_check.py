# core/domain_check.py
import re
import json
import tldextract
from core.preprocessor import extract_urls
from config import TRUSTED_DOMAINS_FILE


# ─── Load trusted data ────────────────────────────────────────────────────────
def _load_trusted_data() -> dict:
    try:
        with open(TRUSTED_DOMAINS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"trusted_domains": [], "real_brand_domains": {}}


_TRUSTED_DATA = _load_trusted_data()
REAL_BRANDS   = _TRUSTED_DATA.get("real_brand_domains", {})
TRUSTED_LIST  = _TRUSTED_DATA.get("trusted_domains", [])

# ─── Suspicious TLDs ──────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "click", "loan",
    "win", "racing", "download",
    "stream", "trade", "review",
    "buzz", "gdn", "men", "work",
    "cam", "monster", "zip", "mov",
]

# ─── Suspicious words in domain ───────────────────────────────────────────────
SUSPICIOUS_DOMAIN_WORDS = [
    "free", "earn", "prize", "win", "reward",
    "claim", "lucky", "bonus", "offer",
    "verify", "secure", "update", "login",
    "account", "bank", "payment", "money",
    "job", "internship", "hiring",
    "limited", "urgent", "confirm",
    "refund", "cashback", "recover",
    "help", "support", "helpme",
    "alert", "notice", "suspend",
    "kyc", "otp", "authenticate",
]

# ─── Short link services ──────────────────────────────────────────────────────
SHORT_LINK_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "rb.gy", "cutt.ly", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "ift.tt",
]


def extract_full_domain_parts(url: str) -> dict:
    """
    Uses tldextract for proper domain parsing.
    amazon-helpmenow.com →
        domain    = amazon-helpmenow
        suffix    = com
        registered = amazon-helpmenow.com
    """
    try:
        if not url.startswith("http"):
            url = "http://" + url
        ext = tldextract.extract(url)
        return {
            "subdomain":  ext.subdomain.lower(),
            "domain":     ext.domain.lower(),
            "suffix":     ext.suffix.lower(),
            "registered": f"{ext.domain}.{ext.suffix}".lower(),
            "full":       f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".").lower(),
        }
    except Exception:
        return {
            "subdomain": "", "domain": "",
            "suffix": "", "registered": "", "full": "",
        }


def check_brand_impersonation(parts: dict) -> tuple[int, str]:
    """
    Detects fake domains impersonating real brands.

    Examples:
    amazon.com          → Safe   (real)
    amazon.in           → Safe   (real)
    amazon-helpmenow.com → SCAM  (fake, contains amazon)
    amazon-verify.tk    → SCAM  (fake + bad TLD)
    secure-amazon.com   → SCAM  (fake pattern)
    amaz0n.com          → SCAM  (lookalike)
    """
    domain_name = parts.get("domain", "").lower()
    suffix      = parts.get("suffix", "").lower()
    registered  = parts.get("registered", "").lower()
    subdomain   = parts.get("subdomain", "").lower()
    full        = parts.get("full", "").lower()

    for brand, real_domains in REAL_BRANDS.items():

        # Check if brand name appears ANYWHERE in domain
        brand_in_domain    = brand in domain_name
        brand_in_subdomain = brand in subdomain

        if not brand_in_domain and not brand_in_subdomain:
            continue

        # Is it exactly a real domain?
        is_real = (
            registered in real_domains
            or any(
                full == rd or full.endswith("." + rd)
                for rd in real_domains
            )
        )

        if is_real:
            return 0, ""  # Legitimate domain

        # ── It contains brand name but is NOT real → FAKE ─────────────────

        # Extra suspicion if domain has hyphens around brand
        has_hyphen = "-" in domain_name
        extra = 15 if has_hyphen else 0

        # Extra suspicion if suspicious words in domain
        susp_words = [
            "help", "support", "verify", "secure", "update",
            "alert", "login", "account", "kyc", "claim",
            "refund", "now", "urgent", "suspend", "helpme",
        ]
        has_susp_word = any(w in domain_name for w in susp_words)
        extra += 20 if has_susp_word else 0

        score = min(75 + extra, 100)

        real_example = real_domains[0] if real_domains else f"{brand}.com"
        reason = (
            f"🚨 FAKE domain impersonating '{brand.upper()}' — "
            f"Real site: {real_example} | "
            f"This '{registered}' is NOT official"
        )
        return score, reason

    return 0, ""


def check_typosquat(domain_name: str) -> tuple[int, str]:
    """
    Detects typosquatting / lookalike characters.
    amaz0n → amazon
    paypa1 → paypal
    g00gle → google
    """
    lookalike_map = {
        "0": "o", "1": "i", "1": "l",
        "3": "e", "4": "a", "5": "s",
        "6": "g", "7": "t", "8": "b",
    }

    # Replace lookalike chars and check against brands
    normalized = domain_name
    for num, letter in lookalike_map.items():
        normalized = normalized.replace(num, letter)

    # If normalized version matches a brand but original doesn't
    for brand in REAL_BRANDS.keys():
        if brand in normalized and brand not in domain_name:
            return 80, (
                f"👁️ Typosquat detected: '{domain_name}' "
                f"looks like '{brand}' — classic scam trick"
            )

    return 0, ""


def check_domain(text: str) -> tuple[int, list[str], bool]:
    """
    Master domain checker.

    Returns:
        score      (int 0-100)
        reasons    (list of strings)
        is_trusted (bool)
    """
    score, reasons = 0, []
    urls = extract_urls(text)

    if not urls:
        return 0, [], False

    is_trusted = False

    for url in urls:
        parts      = extract_full_domain_parts(url)
        domain     = parts.get("registered", "")
        domain_raw = parts.get("domain", "")
        suffix     = parts.get("suffix", "")

        if not domain:
            continue

        # ── 1. Trusted domain check ───────────────────────────────────────
        # Check EXACT match only (not substring)
        for td in TRUSTED_LIST:
            if domain == td or domain.endswith("." + td):
                is_trusted = True
                break

        # ── 2. Brand impersonation (HIGHEST PRIORITY) ─────────────────────
        imp_score, imp_reason = check_brand_impersonation(parts)
        if imp_score > 0:
            score     += imp_score
            reasons.append(imp_reason)
            is_trusted = False  # Override — fake is NEVER trusted

        # ── 3. Typosquat check ────────────────────────────────────────────
        typo_score, typo_reason = check_typosquat(domain_raw)
        if typo_score > 0:
            score     += typo_score
            reasons.append(typo_reason)
            is_trusted = False

        # ── 4. Short link ─────────────────────────────────────────────────
        for short in SHORT_LINK_DOMAINS:
            if short in domain:
                score += 30
                reasons.append(
                    f"🔗 Short/masked link ({short}) hides real URL")
                break

        # ── 5. Suspicious TLD ─────────────────────────────────────────────
        if suffix in SUSPICIOUS_TLDS:
            score += 35
            reasons.append(
                f"⚠️ Suspicious domain extension (.{suffix}) "
                f"commonly used in scams")

        # ── 6. Suspicious words in domain ─────────────────────────────────
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in domain_raw:
                score += 20
                reasons.append(
                    f"🔴 Suspicious word in domain: '{word}'")
                break

        # ── 7. Multiple hyphens ───────────────────────────────────────────
        if domain_raw.count("-") >= 2:
            score += 20
            reasons.append(
                f"➖ Multiple hyphens in domain — suspicious pattern")
        elif domain_raw.count("-") == 1 and imp_score == 0:
            # Single hyphen with brand name = likely scam
            for brand in REAL_BRANDS.keys():
                if brand in domain_raw:
                    score += 25
                    reasons.append(
                        f"➖ Hyphenated brand name '{domain_raw}' "
                        f"— classic phishing trick")
                    break

        # ── 8. Long domain ────────────────────────────────────────────────
        if len(domain) > 25:
            score += 15
            reasons.append(
                f"📏 Unusually long domain ({domain})")

        # ── 9. Raw IP address ─────────────────────────────────────────────
        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            score += 50
            reasons.append(
                "🌐 Raw IP address used instead of domain — very suspicious")

        # ── 10. Lookalike characters ──────────────────────────────────────
        lookalikes = {
            "0": "o", "1": "i", "3": "e",
            "4": "a", "5": "s", "6": "g",
        }
        for num, letter in lookalikes.items():
            if num in domain_raw:
                score += 20
                reasons.append(
                    f"👁️ Lookalike character in domain "
                    f"('{num}' instead of '{letter}') — {domain}")
                break

    return min(score, 100), reasons, is_trusted