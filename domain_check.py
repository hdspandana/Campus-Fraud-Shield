import re
import urllib.parse
 
# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".loan",
    ".win", ".racing", ".download",
    ".stream", ".trade", ".review",
    ".buzz", ".gdn", ".men", ".work",
]
 
# ── Suspicious words inside domains ──────────────────────────────────────────
SUSPICIOUS_DOMAIN_WORDS = [
    "free", "earn", "prize", "win", "reward",
    "claim", "lucky", "bonus", "offer",
    "verify", "secure", "update", "login",
    "account", "bank", "payment", "money",
    "job", "internship", "hiring", "work",
    "limited", "urgent", "confirm",
    "helpme", "help-me", "support",
    "refund", "cashback", "recover",
]
 
# ── Known short link services ─────────────────────────────────────────────────
SHORT_LINK_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "rb.gy", "cutt.ly", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "ift.tt",
]
 
# ── Big brands scammers commonly impersonate ──────────────────────────────────
# Format: (real_domain, keywords_scammers_add_around_it)
BRAND_IMPERSONATION = [
    ("amazon",    ["amazon-help", "amazon-support", "amazon-refund", "amazon-verify",
                   "amazon-helpme", "amazon-claim", "amazon-secure", "amazon-update",
                   "helpmeamazon", "myamazon", "amazon-now", "amazon-alert"]),
    ("google",    ["google-verify", "google-secure", "google-update", "google-alert",
                   "google-support", "googlesupport", "google-claim"]),
    ("sbi",       ["sbi-secure", "sbi-verify", "sbi-update", "sbi-kyc",
                   "sbionline", "sbibank-verify"]),
    ("hdfc",      ["hdfc-kyc", "hdfc-verify", "hdfc-secure", "hdfc-update"]),
    ("paytm",     ["paytm-verify", "paytm-secure", "paytm-refund"]),
    ("flipkart",  ["flipkart-help", "flipkart-verify", "flipkart-refund"]),
    ("whatsapp",  ["whatsapp-verify", "whatsapp-secure"]),
    ("microsoft", ["microsoft-verify", "microsoft-alert", "microsoft-support"]),
    ("apple",     ["apple-verify", "apple-support", "apple-id-verify"]),
    ("nptel",     ["nptel-verify", "nptel-certificate"]),
]
 
 
def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(
        r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/[^\s]*)',
        re.IGNORECASE
    )
    return url_pattern.findall(text)
 
 
def extract_domain(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""
 
 
def check_brand_impersonation(domain: str) -> tuple[int, str]:
    """
    Detect fake domains impersonating real brands.
    e.g. amazon-helpmenow.com → fake Amazon
    """
    domain_lower = domain.lower()
 
    for brand, fake_patterns in BRAND_IMPERSONATION:
        # Check if brand name appears in domain
        if brand in domain_lower:
            # But is it the REAL domain?
            real_domains = {
                "amazon":    ["amazon.com", "amazon.in"],
                "google":    ["google.com", "google.co.in"],
                "sbi":       ["onlinesbi.sbi", "sbi.co.in"],
                "hdfc":      ["hdfcbank.com"],
                "paytm":     ["paytm.com"],
                "flipkart":  ["flipkart.com"],
                "whatsapp":  ["whatsapp.com"],
                "microsoft": ["microsoft.com"],
                "apple":     ["apple.com"],
                "nptel":     ["nptel.ac.in"],
            }
            real = real_domains.get(brand, [])
 
            # If it's not the real domain but contains the brand name → FAKE
            if not any(domain_lower == rd or domain_lower.endswith("." + rd) for rd in real):
                return 60, (
                    f"⚠️ FAKE domain impersonating '{brand.upper()}' — "
                    f"Real site: {real[0] if real else brand + '.com'} | "
                    f"This is: {domain}"
                )
 
            # Check explicit fake patterns
            for pattern in fake_patterns:
                if pattern in domain_lower:
                    return 70, (
                        f"🚨 Known fake pattern '{pattern}' detected — "
                        f"impersonating {brand.upper()}"
                    )
 
    return 0, ""
 
 
def check_domain(text: str) -> tuple[int, list[str]]:
    score   = 0
    reasons = []
    urls    = extract_urls(text)
 
    if not urls:
        return 0, []
 
    for url in urls:
        domain = extract_domain(url)
        if not domain:
            continue
 
        # ── Check 1: Brand impersonation (HIGHEST PRIORITY) ───────────────────
        imp_score, imp_reason = check_brand_impersonation(domain)
        if imp_score > 0:
            score  += imp_score
            reasons.append(imp_reason)
 
        # ── Check 2: Short links ──────────────────────────────────────────────
        for short in SHORT_LINK_DOMAINS:
            if short in domain:
                score  += 30
                reasons.append(f"Short/masked link ({short}) — hides real destination")
                break
 
        # ── Check 3: Suspicious TLD ───────────────────────────────────────────
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score  += 35
                reasons.append(f"Suspicious domain extension ({tld}) — used in scams")
                break
 
        # ── Check 4: Suspicious words in domain ───────────────────────────────
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in domain:
                score  += 20
                reasons.append(f'Suspicious word in domain: "{word}" → {domain}')
                break
 
        # ── Check 5: Long domain ──────────────────────────────────────────────
        if len(domain) > 25:
            score  += 20
            reasons.append(f"Unusually long domain ({domain}) — common scam tactic")
 
        # ── Check 6: Multiple hyphens ─────────────────────────────────────────
        if domain.count("-") >= 2:
            score  += 20
            reasons.append(f"Multiple hyphens in domain ({domain}) — suspicious pattern")
 
        # ── Check 7: Raw IP address ───────────────────────────────────────────
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score  += 50
            reasons.append("Raw IP address used instead of domain — very suspicious")
 
        # ── Check 8: Lookalike characters (paypa1, amaz0n) ───────────────────
        lookalikes = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s"}
        domain_check = domain.split(".")[0]
        for num, letter in lookalikes.items():
            if num in domain_check:
                score  += 15
                reasons.append(f"Lookalike character in domain ({domain}) — e.g. '0' instead of 'o'")
                break
 
    return min(score, 100), reasons