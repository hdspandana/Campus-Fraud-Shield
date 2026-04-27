import re
import urllib.parse

# ── Suspicious TLDs (top level domains) ──────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free domains used by scammers
    ".xyz", ".top", ".click", ".loan",
    ".win", ".racing", ".download",
    ".stream", ".trade", ".review",
]

# ── Suspicious words inside domains ──────────────────────────────────────────
SUSPICIOUS_DOMAIN_WORDS = [
    "free", "earn", "prize", "win", "reward",
    "claim", "lucky", "bonus", "offer",
    "verify", "secure", "update", "login",
    "account", "bank", "payment", "money",
    "job", "internship", "hiring", "work",
    "limited", "urgent", "confirm",
]

# ── Known short link services ─────────────────────────────────────────────────
SHORT_LINK_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "rb.gy", "cutt.ly", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "ift.tt",
]


def extract_urls(text: str) -> list[str]:
    """Extract all URLs from a block of text"""
    url_pattern = re.compile(
        r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/[^\s]*)',
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def extract_domain(url: str) -> str:
    """Pull the domain out of a URL cleanly"""
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www.
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def check_domain(text: str) -> tuple[int, list[str]]:
    """
    Main function — extract URLs, analyze domains
    Returns (score, reasons)
    """
    score = 0
    reasons = []
    urls = extract_urls(text)

    if not urls:
        return 0, []

    for url in urls:
        domain = extract_domain(url)
        if not domain:
            continue

        # Check 1: Short link
        for short in SHORT_LINK_DOMAINS:
            if short in domain:
                score += 30
                reasons.append(f"Short/masked link detected ({short}) — hides real destination")
                break

        # Check 2: Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 35
                reasons.append(f"Suspicious domain extension ({tld}) — commonly used in scams")
                break

        # Check 3: Suspicious words in domain
        for word in SUSPICIOUS_DOMAIN_WORDS:
            if word in domain:
                score += 20
                reasons.append(f'Suspicious word in domain: "{word}" → {domain}')
                break

        # Check 4: Very long domain (scammers use long domains to look legit)
        if len(domain) > 30:
            score += 15
            reasons.append(f"Unusually long domain name ({domain}) — common scam tactic")

        # Check 5: Lots of hyphens (e.g. free-prize-claim-now.com)
        if domain.count("-") >= 2:
            score += 15
            reasons.append(f"Multiple hyphens in domain ({domain}) — suspicious pattern")

        # Check 6: IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score += 40
            reasons.append("Link uses raw IP address instead of domain — very suspicious")

    return min(score, 100), reasons