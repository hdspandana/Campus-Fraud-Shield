# core/preprocessor.py
import re
import tldextract


# ─── Emoji & noise removal ────────────────────────────────────────────────────
def remove_noise(text: str) -> str:
    emoji_pattern = re.compile(
        "["
        u"\U0001F600-\U0001F64F"
        u"\U0001F300-\U0001F5FF"
        u"\U0001F680-\U0001F9FF"
        u"\U00002700-\U000027BF"
        "]+",
        flags=re.UNICODE,
    )
    text = emoji_pattern.sub(" ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ─── URL extraction ───────────────────────────────────────────────────────────
# BUG FIX: the original pattern's third alternative required a trailing
# "/" after the domain to count as a match at all — meaning bare domain
# mentions with no path ("Register at internhub-careers.com within 24
# hours", "Visit fake-portal.in to claim") were invisible to the entire
# domain-analysis pipeline (zero URLs extracted -> zero domains -> local
# heuristics AND live threat-intel both silently skipped). This is
# extremely common real scam phrasing, not an edge case.
#
# Fixed by requiring a recognizable TLD instead of a trailing path —
# this catches bare-domain mentions while avoiding the opposite risk of
# matching ordinary sentence punctuation as if it were a domain (e.g.
# "v2.0", "St. Xavier's", "no.1 choice"). Path after the domain, if
# present, is still captured optionally.
# NOTE: includes common URL-shortener TLDs (.ly for bit.ly/cutt.ly/ow.ly,
# .gl for goo.gl, .gd for is.gd) — URL shorteners are one of the most
# common real scam-link patterns and were previously covered by luck
# (the old regex's generic [a-zA-Z]{2,} matched anything), so this list
# needs to explicitly include them or shortener links silently regress.
_KNOWN_TLDS = (
    r"com|in|net|org|co|io|xyz|info|biz|gov|edu|me|app|online|site|"
    r"tech|store|club|top|win|link|click|tk|ml|ga|cf|us|uk|ac\.in|"
    r"co\.in|gov\.in|edu\.in|nic\.in|org\.in|res\.in|"
    r"ly|gl|gd|to|cc|sh|be|gg|so"
)

def extract_urls(text: str) -> list[str]:
    pattern = re.compile(
        r"(https?://[^\s]+|www\.[^\s]+|"
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
        rf"\.(?:{_KNOWN_TLDS})(?:/[^\s]*)?\b)",
        re.IGNORECASE,
    )
    return pattern.findall(text)


# ─── Domain extraction ────────────────────────────────────────────────────────
def extract_domain(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return ""
    except Exception:
        return ""


# ─── Registered domain (with subdomain stripped) ─────────────────────────────
def extract_full_domain_parts(url: str) -> dict:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        ext = tldextract.extract(url)
        return {
            "subdomain": ext.subdomain,
            "domain":    ext.domain,
            "suffix":    ext.suffix,
            "registered": f"{ext.domain}.{ext.suffix}".lower(),
            "full":       f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".").lower(),
        }
    except Exception:
        return {"subdomain": "", "domain": "", "suffix": "",
                "registered": "", "full": ""}


# ─── Normalize text for ML ────────────────────────────────────────────────────
def normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^\w\s₹@./:-]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ─── Master preprocessor ─────────────────────────────────────────────────────
def preprocess(raw_text: str) -> dict:
    cleaned   = remove_noise(raw_text)
    urls      = extract_urls(raw_text)
    domains   = [extract_domain(u) for u in urls]
    normalized = normalize(cleaned)

    return {
        "original":   raw_text,
        "cleaned":    cleaned,
        "normalized": normalized,
        "urls":       urls,
        "domains":    [d for d in domains if d],
    }