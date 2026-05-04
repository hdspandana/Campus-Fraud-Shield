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
def extract_urls(text: str) -> list[str]:
    pattern = re.compile(
        r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/[^\s]*)",
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