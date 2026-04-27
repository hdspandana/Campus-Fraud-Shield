TRUSTED_DOMAINS = [
    "internshala.com",
    "linkedin.com",
    "naukri.com",
    "unstop.com",
    "dare2compete.com",
    "nptel.ac.in",
    "swayam.gov.in",
    "gov.in",
    "nic.in",
    "collegedunia.com",
    "shiksha.com",
    "glassdoor.com",
    "indeed.com",
    "github.com",
    "stackoverflow.com",
    "google.com",
    "youtube.com",
    "microsoft.com",
    "amazon.in",
    "flipkart.com",
]

TRUSTED_KEYWORDS = [
    "internshala",
    "linkedin",
    "unstop",
    "nptel",
    "swayam",
    "naukri",
]

def check_trusted(text: str) -> tuple[bool, str]:
    """
    Returns (is_trusted, reason)
    If message contains a known trusted domain → flag it
    """
    text_lower = text.lower()

    for domain in TRUSTED_DOMAINS:
        if domain in text_lower:
            return True, f"Contains verified campus platform: {domain}"

    for keyword in TRUSTED_KEYWORDS:
        if keyword in text_lower:
            return True, f"References trusted platform: {keyword}"

    return False, ""