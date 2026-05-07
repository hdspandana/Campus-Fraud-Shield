# core/domain_checker.py
# ═════════════════════════════════════════════════════════════════
# Domain and URL Analysis Engine
# Extracts and analyzes domains/URLs from message text
# Detects brand impersonation, suspicious TLDs, shortlinks
# Uses tldextract for accurate domain parsing
# ═════════════════════════════════════════════════════════════════

import re
import tldextract
from typing import List, Dict, Any, Tuple

# ── Known Safe Domains (Whitelist) ───────────────────────────────
SAFE_DOMAINS = {
    # Internship / Job platforms
    "internshala.com", "naukri.com", "linkedin.com",
    "letsintern.com", "unstop.com", "hackerearth.com",
    "foundit.in", "monsterindia.com", "apna.co",
    "freshersworld.com", "shine.com", "timesjobs.com",

    # Scholarship portals
    "scholarships.gov.in", "ugc.ac.in", "aicte-india.org",
    "ksb.gov.in", "buddy4study.com",

    # Government portals
    "gov.in", "nic.in", "india.gov.in", "mygov.in",
    "digitalindia.gov.in", "isro.gov.in", "drdo.gov.in",
    "uidai.gov.in", "epfindia.gov.in", "irctc.co.in",
    "incometax.gov.in", "nvsp.in", "sih.gov.in",
    "cbseresults.nic.in", "jeemain.nta.nic.in",
    "neet.nta.nic.in", "ugcnet.nta.nic.in",

    # Banks (official)
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com",
    "canarabank.in", "pnbindia.in", "bankofbaroda.in",

    # Payment apps (official)
    "paytm.com", "phonepe.com", "pay.google.com",
    "bhimupi.org.in",

    # Major companies
    "tcs.com", "infosys.com", "wipro.com",
    "cognizant.com", "accenture.com", "hcltech.com",
    "amazon.in", "amazon.com", "microsoft.com",
    "google.com", "apple.com", "meta.com",

    # Education
    "nptel.ac.in", "swayam.gov.in", "coursera.org",
    "edx.org", "udemy.com", "khanacademy.org",
    "education.github.com", "hackerrank.com",

    # Communication (safe)
    "teams.microsoft.com", "meet.google.com",
    "zoom.us", "webex.com",

    # Indian education
    "iitb.ac.in", "iitd.ac.in", "iitm.ac.in",
    "iitk.ac.in", "iisc.ac.in", "nit.ac.in",
    "aicte-india.org", "ugc.ac.in",
}

# ── Known Suspicious TLDs ─────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".click", ".loan", ".work", ".date",
    ".win", ".download", ".racing", ".review",
    ".stream", ".gdn", ".men", ".bid", ".trade",
}

# ── URL Shorteners (always suspicious in scam context) ───────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "dlvr.it", "ift.tt",
    "tiny.cc", "is.gd", "cli.gs", "pic.gd",
    "url4.eu", "tr.im", "twurl.nl", "snipurl.com",
    "short.to", "bkite.com", "snipr.com", "flic.kr",
}

# ── Brand Impersonation Patterns ──────────────────────────────────
# Format: (suspicious_domain_pattern, real_domain, brand_name)
IMPERSONATION_PATTERNS = [
    # Internshala variants
    (r"internshala\.(co|net|org|in|info|xyz|tk)", "internshala.com", "Internshala"),
    (r"internshala[0-9]", "internshala.com", "Internshala"),
    (r"internshala[-_]", "internshala.com", "Internshala"),

    # NSP variants
    (r"nsp[-_]scholarship", "scholarships.gov.in", "NSP"),
    (r"nationalscholarship\.(co|net|in|org)", "scholarships.gov.in", "NSP"),

    # Bank variants
    (r"sbi[-_.]?(bank|online|kyc|login)", "sbi.co.in", "SBI"),
    (r"hdfc[-_.]?(bank|online|kyc|login|secure)", "hdfcbank.com", "HDFC"),
    (r"icici[-_.]?(bank|online|kyc|login)", "icicibank.com", "ICICI"),
    (r"paytm[-_.]?(kyc|bank|wallet|secure)", "paytm.com", "Paytm"),

    # Government variants
    (r"india[-_.]?gov\.(co|net|org|in\.com)", "india.gov.in", "Government of India"),
    (r"pm[-_]?(scholarship|yojana)[-_.]?(gov|official)", "scholarships.gov.in", "PM Scholarship"),

    # Company variants
    (r"tcs[-_.]?(career|hire|job|recruit)", "tcs.com", "TCS"),
    (r"infosys[-_.]?(career|hire|job|recruit)", "infosys.com", "Infosys"),
    (r"wipro[-_.]?(career|hire|job|recruit)", "wipro.com", "Wipro"),
    (r"amazon[-_.]?(job|hire|wfh|work)", "amazon.in", "Amazon"),

    # KBC / lottery variants
    (r"kbc[-_.]?(winner|prize|claim|lucky)", None, "KBC (Fake)"),
    (r"lucky[-_.]?(draw|winner|prize)", None, "Lucky Draw (Fake)"),
]

# ── Gmail Red Flags ───────────────────────────────────────────────
# These phrases + gmail.com = strong scam signal
GMAIL_RED_FLAG_PATTERNS = [
    r"(internshala|tcs|infosys|wipro|cognizant|accenture|"
    r"hcl|amazon|google|microsoft|nsp|scholarship|"
    r"sbi|hdfc|icici|axis|paytm|phonepe|"
    r"govt|government|pm|ministry).{0,30}@gmail\.com",
]


# ── Main Engine Class ─────────────────────────────────────────────
class DomainChecker:
    """
    Domain and URL analysis engine.
    Extracts URLs/emails from text and checks for:
    - Known suspicious domains
    - Brand impersonation
    - URL shorteners
    - Gmail used instead of official email
    - Suspicious TLDs
    """

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze all URLs and email domains in the text.

        Args:
            text: Message text to analyze

        Returns:
            dict with keys: score, reasons, domains
        """
        reasons = []
        score   = 0.0

        # Extract all URLs and emails
        urls    = self._extract_urls(text)
        emails  = self._extract_emails(text)
        domains = self._get_domains(urls + emails)

        # ── Check each domain ─────────────────────────────────
        for domain in domains:
            domain_score, domain_reasons = self._check_domain(
                domain, text
            )
            score   += domain_score
            reasons.extend(domain_reasons)

        # ── Check for Gmail red flags ─────────────────────────
        gmail_score, gmail_reasons = self._check_gmail_redflag(text)
        score   += gmail_score
        reasons.extend(gmail_reasons)

        # ── Check for brand impersonation in full text ────────
        imp_score, imp_reasons = self._check_impersonation(text)
        score   += imp_score
        reasons.extend(imp_reasons)

        # ── Cap score ─────────────────────────────────────────
        score = max(0.0, min(100.0, score))

        # ── Deduplicate reasons ───────────────────────────────
        reasons = list(dict.fromkeys(reasons))[:5]

        return {
            "score":   score,
            "reasons": reasons,
            "domains": domains
        }

    def _extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text."""
        patterns = [
            r"https?://[^\s<>\"]+",
            r"www\.[^\s<>\"]+",
            r"[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\."
            r"(?:com|in|org|net|gov|co\.in|ac\.in)[^\s]*",
        ]
        urls = []
        for pattern in patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(found)
        return list(set(urls))

    def _extract_emails(self, text: str) -> List[str]:
        """Extract all email addresses from text."""
        pattern = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        return re.findall(pattern, text, re.IGNORECASE)

    def _get_domains(self, items: List[str]) -> List[str]:
        """
        Extract clean domain names from URLs and emails.

        Args:
            items: List of URLs or email addresses

        Returns:
            List of clean domain strings
        """
        domains = []
        for item in items:
            try:
                extracted = tldextract.extract(item)
                if extracted.domain and extracted.suffix:
                    full_domain = (
                        f"{extracted.domain}.{extracted.suffix}"
                    )
                    domains.append(full_domain)
            except Exception:
                pass
        return list(set(domains))

    def _check_domain(
        self,
        domain: str,
        text: str
    ) -> Tuple[float, List[str]]:
        """
        Check a single domain for suspicious signals.

        Args:
            domain: Domain string e.g. 'internshala.com'
            text: Full original text for context

        Returns:
            tuple: (score_addition, list of reasons)
        """
        score   = 0.0
        reasons = []

        # Check if domain is in safe whitelist
        if domain in SAFE_DOMAINS:
            score -= 20
            return score, reasons

        # Check for URL shortener
        if domain in URL_SHORTENERS:
            score   += 30
            reasons.append(
                f"Suspicious shortened URL ({domain}) hides real destination"
            )

        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score   += 35
                reasons.append(
                    f"Suspicious domain extension ({tld}) — "
                    f"commonly used in scam websites"
                )
                break

        # Check for Gmail/Yahoo/Hotmail used as official contact
        if domain in {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}:
            score   += 25
            reasons.append(
                f"Personal email ({domain}) used instead of "
                f"official company email"
            )

        # Check for numeric characters in domain (suspicious)
        extracted = tldextract.extract(domain)
        if re.search(r"\d{4,}", extracted.domain):
            score   += 15
            reasons.append(
                f"Domain contains suspicious numbers ({domain})"
            )

        # Check for hyphenated impersonation
        if re.search(
            r"(bank|kyc|secure|login|verify|official|govt|"
            r"scholarship|internship|prize|winner)",
            extracted.domain,
            re.IGNORECASE
        ):
            score   += 20
            reasons.append(
                f"Domain name contains suspicious keywords ({domain})"
            )

        return score, reasons

    def _check_gmail_redflag(
        self,
        text: str
    ) -> Tuple[float, List[str]]:
        """
        Check if trusted brand name is paired with Gmail.
        e.g. 'Contact internshala team at internshala@gmail.com'

        Returns:
            tuple: (score, reasons)
        """
        score   = 0.0
        reasons = []

        for pattern in GMAIL_RED_FLAG_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_text = match.group()
                # Extract brand name
                brand_match = re.match(
                    r"([a-zA-Z]+)", matched_text, re.IGNORECASE
                )
                brand = brand_match.group(1).title() if brand_match else "Company"
                score   += 45
                reasons.append(
                    f"Real {brand} never uses Gmail — "
                    f"official email must end in @{brand.lower()}.com"
                )
                break

        return score, reasons

    def _check_impersonation(
        self,
        text: str
    ) -> Tuple[float, List[str]]:
        """
        Check for brand impersonation in URLs within text.

        Returns:
            tuple: (score, reasons)
        """
        score   = 0.0
        reasons = []

        urls = self._extract_urls(text)

        for url in urls:
            for pattern, real_domain, brand in IMPERSONATION_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    score += 50
                    if real_domain:
                        reasons.append(
                            f"Fake {brand} website detected — "
                            f"real site is {real_domain}"
                        )
                    else:
                        reasons.append(
                            f"Suspicious {brand} link detected — "
                            f"known scam pattern"
                        )
                    break

        return score, reasons

    def is_safe_domain(self, domain: str) -> bool:
        """
        Check if a domain is in the safe whitelist.

        Args:
            domain: Domain string

        Returns:
            True if safe, False otherwise
        """
        return domain in SAFE_DOMAINS

    def get_domain_info(self, text: str) -> Dict[str, Any]:
        """
        Get detailed domain info for 'Why This Score' panel.

        Args:
            text: Message text

        Returns:
            dict with urls, emails, domains, safe_domains, suspicious_domains
        """
        urls    = self._extract_urls(text)
        emails  = self._extract_emails(text)
        domains = self._get_domains(urls + emails)

        safe_domains       = [d for d in domains if d in SAFE_DOMAINS]
        suspicious_domains = [d for d in domains if d not in SAFE_DOMAINS]

        return {
            "urls":               urls[:5],
            "emails":             emails[:5],
            "domains":            domains,
            "safe_domains":       safe_domains,
            "suspicious_domains": suspicious_domains
        }


# ── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    checker = DomainChecker()

    tests = [
        (
            "Pay fee at internshala.co and contact "
            "internshala@gmail.com for details.",
            "SCAM — Fake Internshala domain + Gmail"
        ),
        (
            "Visit bit.ly/internship2024 to confirm "
            "your registration and pay fee.",
            "SCAM — Shortlink"
        ),
        (
            "Check your application at internshala.com "
            "Login with your registered email.",
            "SAFE — Real domain"
        ),
        (
            "SBI account KYC update at sbi-kyc-secure.xyz "
            "Enter OTP to verify your account.",
            "SCAM — Suspicious TLD + keywords"
        ),
        (
            "Contact TCS HR at tcs@gmail.com "
            "for your joining documents.",
            "SCAM — Company using Gmail"
        ),
        (
            "Interview link: meet.google.com/abc-xyz "
            "Join at 3PM. Offer letter from hr@tcs.com",
            "SAFE — Google Meet + official TCS email"
        ),
    ]

    print("Domain Checker Test Results:")
    print("=" * 60)

    for text, expected in tests:
        result  = checker.analyze(text)
        label   = (
            "SCAM"       if result["score"] >= 70
            else "SUSPICIOUS" if result["score"] >= 40
            else "SAFE"
        )
        print(f"\nText:     {text[:65]}...")
        print(f"Expected: {expected}")
        print(f"Score:    {result['score']:.1f}/100 → {label}")
        print(f"Domains:  {result['domains']}")
        print(f"Reasons:  {result['reasons']}")