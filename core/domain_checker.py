# core/domain_checker.py
# ═════════════════════════════════════════════════════════════════
# Domain and URL Analysis Engine — Maximum Security Version
# Detects: Typosquats, Fake Portals, Suspicious TLDs,
#          Brand Impersonation, Phishing Paths, HTTP-only links
# ═════════════════════════════════════════════════════════════════

import re
import tldextract
from typing import List, Dict, Any, Tuple

# ── Safe Domains Whitelist ────────────────────────────────────────
SAFE_DOMAINS = {
    "internshala.com", "naukri.com", "linkedin.com",
    "letsintern.com", "unstop.com", "hackerearth.com",
    "foundit.in", "monsterindia.com", "apna.co",
    "scholarships.gov.in", "ugc.ac.in", "aicte-india.org",
    "ksb.gov.in", "buddy4study.com",
    "gov.in", "nic.in", "india.gov.in", "mygov.in",
    "digitalindia.gov.in", "isro.gov.in", "drdo.gov.in",
    "uidai.gov.in", "epfindia.gov.in", "irctc.co.in",
    "incometax.gov.in", "nvsp.in", "sih.gov.in",
    "cbseresults.nic.in", "jeemain.nta.nic.in",
    "neet.nta.nic.in", "ugcnet.nta.nic.in",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com",
    "canarabank.in", "pnbindia.in", "bankofbaroda.in",
    "paytm.com", "phonepe.com", "pay.google.com",
    "bhimupi.org.in",
    "tcs.com", "infosys.com", "wipro.com",
    "cognizant.com", "accenture.com", "hcltech.com",
    "amazon.in", "amazon.com", "microsoft.com",
    "google.com", "apple.com", "meta.com",
    "nptel.ac.in", "swayam.gov.in", "coursera.org",
    "edx.org", "udemy.com", "khanacademy.org",
    "hackerrank.com", "github.com", "stackoverflow.com",
    "teams.microsoft.com", "meet.google.com",
    "zoom.us", "webex.com",
}

# ── Malicious TLDs ────────────────────────────────────────────────
MALICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq",
    "top", "click", "loan", "work", "date",
    "win", "download", "racing", "review",
    "stream", "gdn", "men", "bid", "trade",
    "site", "online", "cloud", "link", "live",
    "fun", "space", "icu", "vip", "monster",
}

# ── URL Shorteners ────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "dlvr.it", "short.to",
    "tiny.cc", "is.gd", "cli.gs", "snipurl.com",
    "rb.gy", "cutt.ly", "shorturl.at",
}

# ── Phishing Paths ────────────────────────────────────────────────
PHISHING_PATHS = [
    "/login", "/auth", "/signin", "/verify",
    "/account", "/update", "/security", "/payment",
    "/portal", "/support", "/alert", "/notice",
    "/otp", "/kyc", "/activate", "/confirm",
    "/claim", "/reward", "/prize", "/winner",
    "/recover", "/reset", "/unlock", "/validate",
]

# ── Known Brand Names for Impersonation Detection ─────────────────
BRAND_NAMES = {
    "google": "google.com",
    "amazon": "amazon.in",
    "flipkart": "flipkart.com",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "internshala": "internshala.com",
    "naukri": "naukri.com",
    "linkedin": "linkedin.com",
    "microsoft": "microsoft.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "twitter": "twitter.com",
    "nsp": "scholarships.gov.in",
    "irctc": "irctc.co.in",
    "uidai": "uidai.gov.in",
    "tcs": "tcs.com",
    "infosys": "infosys.com",
    "wipro": "wipro.com",
    "youtube": "youtube.com",
    "netflix": "netflix.com",
    "kbc": None,
    "jio": "jio.com",
    "airtel": "airtel.in",
    "bsnl": "bsnl.co.in",
}

# ── Character Substitution Map ────────────────────────────────────
# Used to normalize domains before comparison
CHAR_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i",
    "vv": "w", "rn": "m",
}


class DomainChecker:
    """
    Maximum security domain analysis engine.
    Catches typosquats, fake portals, phishing paths,
    brand impersonation, and suspicious TLDs.
    """

    def analyze(self, text: str) -> Dict[str, Any]:
        reasons = []
        score   = 0.0

        urls    = self._extract_urls(text)
        emails  = self._extract_emails(text)
        domains = self._get_domains(urls + emails)

        # ── Check 1: Domain-level checks ─────────────────────────
        for domain in domains:
            d_score, d_reasons = self._check_domain(domain, text)
            score   += d_score
            reasons.extend(d_reasons)

        # ── Check 2: Full URL path analysis ──────────────────────
        for url in urls:
            u_score, u_reasons = self._check_url_path(url)
            score   += u_score
            reasons.extend(u_reasons)

        # ── Check 3: HTTP (not HTTPS) detection ──────────────────
        h_score, h_reasons = self._check_http_only(text)
        score   += h_score
        reasons.extend(h_reasons)

        # ── Check 4: Brand impersonation in domain ────────────────
        for domain in domains:
            b_score, b_reasons = self._check_brand_impersonation(domain)
            score   += b_score
            reasons.extend(b_reasons)

        # ── Check 5: Typosquatting in full text ───────────────────
        t_score, t_reasons = self._detect_typosquat_in_text(text)
        score   += t_score
        reasons.extend(t_reasons)

        # ── Check 6: Gmail red flags ──────────────────────────────
        g_score, g_reasons = self._check_gmail_redflag(text)
        score   += g_score
        reasons.extend(g_reasons)

        # ── Check 7: Brand name in suspicious domain ──────────────
        for domain in domains:
            bs_score, bs_reasons = self._check_brand_in_suspicious_domain(domain)
            score   += bs_score
            reasons.extend(bs_reasons)

        score   = max(0.0, min(100.0, score))
        reasons = list(dict.fromkeys(reasons))[:5]

        return {
            "score":   score,
            "reasons": reasons,
            "domains": domains,
        }

    # ── URL/Email Extraction ──────────────────────────────────────
    def _extract_urls(self, text: str) -> List[str]:
        patterns = [
            r"https?://[^\s<>\"]+",
            r"www\.[^\s<>\"]+",
            r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]"
            r"\.(?:xyz|tk|ml|ga|cf|top|click|site|online|"
            r"live|fun|space|icu|vip|link|loan|win|cloud)"
            r"(?:/[^\s]*)?\b",
        ]
        urls = []
        for p in patterns:
            urls.extend(re.findall(p, text, re.IGNORECASE))
        return list(set(urls))

    def _extract_emails(self, text: str) -> List[str]:
        return re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            text, re.IGNORECASE
        )

    def _get_domains(self, items: List[str]) -> List[str]:
        domains = []
        for item in items:
            try:
                ext = tldextract.extract(item)
                if ext.domain and ext.suffix:
                    domains.append(f"{ext.domain}.{ext.suffix}")
                    if ext.subdomain:
                        domains.append(
                            f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
                        )
            except Exception:
                pass
        return list(set(domains))

    # ── Check 1: Domain-Level ─────────────────────────────────────
    def _check_domain(
        self, domain: str, text: str
    ) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []
        ext     = tldextract.extract(domain)
        suffix  = ext.suffix.lower()

        # Whitelisted domain
        if domain in SAFE_DOMAINS:
            score -= 15
            return score, reasons

        # Malicious TLD
        if suffix in MALICIOUS_TLDS:
            score   += 45
            reasons.append(
                f"Malicious domain extension (.{suffix}) — "
                f"used in 90%+ of phishing attacks"
            )

        # URL shortener
        if domain in URL_SHORTENERS:
            score   += 30
            reasons.append(
                f"URL shortener ({domain}) hides real destination"
            )

        # Personal email provider used officially
        if domain in {
            "gmail.com", "yahoo.com",
            "hotmail.com", "outlook.com"
        }:
            score   += 20
            reasons.append(
                f"Personal email ({domain}) used instead of official domain"
            )

        # Numeric characters in domain name
        if re.search(r"\d{3,}", ext.domain):
            score   += 15
            reasons.append(
                f"Suspicious numbers in domain ({domain})"
            )

        # Hyphen-rich domain (common in phishing)
        if ext.domain.count("-") >= 2:
            score   += 20
            reasons.append(
                f"Multiple hyphens in domain ({domain}) — "
                f"common phishing pattern"
            )

        return score, reasons

    # ── Check 2: URL Path Analysis ────────────────────────────────
    def _check_url_path(self, url: str) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        url_lower = url.lower()
        ext       = tldextract.extract(url)
        domain    = f"{ext.domain}.{ext.suffix}"

        # Phishing path on non-whitelisted domain
        if domain not in SAFE_DOMAINS:
            for path in PHISHING_PATHS:
                if path in url_lower:
                    score   += 35
                    reasons.append(
                        f"Phishing path '{path}' on unverified domain — "
                        f"classic credential theft pattern"
                    )
                    break

        # Multiple phishing paths
        matched_paths = [p for p in PHISHING_PATHS if p in url_lower]
        if len(matched_paths) >= 2:
            score   += 20
            reasons.append(
                f"Multiple sensitive paths in URL: "
                f"{', '.join(matched_paths[:3])}"
            )

        return score, reasons

    # ── Check 3: HTTP Only ────────────────────────────────────────
    def _check_http_only(self, text: str) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        http_urls  = re.findall(r"http://[^\s]+", text, re.IGNORECASE)
        https_urls = re.findall(r"https://[^\s]+", text, re.IGNORECASE)

        for url in http_urls:
            ext    = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"
            if domain not in SAFE_DOMAINS:
                score   += 25
                reasons.append(
                    f"Insecure HTTP link detected ({domain}) — "
                    f"legitimate sites use HTTPS"
                )
                break

        return score, reasons

    # ── Check 4: Brand Impersonation ─────────────────────────────
    def _check_brand_impersonation(
        self, domain: str
    ) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        if domain in SAFE_DOMAINS:
            return score, reasons

        # Normalize domain for comparison
        normalized = self._normalize_domain(domain)
        ext        = tldextract.extract(domain)

        for brand, real_domain in BRAND_NAMES.items():
            if brand in normalized and domain != real_domain:
                score   += 50
                reasons.append(
                    f"Brand impersonation: '{domain}' pretends to be "
                    f"'{real_domain or brand}'"
                )
                break

        return score, reasons

    # ── Check 5: Typosquat in Text ────────────────────────────────
    def _detect_typosquat_in_text(
        self, text: str
    ) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        # Extract anything that looks like a domain from text
        candidates = re.findall(
            r"\b([a-zA-Z0-9@$!][a-zA-Z0-9\-@$!0-9]{2,}"
            r"\.[a-zA-Z]{2,})\b",
            text, re.IGNORECASE
        )

        for candidate in candidates:
            normalized = self._normalize_domain(candidate.lower())

            for brand in BRAND_NAMES:
                # Skip exact matches (real domain)
                if candidate.lower() == f"{brand}.com":
                    continue

                # Check edit distance
                dist = self._levenshtein(normalized, brand)

                if 0 < dist <= 2 and len(brand) > 3:
                    score   += 55
                    reasons.append(
                        f"Typosquatting detected: '{candidate}' looks like "
                        f"'{brand}.com' ({dist} char difference). "
                        f"Likely fake site impersonating "
                        f"{brand.title()}."
                    )
                    break

        return score, reasons

    # ── Check 6: Gmail Red Flag ───────────────────────────────────
    def _check_gmail_redflag(
        self, text: str
    ) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        pattern = (
            r"(internshala|tcs|infosys|wipro|cognizant|accenture|"
            r"hcl|amazon|google|microsoft|nsp|scholarship|"
            r"sbi|hdfc|icici|axis|paytm|phonepe|"
            r"govt|government|pm|ministry|university|college)"
            r".{0,30}@gmail\.com"
        )
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            brand = match.group(1).title()
            score   += 45
            reasons.append(
                f"Real {brand} never uses Gmail — "
                f"official email must end in @{brand.lower()}.com"
            )

        return score, reasons

    # ── Check 7: Brand Name in Suspicious Domain ──────────────────
    def _check_brand_in_suspicious_domain(
        self, domain: str
    ) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        if domain in SAFE_DOMAINS:
            return score, reasons

        ext    = tldextract.extract(domain)
        suffix = ext.suffix.lower()
        name   = (ext.subdomain + "." + ext.domain).lower()

        for brand in BRAND_NAMES:
            if brand in name and suffix in MALICIOUS_TLDS:
                score   += 60
                reasons.append(
                    f"Brand '{brand}' used inside malicious domain "
                    f"'{domain}' — classic phishing technique"
                )
                break
            elif brand in name and suffix not in {"com", "in", "org", "net", "gov"}:
                score   += 40
                reasons.append(
                    f"Brand name '{brand}' in suspicious domain "
                    f"'{domain}'"
                )
                break

        return score, reasons

    # ── Helpers ───────────────────────────────────────────────────
    def _normalize_domain(self, domain: str) -> str:
        """Replace look-alike characters with real letters."""
        result = domain.lower()
        for fake, real in CHAR_SUBSTITUTIONS.items():
            result = result.replace(fake, real)
        return result

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions  = prev_row[j + 1] + 1
                deletions   = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    def is_safe_domain(self, domain: str) -> bool:
        return domain in SAFE_DOMAINS

    def get_domain_info(self, text: str) -> Dict[str, Any]:
        urls    = self._extract_urls(text)
        emails  = self._extract_emails(text)
        domains = self._get_domains(urls + emails)
        return {
            "urls":               urls[:5],
            "emails":             emails[:5],
            "domains":            domains,
            "safe_domains":       [d for d in domains if d in SAFE_DOMAINS],
            "suspicious_domains": [d for d in domains if d not in SAFE_DOMAINS],
        }


if __name__ == "__main__":
    checker = DomainChecker()
    tests = [
        "http://university-portal-login.xyz/auth",
        "gooogle.com",
        "g00gle.com share your OTP",
        "amaz0n-winner.xyz claim your prize",
        "pay fee at internshala-fee.xyz",
        "https://internshala.com/jobs",
        "login to sbi-secure-kyc.tk immediately",
        "facebo0k.com lucky winner",
        "visit amazon-lucky-winner.top to claim",
        "scholarships.gov.in application received",
    ]
    print("="*60)
    for t in tests:
        r = checker.analyze(t)
        label = (
            "SCAM" if r["score"] >= 70
            else "SUSPICIOUS" if r["score"] >= 40
            else "SAFE"
        )
        print(f"\n[{label}] {r['score']:.0f}/100")
        print(f"Input:   {t[:60]}")
        print(f"Reasons: {r['reasons'][:2]}")