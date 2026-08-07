# core/domain_checker.py
# ═════════════════════════════════════════════════════════════════
# Production Domain & URL Threat Analysis Engine
# 15+ detection vectors for malicious URLs
# Catches: typosquatting, phishing paths, HTTP downgrades,
#          impersonation, suspicious TLDs, IP addresses,
#          subdomain abuse, character substitution, and more
# ═════════════════════════════════════════════════════════════════

import re
import time
import tldextract
import requests
from typing import List, Dict, Any, Tuple

try:
    from config import GOOGLE_SAFE_BROWSING_KEY, VIRUSTOTAL_KEY
except ImportError:
    # Fallback so this module still works if imported standalone / in tests
    import os
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ── Simple in-memory cache for threat-intel lookups ────────────────
# Avoids re-querying the same domain/URL repeatedly within one running
# process (Streamlit session), which would otherwise burn through free
# API quotas fast. Not persisted across restarts — that's fine here,
# since the point is just to avoid duplicate calls in a single session.
_THREAT_INTEL_CACHE: Dict[str, Tuple[float, float, List[str]]] = {}
_THREAT_INTEL_CACHE_TTL_SECONDS = 3600
_THREAT_INTEL_TIMEOUT_SECONDS = 4

# ── Commonly Impersonated Brands ──────────────────────────────────
COMMONLY_IMPERSONATED = {
    "google":      "google.com",
    "facebook":    "facebook.com",
    "instagram":   "instagram.com",
    "whatsapp":    "whatsapp.com",
    "youtube":     "youtube.com",
    "amazon":      "amazon.in",
    "flipkart":    "flipkart.com",
    "paypal":      "paypal.com",
    "paytm":       "paytm.com",
    "phonepe":     "phonepe.com",
    "internshala": "internshala.com",
    "naukri":      "naukri.com",
    "linkedin":    "linkedin.com",
    "microsoft":   "microsoft.com",
    "apple":       "apple.com",
    "netflix":     "netflix.com",
    "sbi":         "sbi.co.in",
    "hdfc":        "hdfcbank.com",
    "icici":       "icicibank.com",
    "axis":        "axisbank.com",
    "kotak":       "kotak.com",
    "tcs":         "tcs.com",
    "infosys":     "infosys.com",
    "wipro":       "wipro.com",
    "swiggy":      "swiggy.com",
    "zomato":      "zomato.com",
    "myntra":      "myntra.com",
    "uber":        "uber.com",
    "ola":         "olacabs.com",
    "airtel":      "airtel.in",
    "jio":         "jio.com",
    "vodafone":    "vodafone.in",
    "irctc":       "irctc.co.in",
    "uidai":       "uidai.gov.in",
    "epfo":        "epfindia.gov.in",
    "incometax":   "incometax.gov.in",
}

# ── Known Safe Domains ────────────────────────────────────────────
SAFE_DOMAINS = {
    "internshala.com", "naukri.com", "linkedin.com",
    "letsintern.com", "unstop.com", "hackerearth.com",
    "foundit.in", "monsterindia.com", "apna.co",
    "freshersworld.com", "shine.com", "timesjobs.com",
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
    "facebook.com", "instagram.com", "youtube.com",
    "whatsapp.com", "twitter.com",
    "nptel.ac.in", "swayam.gov.in", "coursera.org",
    "edx.org", "udemy.com", "khanacademy.org",
    "education.github.com", "hackerrank.com",
    "teams.microsoft.com", "meet.google.com",
    "zoom.us", "webex.com",
    "iitb.ac.in", "iitd.ac.in", "iitm.ac.in",
    "iitk.ac.in", "iisc.ac.in", "nit.ac.in",
    "github.com", "stackoverflow.com",
    "flipkart.com", "myntra.com", "swiggy.com", "zomato.com",
}

# ── Highly Suspicious TLDs ────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz": 35, ".tk": 40, ".ml": 40, ".ga": 40, ".cf": 40, ".gq": 40,
    ".top": 30, ".click": 35, ".loan": 35, ".work": 30, ".date": 35,
    ".win": 35, ".download": 35, ".racing": 35, ".review": 30,
    ".stream": 30, ".gdn": 35, ".men": 35, ".bid": 35, ".trade": 30,
    ".country": 30, ".kim": 30, ".cricket": 30, ".science": 30,
    ".party": 30, ".faith": 30, ".mom": 30, ".accountant": 35,
    ".cam": 30, ".rest": 30, ".fit": 25, ".online": 20, ".site": 20,
}

# ── URL Shorteners ────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "dlvr.it", "ift.tt",
    "tiny.cc", "is.gd", "cli.gs", "pic.gd",
    "url4.eu", "tr.im", "twurl.nl", "snipurl.com",
    "short.to", "bkite.com", "snipr.com", "flic.kr",
    "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly",
    "tiny.one", "bit.do", "v.gd", "t2m.io",
}

# ── Free / Suspicious Hosting Providers ───────────────────────────
SUSPICIOUS_HOSTS = {
    "000webhostapp.com", "weebly.com", "wixsite.com",
    "blogspot.com", "wordpress.com", "github.io",
    "netlify.app", "vercel.app", "herokuapp.com",
    "neocities.org", "altervista.org", "jimdofree.com",
    "webnode.com", "yolasite.com", "byethost.com",
    "freehostia.com", "infinityfree.net", "hostinger.com",
    "glitch.me", "repl.co", "ngrok.io",
}

# ── Phishing Keywords in Domain Names ─────────────────────────────
PHISHING_DOMAIN_KEYWORDS = {
    "login":       20,
    "signin":      20,
    "secure":      18,
    "verify":      20,
    "verification":20,
    "auth":        15,
    "authenticate":18,
    "account":     15,
    "update":      15,
    "confirm":     18,
    "validate":    18,
    "kyc":         25,
    "wallet":      15,
    "recovery":    20,
    "recover":     20,
    "reset":       15,
    "unlock":      18,
    "support":     12,
    "help":        10,
    "service":     10,
    "official":    20,
    "verified":    18,
    "alert":       15,
    "warning":     15,
    "billing":     15,
    "payment":     15,
    "refund":      18,
    "claim":       20,
    "prize":       25,
    "winner":      25,
    "lucky":       25,
    "bonus":       18,
    "reward":      18,
    "free":        15,
    "gift":        18,
    "offer":       12,
    "limited":     12,
    "urgent":      15,
    "portal":      15,
    "gateway":     12,
}

# ── Phishing Keywords in URL Path ─────────────────────────────────
PHISHING_PATH_KEYWORDS = {
    "/login":     15,
    "/signin":    15,
    "/auth":      18,
    "/verify":    20,
    "/confirm":   18,
    "/validate":  18,
    "/secure":    15,
    "/kyc":       25,
    "/recover":   20,
    "/unlock":    18,
    "/wallet":    15,
    "/payment":   15,
    "/refund":    20,
    "/claim":     20,
    "/prize":     25,
    "/winner":    25,
    "/account/update":   25,
    "/account/verify":   25,
    "/security/check":   20,
}

# ── Brand Impersonation Patterns ──────────────────────────────────
IMPERSONATION_PATTERNS = [
    (r"internshala\.(co|net|org|in|info|xyz|tk)(?!m)", "internshala.com", "Internshala"),
    (r"internshala[0-9]", "internshala.com", "Internshala"),
    (r"internshala[-_]", "internshala.com", "Internshala"),
    (r"nsp[-_]scholarship", "scholarships.gov.in", "NSP"),
    (r"nationalscholarship\.(co|net|in|org)", "scholarships.gov.in", "NSP"),
    (r"sbi[-_.]?(bank|online|kyc|login|secure|update)", "sbi.co.in", "SBI"),
    (r"hdfc[-_.]?(bank|online|kyc|login|secure|update)", "hdfcbank.com", "HDFC"),
    (r"icici[-_.]?(bank|online|kyc|login|secure)", "icicibank.com", "ICICI"),
    (r"paytm[-_.]?(kyc|bank|wallet|secure|login)", "paytm.com", "Paytm"),
    (r"phonepe[-_.]?(kyc|secure|login|update)", "phonepe.com", "PhonePe"),
    (r"india[-_.]?gov\.(co|net|org|in\.com|xyz)", "india.gov.in", "Government of India"),
    (r"pm[-_]?(scholarship|yojana)[-_.]?(gov|official|claim)", "scholarships.gov.in", "PM Scholarship"),
    (r"tcs[-_.]?(career|hire|job|recruit|joining)", "tcs.com", "TCS"),
    (r"infosys[-_.]?(career|hire|job|recruit|joining)", "infosys.com", "Infosys"),
    (r"wipro[-_.]?(career|hire|job|recruit|joining)", "wipro.com", "Wipro"),
    (r"amazon[-_.]?(job|hire|wfh|work|prize|winner)", "amazon.in", "Amazon"),
    (r"flipkart[-_.]?(prize|winner|lucky|offer)", "flipkart.com", "Flipkart"),
    (r"google[-_.]?(prize|winner|lucky|verify|secure)", "google.com", "Google"),
    (r"facebook[-_.]?(prize|winner|secure|verify)", "facebook.com", "Facebook"),
    (r"whatsapp[-_.]?(prize|winner|gold|premium|verify)", "whatsapp.com", "WhatsApp"),
    (r"kbc[-_.]?(winner|prize|claim|lucky|registration)", None, "KBC (Fake)"),
    (r"lucky[-_.]?(draw|winner|prize)", None, "Lucky Draw (Fake)"),
    (r"jio[-_.]?(prize|winner|lucky|free|recharge)", "jio.com", "Jio"),
    (r"airtel[-_.]?(prize|winner|lucky|free|recharge)", "airtel.in", "Airtel"),
    (r"university[-_.]?(portal|login|verify|secure)", None, "University (Fake)"),
    (r"college[-_.]?(portal|login|verify|secure)", None, "College (Fake)"),
    (r"scholarship[-_.]?(claim|verify|portal|gov)", None, "Scholarship (Fake)"),
]

# ── Gmail Red Flag Patterns ───────────────────────────────────────
GMAIL_RED_FLAG_PATTERNS = [
    r"(internshala|tcs|infosys|wipro|cognizant|accenture|"
    r"hcl|amazon|google|microsoft|nsp|scholarship|"
    r"sbi|hdfc|icici|axis|paytm|phonepe|"
    r"govt|government|pm|ministry).{0,30}@gmail\.com",
]


# ═════════════════════════════════════════════════════════════════
class DomainChecker:
    """
    Production-grade URL/domain threat analyzer.
    15+ detection vectors covering typosquatting, phishing,
    impersonation, suspicious TLDs, HTTP downgrades, and more.
    """

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze all URLs and emails in text.

        Returns:
            dict with score, reasons, domains
        """
        reasons    = []
        score      = 0.0
        red_flags  = 0  # Count red flags for compound bonus

        urls    = self._extract_urls(text)
        emails  = self._extract_emails(text)
        domains = self._get_domains(urls + emails)

        # ── 1. Per-domain checks (whitelist, TLD, shortener) ──────
        for domain in domains:
            d_score, d_reasons = self._check_domain(domain, text)
            score   += d_score
            reasons.extend(d_reasons)
            if d_score > 0:
                red_flags += 1

        # ── 2. Typosquatting detection ────────────────────────────
        for domain in domains:
            t_score, t_reasons = self._check_typosquatting(domain)
            score   += t_score
            reasons.extend(t_reasons)
            if t_score > 0:
                red_flags += 1

        # ── 3. Brand impersonation in URLs ────────────────────────
        i_score, i_reasons = self._check_impersonation(text)
        score   += i_score
        reasons.extend(i_reasons)
        if i_score > 0:
            red_flags += 1

        # ── 4. Gmail used by professional brand ───────────────────
        g_score, g_reasons = self._check_gmail_redflag(text)
        score   += g_score
        reasons.extend(g_reasons)
        if g_score > 0:
            red_flags += 1

        # ── 5. HTTP (no SSL) detection ────────────────────────────
        h_score, h_reasons = self._check_http_scheme(urls)
        score   += h_score
        reasons.extend(h_reasons)
        if h_score > 0:
            red_flags += 1

        # ── 6. Phishing path keywords ─────────────────────────────
        p_score, p_reasons = self._check_path_keywords(urls)
        score   += p_score
        reasons.extend(p_reasons)
        if p_score > 0:
            red_flags += 1

        # ── 7. IP address as URL ──────────────────────────────────
        ip_score, ip_reasons = self._check_ip_address(urls)
        score   += ip_score
        reasons.extend(ip_reasons)
        if ip_score > 0:
            red_flags += 1

        # ── 8. Subdomain abuse ────────────────────────────────────
        sd_score, sd_reasons = self._check_subdomain_abuse(urls)
        score   += sd_score
        reasons.extend(sd_reasons)
        if sd_score > 0:
            red_flags += 1

        # ── 9. Multi-hyphen suspicious pattern ────────────────────
        mh_score, mh_reasons = self._check_multi_hyphen(domains)
        score   += mh_score
        reasons.extend(mh_reasons)
        if mh_score > 0:
            red_flags += 1

        # ── 10. Real-time threat intelligence (VirusTotal / Safe Browsing) ──
        # Only fires if API keys are configured; silently skipped otherwise
        # so this never breaks the app for anyone without keys set up.
        ti_score, ti_reasons, ti_status = self._check_threat_intel(domains, urls)
        score   += ti_score
        reasons.extend(ti_reasons)
        if ti_score > 0:
            red_flags += 1

        if ti_status == self.TI_UNAVAILABLE:
            reasons.append(
                "⚪ Threat-intelligence lookup was attempted but did not "
                "complete (network/rate-limit issue) — this does NOT mean "
                "the domain is safe, only that it wasn't verified."
            )

        # ── 11. Compound red flag bonus ───────────────────────────
        if red_flags >= 3:
            score += 25
            reasons.append(
                f"⚠️ {red_flags} independent red flags detected — "
                f"highly likely phishing/malicious URL"
            )
        elif red_flags >= 2:
            score += 15
            reasons.append(
                f"Multiple suspicious signals ({red_flags}) detected in URL"
            )

        # ── Cap and dedupe ────────────────────────────────────────
        score   = max(0.0, min(100.0, score))
        reasons = list(dict.fromkeys(reasons))[:7]

        return {
            "score":     score,
            "reasons":   reasons,
            "domains":   domains,
            "ti_status": ti_status,  # not_configured | checked | unavailable
        }

    # ── URL/Email Extraction ──────────────────────────────────────
    def _extract_urls(self, text: str) -> List[str]:
        patterns = [
            r"https?://[^\s<>\"']+",
            r"www\.[^\s<>\"']+",
            r"[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\."
            r"(?:com|in|org|net|gov|co\.in|ac\.in|xyz|tk|ml|ga|cf|gq|"
            r"top|click|loan|work|date|win|info|biz|site|online)[^\s]*",
        ]
        urls = []
        for pattern in patterns:
            urls.extend(re.findall(pattern, text, re.IGNORECASE))
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
            except Exception:
                pass
        return list(set(domains))

    # ── Check 1: Per-Domain Analysis ──────────────────────────────
    def _check_domain(self, domain: str, text: str) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        if domain in SAFE_DOMAINS:
            return -20, reasons

        if domain in URL_SHORTENERS:
            score += 30
            reasons.append(
                f"Suspicious shortened URL ({domain}) — hides real destination"
            )

        if domain in SUSPICIOUS_HOSTS:
            score += 25
            reasons.append(
                f"Free/anonymous hosting detected ({domain}) — "
                f"common for phishing sites"
            )

        # Check suspicious TLDs
        for tld, tld_score in SUSPICIOUS_TLDS.items():
            if domain.endswith(tld):
                score += tld_score
                reasons.append(
                    f"Suspicious domain extension ({tld}) — "
                    f"frequently used in scam websites"
                )
                break

        # Personal email used as official contact
        if domain in {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}:
            score += 25
            reasons.append(
                f"Personal email ({domain}) used instead of official email"
            )

        # Phishing keywords in domain
        ext = tldextract.extract(domain)
        domain_name = ext.domain.lower()

        keyword_hits = []
        keyword_score_total = 0
        for keyword, k_score in PHISHING_DOMAIN_KEYWORDS.items():
            if keyword in domain_name:
                keyword_hits.append(keyword)
                keyword_score_total += k_score

        if keyword_hits:
            # Cap keyword score to avoid runaway
            keyword_score_total = min(keyword_score_total, 50)
            score += keyword_score_total
            reasons.append(
                f"Domain contains phishing keywords "
                f"({', '.join(keyword_hits[:3])}) → {domain}"
            )

        # Numeric characters in domain (suspicious)
        if re.search(r"\d{3,}", domain_name):
            score += 15
            reasons.append(
                f"Domain contains long number sequence ({domain})"
            )

        # Excessively long domain name
        if len(domain_name) > 25:
            score += 15
            reasons.append(
                f"Suspiciously long domain name ({len(domain_name)} chars)"
            )

        return score, reasons

    # ── Check 2: Typosquatting ────────────────────────────────────
    def _check_typosquatting(self, domain: str) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        if domain in SAFE_DOMAINS:
            return score, reasons

        ext = tldextract.extract(domain)
        domain_name = ext.domain.lower()

        if len(domain_name) < 4:
            return score, reasons

        for brand, real_domain in COMMONLY_IMPERSONATED.items():
            if domain == real_domain:
                return 0, []

            distance = self._levenshtein(domain_name, brand)

            if distance == 1:
                score += 50
                reasons.append(
                    f"🎯 Typosquatting detected: '{domain}' looks like "
                    f"'{real_domain}' (1 char difference). "
                    f"Likely fake site impersonating {brand.title()}."
                )
                break
            elif distance == 2 and len(brand) >= 6:
                score += 35
                reasons.append(
                    f"Possible typosquatting: '{domain}' is similar to "
                    f"'{real_domain}'. Verify carefully."
                )
                break

        # Number substitution attacks (g00gle, faceb00k)
        sub_map = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}
        normalized = domain_name
        for d, l in sub_map.items():
            normalized = normalized.replace(d, l)

        if normalized != domain_name:
            for brand in COMMONLY_IMPERSONATED:
                if normalized == brand:
                    score += 55
                    reasons.append(
                        f"🎯 Character substitution attack: '{domain}' "
                        f"uses numbers to mimic '{brand}.com'. "
                        f"Classic phishing pattern."
                    )
                    break

        return score, reasons

    # ── Check 3: HTTP (insecure) Scheme ───────────────────────────
    def _check_http_scheme(self, urls: List[str]) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        for url in urls:
            if url.lower().startswith("http://"):
                # Even worse if URL contains login/auth/payment paths
                sensitive = any(
                    kw in url.lower()
                    for kw in [
                        "login", "auth", "signin", "verify",
                        "payment", "secure", "bank", "kyc",
                        "wallet", "account", "password",
                    ]
                )
                if sensitive:
                    score += 35
                    reasons.append(
                        f"🚨 INSECURE HTTP used for sensitive page "
                        f"(login/auth/payment) — never enter credentials here"
                    )
                else:
                    score += 18
                    reasons.append(
                        f"Insecure HTTP connection (not HTTPS) — "
                        f"data can be intercepted"
                    )
                break

        return score, reasons

    # ── Check 4: Phishing Path Keywords ───────────────────────────
    def _check_path_keywords(self, urls: List[str]) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []
        matched_paths = []

        for url in urls:
            url_lower = url.lower()
            for keyword, k_score in PHISHING_PATH_KEYWORDS.items():
                if keyword in url_lower:
                    score += k_score
                    matched_paths.append(keyword)
                    break  # one path keyword per URL

        if matched_paths:
            score = min(score, 45)  # cap path score
            reasons.append(
                f"URL path contains phishing keywords "
                f"({', '.join(set(matched_paths))[:50]})"
            )

        return score, reasons

    # ── Check 5: IP Address as URL ────────────────────────────────
    def _check_ip_address(self, urls: List[str]) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        ip_pattern = re.compile(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}",
            re.IGNORECASE
        )
        for url in urls:
            if ip_pattern.search(url):
                score += 45
                reasons.append(
                    "🚨 URL uses raw IP address instead of domain — "
                    "extremely suspicious, almost always malicious"
                )
                break

        return score, reasons

    # ── Check 6: Subdomain Abuse ──────────────────────────────────
    def _check_subdomain_abuse(self, urls: List[str]) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        for url in urls:
            try:
                ext = tldextract.extract(url)
                if ext.subdomain:
                    sub_count = len(ext.subdomain.split("."))
                    # 4+ subdomains is highly unusual
                    if sub_count >= 4:
                        score += 25
                        reasons.append(
                            f"Excessive subdomain nesting "
                            f"({sub_count} levels) — phishing pattern"
                        )
                        break
                    # Check if subdomain contains brand name + main domain doesn't
                    sub_lower = ext.subdomain.lower()
                    domain_lower = ext.domain.lower()
                    for brand in COMMONLY_IMPERSONATED:
                        if brand in sub_lower and brand not in domain_lower:
                            score += 35
                            reasons.append(
                                f"🎯 Brand name '{brand}' in subdomain but "
                                f"actual domain is '{ext.domain}.{ext.suffix}' — "
                                f"impersonation attack"
                            )
                            return score, reasons
            except Exception:
                pass

        return score, reasons

    # ── Check 7: Multi-Hyphen Pattern ─────────────────────────────
    def _check_multi_hyphen(self, domains: List[str]) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        for domain in domains:
            if domain in SAFE_DOMAINS:
                continue
            ext = tldextract.extract(domain)
            hyphen_count = ext.domain.count("-")
            if hyphen_count >= 2:
                score += 20
                reasons.append(
                    f"Multiple hyphens in domain ({hyphen_count}) — "
                    f"common in phishing URLs"
                )
                break

        return score, reasons

    # ── Check: Real-time Threat Intelligence (VirusTotal + Safe Browsing) ──
    #
    # TI status values — these describe HOW MUCH we actually know, which is
    # a different axis from the risk score itself:
    #   "not_configured" — no API keys set at all, no calls attempted
    #   "checked"        — at least one call to VT/GSB completed successfully
    #                      (whether it found something or came back clean)
    #   "unavailable"    — a key was configured, a call was attempted, and
    #                      it failed (timeout/network error/non-200). We
    #                      still fail OPEN on the risk score (never punish
    #                      a domain just because an API had an outage), but
    #                      the caller must know this happened so confidence
    #                      can be reduced without touching risk.
    #
    # Previously "not configured", "checked and clean", and "checked but
    # broken" all collapsed into the identical (0.0, []) output — this made
    # them indistinguishable to every downstream consumer (scorer.py,
    # eventually the UI). That's the bug being fixed here.
    TI_NOT_CONFIGURED = "not_configured"
    TI_CHECKED         = "checked"
    TI_UNAVAILABLE      = "unavailable"

    def _check_threat_intel(
        self, domains: List[str], urls: List[str]
    ) -> Tuple[float, List[str], str]:
        """
        Cross-references domains/URLs against VirusTotal and Google Safe
        Browsing. Both are optional — if their API keys aren't set in
        .env, this returns (0.0, [], "not_configured") immediately with no
        network calls, so the app works identically to before for anyone
        without keys.

        Capped to the first 2 domains/URLs per scan to bound latency and
        protect free-tier API quotas (both VT and GSB free tiers are
        rate-limited per day).

        Returns (score, reasons, status) where status is one of
        TI_NOT_CONFIGURED / TI_CHECKED / TI_UNAVAILABLE. If ANY configured
        call fails, the overall status is TI_UNAVAILABLE — we'd rather
        under-claim confidence than over-claim it when only one of several
        lookups actually succeeded.
        """
        if not GOOGLE_SAFE_BROWSING_KEY and not VIRUSTOTAL_KEY:
            return 0.0, [], self.TI_NOT_CONFIGURED

        score   = 0.0
        reasons = []
        any_call_attempted = False
        any_call_failed    = False

        if VIRUSTOTAL_KEY:
            for domain in domains[:2]:
                any_call_attempted = True
                vt_score, vt_reasons, vt_ok = self._query_virustotal(domain)
                score += vt_score
                reasons.extend(vt_reasons)
                if not vt_ok:
                    any_call_failed = True

        if GOOGLE_SAFE_BROWSING_KEY:
            for url in urls[:2]:
                any_call_attempted = True
                gsb_score, gsb_reasons, gsb_ok = self._query_safe_browsing(url)
                score += gsb_score
                reasons.extend(gsb_reasons)
                if not gsb_ok:
                    any_call_failed = True

        if not any_call_attempted:
            # Keys configured but no domains/URLs in the message to check —
            # this is a real "checked, nothing to check" state, not a failure.
            status = self.TI_CHECKED
        elif any_call_failed:
            status = self.TI_UNAVAILABLE
        else:
            status = self.TI_CHECKED

        return score, reasons, status

    def _cache_get(self, key: str):
        cached = _THREAT_INTEL_CACHE.get(key)
        if cached is None:
            return None
        score, reasons, ok, cached_at = cached
        if time.time() - cached_at > _THREAT_INTEL_CACHE_TTL_SECONDS:
            del _THREAT_INTEL_CACHE[key]
            return None
        return score, reasons, ok

    def _cache_set(self, key: str, score: float, reasons: List[str], ok: bool = True):
        _THREAT_INTEL_CACHE[key] = (score, reasons, ok, time.time())

    def _query_virustotal(self, domain: str) -> Tuple[float, List[str], bool]:
        """
        Returns (score, reasons, ok) where ok=False means the call itself
        failed (network error, timeout, non-200) — as opposed to succeeding
        and finding nothing. score still fails open to 0.0 on failure (an
        API outage should never itself raise a domain's risk), but `ok`
        lets the caller distinguish "verified clean" from "couldn't verify."
        """
        cache_key = f"vt:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        score, reasons, ok = 0.0, [], True
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=_THREAT_INTEL_TIMEOUT_SECONDS,
            )
            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    score = min(60.0, 15.0 * malicious)
                    reasons.append(
                        f"🚨 VirusTotal: {malicious} security vendor(s) "
                        f"flagged '{domain}' as malicious"
                    )
                elif suspicious > 0:
                    score = min(30.0, 10.0 * suspicious)
                    reasons.append(
                        f"⚠️ VirusTotal: {suspicious} security vendor(s) "
                        f"flagged '{domain}' as suspicious"
                    )
                # else: verified clean — score stays 0.0, ok stays True.
                # This is a genuinely different outcome from the branches
                # below, even though the score is the same.
            else:
                # Rate limit, unknown domain, bad key, etc. — the score
                # correctly fails open (0.0), but this was NOT a
                # successful clean check, so ok must be False.
                ok = False
        except Exception:
            # Network error, timeout, malformed response, etc.
            # Score fails open (0.0) — threat-intel is a bonus signal,
            # never a single point of failure for the whole pipeline —
            # but ok=False so the caller knows this wasn't a real check.
            ok = False

        # Cache failures too, but with a short TTL override isn't needed
        # here since the normal TTL already bounds how long a stale
        # "unavailable" result can linger.
        self._cache_set(cache_key, score, reasons, ok)
        return score, reasons, ok

    def _query_safe_browsing(self, url: str) -> Tuple[float, List[str], bool]:
        """
        Returns (score, reasons, ok) — see _query_virustotal docstring for
        what ok means. Same fail-open-on-score, honest-on-status contract.
        """
        cache_key = f"gsb:{url}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        score, reasons, ok = 0.0, [], True
        try:
            resp = requests.post(
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": GOOGLE_SAFE_BROWSING_KEY},
                json={
                    "client": {"clientId": "campus-fraud-shield", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
                timeout=_THREAT_INTEL_TIMEOUT_SECONDS,
            )
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "known threat")
                    score = 55.0
                    reasons.append(
                        f"🚨 Google Safe Browsing: URL matches known "
                        f"{threat_type.replace('_', ' ').title()} database"
                    )
                # else: verified clean — score 0.0, ok True.
            else:
                ok = False
        except Exception:
            ok = False

        self._cache_set(cache_key, score, reasons, ok)
        return score, reasons, ok

    # ── Check 8: Brand Impersonation Patterns ─────────────────────
    def _check_impersonation(self, text: str) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []
        urls    = self._extract_urls(text)

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
                            f"Suspicious {brand} link — known scam pattern"
                        )
                    break

        return score, reasons

    # ── Check 9: Gmail Red Flag ───────────────────────────────────
    def _check_gmail_redflag(self, text: str) -> Tuple[float, List[str]]:
        score   = 0.0
        reasons = []

        for pattern in GMAIL_RED_FLAG_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_text = match.group()
                brand_match = re.match(r"([a-zA-Z]+)", matched_text, re.IGNORECASE)
                brand = brand_match.group(1).title() if brand_match else "Company"
                score += 45
                reasons.append(
                    f"Real {brand} never uses Gmail — "
                    f"official email must end in @{brand.lower()}.com"
                )
                break

        return score, reasons

    # ── Helper: Levenshtein Distance ──────────────────────────────
    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions    = previous_row[j + 1] + 1
                deletions     = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    # ── Public Helpers ────────────────────────────────────────────
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


# ── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    checker = DomainChecker()

    tests = [
        ("http://university-portal-login.xyz/auth",     "SCAM"),
        ("gooogle.com",                                  "SCAM"),
        ("g00gle.com",                                   "SCAM"),
        ("faceboook.com",                                "SCAM"),
        ("https://sbi-kyc-secure-update.xyz/login",      "SCAM"),
        ("http://192.168.1.1/wp-admin/login.php",        "SCAM"),
        ("https://hdfc.bank.kyc.verify.secure.com",      "SCAM"),
        ("https://bit.ly/abc123",                        "SCAM"),
        ("https://internshala.com",                      "SAFE"),
        ("https://google.com",                           "SAFE"),
        ("https://sbi.co.in",                            "SAFE"),
        ("https://meet.google.com/abc-xyz",              "SAFE"),
    ]

    print(f"{'='*70}")
    print("DOMAIN CHECKER v2 — TEST RESULTS")
    print(f"{'='*70}")

    for url, expected in tests:
        result = checker.analyze(url)
        score  = result["score"]
        label  = "SCAM" if score >= 70 else "SUSPICIOUS" if score >= 40 else "SAFE"
        match  = "✅" if label == expected else "❌"

        print(f"\n{match} {url}")
        print(f"   Expected: {expected}  Got: {label}  ({score:.0f}/100)")
        for r in result["reasons"][:3]:
            print(f"   · {r}")