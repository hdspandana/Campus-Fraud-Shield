# core/rules_engine.py
import re
from typing import List, Dict, Tuple, Any
from core.homoglyph_normalizer import find_spoofed_brands

# Each pattern: (regex, score_weight, reason_string)
FEE_PATTERNS = [
    (r"registration\s*(fee|charge|amount|deposit|to|for|bhejo|karo)?", 35, "Asks for registration payment"),
    (r"joining\s*(fee|charge|amount|deposit|to|for|bhejo|karo)?", 35, "Asks for joining payment"),
    (r"security\s*(deposit|fee|charge|amount)?", 35, "Asks for security deposit"),
    (r"processing\s*(fee|charge|amount|deposit)?", 35, "Asks for processing payment"),
    (r"activation\s*(fee|charge|amount|deposit)?", 35, "Asks for profile activation payment"),
    (r"training\s*(fee|charge|amount|deposit)?", 35, "Asks for mandatory training payment"),
    (r"documentation\s*(fee|charge|amount|deposit)?", 35, "Asks for documentation fee"),
    (r"verification\s*(fee|charge|amount|deposit)?", 35, "Asks for background verification fee"),
    (r"kit\s*(charge|fee|amount)?", 30, "Asks for up-front kit charges"),
    (r"delivery\s*(charge|fee|amount)?", 30, "Asks for up-front delivery charges"),
    (r"stamp\s*duty", 30, "Asks for legal stamp duty payment"),
    (r"gst\s*(charge|fee|amount)?", 25, "Asks for up-front GST payment"),
    (r"refundable\s*deposit", 30, "Asks for a refundable security deposit"),
    (r"panjikaran\s*shulk", 35, "Asks for registration fee (Hindi)"),
    (r"fee?\s*bhejo", 35, "Asks to send fee via UPI (Hinglish)"),
    (r"paisa\s*bhejo", 35, "Asks to send money (Hindi)"),
    (r"payment\s*karo", 30, "Asks to make a payment (Hindi)"),
    (r"pay\s*(rs\.?|₹)?\s*\d+", 30, "Direct payment request with numeric value"),
]

OTP_PATTERNS = [
    (r"shar(e|ing)\s*(your\s*)?otp", 45, "Asks to share sensitive mobile OTP"),
    (r"send\s*(your\s*)?otp", 45, "Asks to text / forward mobile OTP"),
    (r"otp\s*(de|do|bhejo|batao)", 45, "Asks to supply account OTP (Hinglish)"),
    (r"enter\s*(the\s*)?otp", 35, "Asks to enter OTP on an unverified link"),
    (r"verify\s*(with\s*)?otp", 30, "Unsolicited identity verification request"),
    (r"otp\s*share\s*mat\s*karo", -40, "Explicit warning against sharing security codes (Safe Signal)"),
]

URGENCY_PATTERNS = [
    (r"24\s*hours?\s*(only|mein|me|left)", 20, "Imposes high-pressure 24-hour deadline"),
    (r"offer\s*expires", 20, "Creates artificial psychological scarcity"),
    (r"limited\s*(time|seats?|slots?)", 20, "Limited availability high-pressure tactic"),
    (r"act\s*now", 15, "Creates an artificial sense of immediate urgency"),
    (r"today\s*only", 20, "Imposes immediate same-day pressure"),
    (r"abhi\s*(karo|kijiye|bhejo)", 20, "Immediate action demanded in Hindi"),
    (r"jaldi\s*karo", 20, "High-pressure dynamic in Hindi: hurry up"),
    (r"turant", 15, "Immediate compliance demanded in Hindi"),
    (r"sirf\s*aaj", 20, "Creates immediate same-day pressure (Hindi)"),
    (r"aaj\s*hi", 15, "Action forced on current date (Hindi)"),
    (r"kal\s*tak", 15, "Enforces narrow deadline by tomorrow (Hindi)"),
    (r"expires?\s*tonight", 20, "Imposes absolute expiration by tonight"),
    (r"do\s*not\s*(miss|delay)", 15, "Creates psychological pressure to avoid missing out"),
    (r"earn\s*(rs\.?|₹)?\s*[\d,]+\s*per\s*(hour|day|week)", 25, "Unrealistic high-frequency earning claim"),
]

CONTACT_PATTERNS = [
    (r"@[a-z0-9\-]+\.com", 0, "Standard web domain structure lookahead"),
    (r"\b[A-Za-z0-9._%+-]+@gmail\.com\b", 25, "Uses generic free Gmail instead of institutional domain"),
    (r"\b[A-Za-z0-9._%+-]+@yahoo\.com\b", 25, "Uses generic free Yahoo instead of institutional domain"),
    (r"\b[A-Za-z0-9._%+-]+@hotmail\.com\b", 25, "Uses generic free Hotmail instead of institutional domain"),
    (r"bit\.ly/", 30, "Uses unverified anonymous link tracking shortener (bit.ly)"),
    (r"tinyurl\.com", 30, "Uses unverified anonymous link tracking shortener (tinyurl)"),
    (r"t\.me/", 20, "Redirects conversation to anonymous Telegram channel"),
    (r"whatsapp\s*(only|link|pe|bhejo)", 20, "Forces recruitment conversation exclusively onto WhatsApp"),
    (r"telegram\s*(only|channel|group|link)", 20, "Forces conversation into anonymous Telegram group"),
]

PAYMENT_PATTERNS = [
    (r"(send|pay|transfer)\s*(to\s*)?(paytm|phonepe|gpay|upi)", 30, "Requests payment via personal digital wallets"),
    (r"paytm\s*[6-9]\d{9}", 35, "Provides personal mobile layout for Paytm transfers"),
    (r"phonepe\s*[6-9]\d{9}", 35, "Provides personal mobile layout for PhonePe transfers"),
    (r"gpay\s*[6-9]\d{9}", 35, "Provides personal mobile layout for GPay transfers"),
    (r"\b[6-9]\d{9}\s*(pe|par)\s*(bhejo|karo|transfer)\b", 35, "Demands direct funds transfer to mobile number"),
    (r"wallet\s*(mein|me)\s*(bhejo|dalo)", 30, "Demands wallet fund load (Hindi)"),
]

PRIZE_PATTERNS = [
    (r"(you\s*have\s*)?(won|win)\s*(a\s*)?(prize|lottery|lucky\s*draw)", 40, "Claims prize or lottery winnings"),
    (r"lucky\s*(draw|winner)", 40, "Claims unverified lucky draw placement"),
    (r"kbc\s*(winner|prize|lucky|lottery)", 40, "Impersonates standard KBC lucky draw frames"),
    (r"congratulations.{0,30}(won|win|prize|selected)", 30, "Unsolicited congratulatory win announcement"),
    (r"claim\s*(your\s*)?(prize|reward|amount)", 35, "Demands action to extract prize or reward value"),
]

SELECTION_PATTERNS = [
    (r"(you\s*(are|have\s*been))\s*selected", 15, "Claims career selection without tracking history"),
    (r"shortlisted\s*(for\s*)?internship", 10, "Claims corporate internship shortlisting"),
    (r"pre[\s-]?selected", 15, "Claims advance automated pre-selection"),
    (r"selected\s*(candidates?\s*)?(must|should|have\s*to)\s*pay", 45, "Enforces selection payment: direct scam pattern"),
    (r"selection\s*(ke\s*)?baad\s*fee", 45, "Demands post-selection processing fee (Hindi)"),
]

SAFE_SIGNALS = [
    (r"no\s*fee\s*(required|charged|applicable)", -35, "Explicitly states zero cost matching official policies"),
    (r"free\s*(to\s*)?(apply|register|join)", -30, "Explicitly states free career registration lifecycle"),
    (r"stipend\s*(provided|included|of\s*rs)", -20, "Mentions standard compliant student stipend structure"),
    (r"official\s*website", -15, "References official verification baseline"),
    (r"bring\s*(your\s*)?documents", -20, "Asks for physical document vetting at onboarding locations"),
    (r"(microsoft\s*teams|google\s*meet|zoom)\s*(interview|link|call)", -25, "Requires verification via safe enterprise video tool"),
    (r"offer\s*letter\s*(attached|sent|mailed)", -20, "References valid attachment vectors from verified sources"),
    (r"report(ing)?\s*(date|to)\s*(office|campus|center)", -20, "Demands physical campus report before financial tracking"),
    (r"koi\s*fee\s*nahi", -30, "States zero cost policy clearly in Hindi"),
    (r"muft\s*(mein|hai)", -25, "States zero financial obligation in Hindi"),
]

AMOUNT_PATTERNS = [
    r"rs\.?\s*[\d,]+",
    r"₹\s*[\d,]+",
    r"inr\s*[\d,]+",
    r"[\d,]+\s*rupees?",
    r"[\d,]+\s*rs\.?",
]

PHONE_PATTERN = r"\b[6-9]\d{9}\b"

URL_PATTERNS = [
    r"https?://[^\s<>\"']+",
    r"www\.[^\s<>\"']+",
    r"bit\.ly/[^\s<>\"']+",
    r"tinyurl\.com/[^\s<>\"']+",
]

CATEGORY_SIGNALS = {
    "internship_fee": [r"internship.{0,30}fee", r"internship.{0,30}pay", r"internship.{0,30}deposit", r"intern\.{0,30}registration"],
    "job_fee": [r"job.{0,30}fee", r"joining.{0,30}fee", r"placement.{0,30}fee", r"recruitment.{0,30}fee"],
    "scholarship_fee": [r"scholarship.{0,30}fee", r"scholarship.{0,30}pay", r"scholarship.{0,30}processing", r"scholarship.{0,30}release"],
    "otp_fraud": [r"share.{0,10}otp", r"send.{0,10}otp", r"otp.{0,10}(share|send|de|do)", r"verify.{0,20}otp"],
    "lottery_prize": [r"lucky\s*draw", r"won.{0,20}prize", r"lottery.{0,20}winner", r"kbc.{0,20}winner"],
    "parttime_job": [r"work\s*from\s*home.{0,30}earn", r"part[\s-]?time.{0,30}(earn|pay|job)", r"data\s*entry.{0,30}earn", r"youtube.{0,30}(like|subscribe).{0,20}earn"],
    "bank_impersonation": [r"(sbi|hdfc|icici|axis|paytm|phonepe).{0,30}(block|suspend|verify)", r"kyc.{0,30}(update|verify|complete)", r"account.{0,20}(block|suspend|deactivat)"],
    "gov_scheme_fraud": [r"pm\s*(scholarship|yojana|scheme).{0,30}(fee|pay)", r"government.{0,30}(free|scheme).{0,30}(fee|pay|register)", r"nsp.{0,30}(fee|processing|pay)"],
}


class RulesEngine:
    """
    Fast pattern-based scam detection engine.
    Analyzes strings using regex loops for deterministic validation.
    Safe signals are suppressed when spoofed brand names are detected.
    """

    def analyze(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        reasons    = []
        flags      = []
        raw_score  = 0

        # ── Check for spoofs BEFORE pattern loop ──────────────
        # If spoof found → suppress ALL safe/negative signals
        # because spoofed brand name makes all safety signals invalid
        spoofs_found   = find_spoofed_brands(text)
        spoof_detected = len(spoofs_found) > 0

        all_patterns = [
            ("fee",       FEE_PATTERNS),
            ("otp",       OTP_PATTERNS),
            ("urgency",   URGENCY_PATTERNS),
            ("contact",   CONTACT_PATTERNS),
            ("payment",   PAYMENT_PATTERNS),
            ("prize",     PRIZE_PATTERNS),
            ("selection", SELECTION_PATTERNS),
            ("safe",      SAFE_SIGNALS),
        ]

        for group_name, patterns in all_patterns:
            for pattern, weight, reason in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):

                    # ── Suppress safe signals if spoof detected ──
                    # A message with "g00gle" + "no fee required"
                    # should NOT get the safe signal reduction
                    if weight < 0 and spoof_detected:
                        flags.append(
                            f"safe_signal_suppressed"
                            f"(spoof):{pattern[:20]}"
                        )
                        continue

                    raw_score += weight
                    if weight > 0:
                        reasons.append(reason)
                        flags.append(f"{group_name}:{pattern[:15]}")

        score           = max(0.0, min(100.0, float(raw_score)))
        category        = self._detect_category(text_lower)
        extractions     = self._extract_info(text)
        display_reasons = list(dict.fromkeys(reasons))[:5]

        return {
            "score":       score,
            "reasons":     display_reasons,
            "flags":       flags,
            "category":    category,
            "extractions": extractions,
            "raw_score":   raw_score,
        }

    def _detect_category(self, text_lower: str) -> str:
        scores: Dict[str, int] = {}
        for category, patterns in CATEGORY_SIGNALS.items():
            count = sum(
                1 for pattern in patterns
                if re.search(pattern, text_lower, re.IGNORECASE)
            )
            if count > 0:
                scores[category] = count
        return max(scores, key=scores.get) if scores else "unknown_scam"

    def _extract_info(self, text: str) -> Dict[str, Any]:
        phones = re.findall(PHONE_PATTERN, text)

        amounts = []
        for pattern in AMOUNT_PATTERNS:
            found = re.findall(pattern, text, re.IGNORECASE)
            amounts.extend(found)
        amounts = list(dict.fromkeys(amounts))

        urls = []
        for pattern in URL_PATTERNS:
            found = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(found)
        urls = list(dict.fromkeys(urls))

        return {
            "phones":  [str(p) for p in phones[:3]],
            "amounts": [str(a) for a in amounts[:3]],
            "urls":    [str(u) for u in urls[:3]],
        }

    def get_triggered_rules(self, text: str) -> List[Dict[str, Any]]:
        text_lower = text.lower()
        triggered  = []

        all_patterns = [
            ("Fee Pattern",       FEE_PATTERNS),
            ("OTP Pattern",       OTP_PATTERNS),
            ("Urgency Pattern",   URGENCY_PATTERNS),
            ("Contact Pattern",   CONTACT_PATTERNS),
            ("Payment Pattern",   PAYMENT_PATTERNS),
            ("Prize Pattern",     PRIZE_PATTERNS),
            ("Selection Pattern", SELECTION_PATTERNS),
            ("Safe Signal",       SAFE_SIGNALS),
        ]

        for group_name, patterns in all_patterns:
            for pattern, weight, reason in patterns:
                match = re.search(pattern, text_lower, re.IGNORECASE)
                if match:
                    triggered.append({
                        "group":       group_name,
                        "reason":      reason,
                        "weight":      weight,
                        "matched":     str(match.group()),
                        "is_positive": weight > 0,
                    })
        return triggered