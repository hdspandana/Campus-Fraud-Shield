# core/campus_checker.py
import re
import os
import json
from typing import List, Dict, Any, Tuple
from core.homoglyph_normalizer import find_spoofed_brands, get_spoof_score

# ── Load campus entities data ────────────────────────────────────
_DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "campus_entities.json"
)
try:
    with open(_DATA_PATH, "r", encoding="utf-8") as _f:
        CAMPUS_DATA = json.load(_f)
except Exception:
    CAMPUS_DATA = {}

# ── Fee Policies ─────────────────────────────────────────────────
FEE_POLICIES = {
    "internshala":    "never_charges_registration_fee",
    "naukri":         "never_charges_application_fee",
    "linkedin":       "never_charges_application_fee",
    "letsintern":     "never_charges_registration_fee",
    "unstop":         "never_charges_participation_fee_for_basic",
    "hackerearth":    "free_for_basic_competitions",
    "foundit":        "never_charges_application_fee",
    "monsterindia":   "never_charges_application_fee",
    "apna":           "never_charges_application_fee",
    "freshersworld":  "never_charges_application_fee",
    "shine":          "never_charges_application_fee",
    "timesjobs":      "never_charges_application_fee",
    "tcs":            "never_charges_joining_or_training_fee",
    "infosys":        "never_charges_joining_or_training_fee",
    "wipro":          "never_charges_joining_or_training_fee",
    "cognizant":      "never_charges_joining_or_training_fee",
    "accenture":      "never_charges_joining_or_training_fee",
    "hcl":            "never_charges_joining_or_training_fee",
    "amazon":         "never_charges_joining_fee",
    "google":         "never_charges_application_fee",
    "microsoft":      "never_charges_application_fee",
    "sbi":            "never_asks_otp_via_call_or_message",
    "hdfc":           "never_asks_otp_via_call_or_message",
    "icici":          "never_asks_otp_via_call_or_message",
    "axis":           "never_asks_otp_via_call_or_message",
    "paytm":          "never_charges_kyc_fee",
    "phonepe":        "never_charges_for_transactions",
    "gpay":           "never_charges_for_transactions",
    "nsp":            "never_requires_processing_fee",
    "pm_scholarship": "fee_paid_by_government",
    "ugc":            "never_requires_fee_for_approval",
    "aicte":          "never_requires_fee_for_recognition",
    "irctc":          "known_fee_structure_on_website",
    "uidai":          "aadhaar_update_has_nominal_fee_at_center",
    "nta":            "known_exam_fee_on_official_portal_only",
    "rbi":            "never_contacts_individuals_for_money",
    "epfo":           "pf_withdrawal_is_completely_free",
}

NO_FEE_POLICIES = {
    "never_charges_registration_fee",
    "never_charges_application_fee",
    "never_charges_joining_or_training_fee",
    "never_requires_processing_fee",
    "fee_paid_by_government",
    "free_for_basic_competitions",
    "never_charges_participation_fee_for_basic",
    "never_requires_fee_for_approval",
    "never_requires_fee_for_recognition",
    "pf_withdrawal_is_completely_free",
    "never_charges_kyc_fee",
    "never_charges_for_transactions",
    "never_charges_joining_fee",
    "never_asks_otp_via_call_or_message",
    "never_contacts_individuals_for_money",
}

# ── Contact Policies ─────────────────────────────────────────────
CONTACT_POLICIES = {
    "sbi": {
        "uses": ["sbi.co.in", "onlinesbi.sbi", "1800-11-2211"],
        "never_uses": ["@gmail.com", "WhatsApp", "Telegram"]
    },
    "hdfc": {
        "uses": ["hdfcbank.com", "1800-202-6161"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "icici": {
        "uses": ["icicibank.com", "1800-1080"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "axis": {
        "uses": ["axisbank.com", "1800-419-5959"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "paytm": {
        "uses": ["paytm.com", "0120-4456-456"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "phonepe": {
        "uses": ["phonepe.com", "080-68727374"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "gpay": {
        "uses": ["pay.google.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "tcs": {
        "uses": ["tcs.com", "nextstep.tcs.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal mobile"]
    },
    "infosys": {
        "uses": ["infosys.com", "infytq.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "wipro": {
        "uses": ["wipro.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal mobile"]
    },
    "nsp": {
        "uses": ["scholarships.gov.in"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "pm_scholarship": {
        "uses": ["scholarships.gov.in", "ksb.gov.in"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "ugc": {
        "uses": ["ugc.ac.in"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "aicte": {
        "uses": ["aicte-india.org"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "internshala": {
        "uses": ["internshala.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "amazon": {
        "uses": ["amazon.jobs", "amazon.in"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "google": {
        "uses": ["google.com", "careers.google.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
    "microsoft": {
        "uses": ["microsoft.com", "careers.microsoft.com"],
        "never_uses": ["@gmail.com", "WhatsApp", "personal number"]
    },
}

# ── Government Scheme Facts ───────────────────────────────────────
GOV_SCHEME_FACTS = {
    "pm_scholarship": {
        "official_site": "scholarships.gov.in",
        "max_monthly":   3000,
        "max_annual":    36000,
        "real_amount":   "Rs.2000-Rs.3000 per month"
    },
    "nsp": {
        "official_site": "scholarships.gov.in",
        "max_monthly":   3500,
        "max_annual":    50000,
        "real_amount":   "Rs.1000-Rs.3500 per month"
    },
    "ugc": {
        "official_site": "ugc.ac.in",
        "max_monthly":   5000,
        "max_annual":    60000
    },
    "aicte": {
        "official_site": "aicte-india.org",
        "max_monthly":   5000,
        "max_annual":    60000
    },
}

# ── Urgency Patterns ─────────────────────────────────────────────
URGENCY_PATTERNS = [
    r"offer expires in \d+",
    r"limited seats",
    r"only \d+ slots",
    r"act now",
    r"expires today",
    r"last chance",
    r"confirm immediately",
    r"within \d+ hours",
    r"valid today only",
    r"don.t miss",
]

# ── Impersonation Signals ────────────────────────────────────────
IMPERSONATION_SIGNALS = [
    r"hr.*department.*gmail",
    r"recruitment.*gmail",
    r"official.*whatsapp",
    r"government.*whatsapp",
    r"bank.*whatsapp",
]

# ── Scam Templates ───────────────────────────────────────────────
SCAM_TEMPLATES = [
    r"selected.*without.*interview",
    r"no.*interview.*required",
    r"direct.*selection",
    r"guaranteed.*job",
    r"100.*percent.*placement",
    r"earn.*per.*like",
    r"per.*like.*earn",
    r"work.*from.*home.*\d+.*per.*day",
    r"advance.*payment.*only",
    r"refundable.*deposit.*\d+",
    r"security.*deposit.*\d+",
    r"registration.*fee.*\d+",
    r"activation.*fee.*\d+",
]

# ── Legitimate Ranges ────────────────────────────────────────────
LEGITIMATE_RANGES = {
    "internship_stipend":  (2000,   80000),
    "fresher_salary":      (15000, 200000),
    "wfh_daily_earning":   (200,     2000),
    "scholarship_monthly": (500,     5000),
}


# ═════════════════════════════════════════════════════════════════
class CampusChecker:
    """Campus-specific expert rule engine with 7 checks."""

    def analyze(self, text: str) -> Dict[str, Any]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        # ── Spoof check FIRST ─────────────────────────────────
        # If spoof detected, score starts at 85-95 immediately
        s, r, v, e = self._check_spoofed_brands(text)
        spoof_detected = s > 0
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        # ── All other checks run on ORIGINAL text ─────────────
        s, r, v, e = self._check_fee_policy(text)
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        s, r, v, e = self._check_contact_policy(text)
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        s, r, v, e = self._check_process_sequence(text)
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        s, r, v, e = self._check_gov_scheme(text)
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        s, r, v, e = self._check_urgency_patterns(text)
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        s, r, v, e = self._check_scam_templates(text)
        score += s
        reasons.extend(r)
        violations.extend(v)
        entities_found.extend(e)

        # ── If spoof detected, floor score at 85 ──────────────
        # Prevents safe signals from pulling score below 85
        if spoof_detected:
            score = max(score, 85.0)

        score          = max(0.0, min(100.0, score))
        reasons        = list(dict.fromkeys(reasons))[:5]
        violations     = list(dict.fromkeys(violations))
        entities_found = list(dict.fromkeys(entities_found))

        return {
            "score":          score,
            "reasons":        reasons,
            "violations":     violations,
            "entities_found": entities_found
        }

    def _check_spoofed_brands(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        """
        Detect visual brand spoofing.
        g00gle / gooogle / payтm = GUARANTEED SCAM score 85-95.

        DESIGN RULE:
        - get_spoof_score() handles ALL score logic internally
        - This method just calls it and passes results through
        - We do NOT re-run safety checks on normalized text
        - Safe signals are NOT applied when spoof is detected
        """
        spoof_score, spoof_reasons = get_spoof_score(text)

        if spoof_score == 0:
            return 0.0, [], [], []

        violations     = ["spoofed_brand_name"]
        entities_found = []

        spoofs = find_spoofed_brands(text)
        for spoof in spoofs:
            entities_found.append(f"spoofed:{spoof['matched_brand']}")

        return spoof_score, spoof_reasons, violations, entities_found

    def _check_fee_policy(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        amounts = re.findall(
            r"rs\.?\s*[\d,]+|₹\s*[\d,]+", text, re.IGNORECASE
        )
        amounts = list(dict.fromkeys(amounts))

        fee_keywords = [
            "registration fee", "joining fee", "security deposit",
            "processing fee", "verification fee", "activation fee",
            "training fee", "kit charges", "documentation fee",
            "panjikaran shulk", "fee bhejo", "paisa bhejo",
            "refundable deposit", "courier charges",
        ]

        for keyword in fee_keywords:
            if re.search(keyword, text, re.IGNORECASE):
                matched_entity = False
                for entity, policy in FEE_POLICIES.items():
                    if re.search(
                        rf"\b{re.escape(entity)}\b", text, re.IGNORECASE
                    ):
                        if policy in NO_FEE_POLICIES:
                            score          += 40
                            reasons.append(
                                f"{entity.title()} never charges "
                                f"registration fee"
                            )
                            violations.append(f"fee_policy:{entity}")
                            entities_found.append(entity)
                            matched_entity = True
                            break
                if not matched_entity:
                    score += 35
                    reasons.append("Message contains fee demand")
                    violations.append("generic_fee")

        for entity, facts in GOV_SCHEME_FACTS.items():
            entity_pattern = entity.replace("_", ".*")
            if re.search(
                rf"\b{entity_pattern}\b", text, re.IGNORECASE
            ):
                max_monthly = facts.get("max_monthly", 99999)
                for amount in amounts:
                    num = re.search(r"[\d,]+", amount)
                    if num:
                        value = int(num.group().replace(",", ""))
                        if value > max_monthly * 2:
                            score += 30
                            reasons.append(
                                f"{entity.title()} scholarship max is "
                                f"Rs.{max_monthly}/month. "
                                f"Claimed Rs.{value} is suspicious"
                            )
                            violations.append(f"amount_exceeds:{entity}")
                            entities_found.append(entity)
                            break

        return score, reasons, violations, entities_found

    def _check_contact_policy(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        emails = re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text
        )
        emails = list(dict.fromkeys(emails))

        phones = re.findall(r"\b[6-9]\d{9}\b", text)

        urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", text)

        for entity, policy in CONTACT_POLICIES.items():
            if re.search(
                rf"\b{re.escape(entity)}\b", text, re.IGNORECASE
            ):
                for email in emails:
                    if (
                        email.endswith("@gmail.com")
                        or email.endswith("@yahoo.com")
                        or email.endswith("@hotmail.com")
                    ):
                        score += 45
                        reasons.append(
                            f"Real {entity.upper()} never uses Gmail — "
                            f"official email must end in @{entity}.com"
                        )
                        violations.append(
                            f"contact_mismatch:{entity}:email"
                        )
                        entities_found.append(entity)
                        break

                if phones and entity in [
                    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
                    "internshala", "tcs", "infosys", "wipro", "cognizant",
                    "accenture", "amazon", "google", "microsoft"
                ]:
                    score += 35
                    reasons.append(
                        f"Real {entity.upper()} never contacts via "
                        f"personal mobile number"
                    )
                    violations.append(
                        f"contact_mismatch:{entity}:phone"
                    )
                    entities_found.append(entity)

                for url in urls:
                    dm = re.search(
                        r"(?:https?://)?(?:www\.)?"
                        r"([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})",
                        url
                    )
                    if dm:
                        domain   = dm.group(1).lower()
                        official = policy["uses"]
                        if not any(
                            domain == u or domain.endswith("." + u)
                            for u in official
                        ):
                            score += 30
                            reasons.append(
                                f"Real {entity.upper()} uses "
                                f"official domains only"
                            )
                            violations.append(
                                f"contact_mismatch:{entity}:url"
                            )
                            entities_found.append(entity)
                            break

        for pattern in IMPERSONATION_SIGNALS:
            if re.search(pattern, text, re.IGNORECASE):
                score += 30
                reasons.append(
                    "Official HR/government bodies never contact "
                    "via Gmail or WhatsApp"
                )
                violations.append("impersonation_signal")
                break

        professional_keywords = [
            "hr", "recruitment", "hiring", "internship", "job",
            "offer", "selected", "appointment", "joining", "company"
        ]
        if re.search(r"@gmail\.com", text, re.IGNORECASE):
            for keyword in professional_keywords:
                if re.search(
                    rf"\b{keyword}\b", text, re.IGNORECASE
                ):
                    score += 40
                    reasons.append(
                        "Professional recruitment emails never use "
                        "Gmail — real companies use official domain emails"
                    )
                    violations.append("contact_mismatch:generic:gmail")
                    break

        return score, reasons, violations, entities_found

    def _check_process_sequence(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        text_lower = text.lower()

        if re.search(
            r"selected.*pay.*fee|pay.*fee.*selected", text_lower
        ):
            score += 35
            reasons.append(
                "Real internships/jobs interview BEFORE selecting. "
                "Selection before interview = scam"
            )
            violations.append(
                "process_sequence:selection_before_interview"
            )
            entities_found.extend(["internship", "job"])

        if re.search(
            r"pay.*fee.*confirm|fee.*confirm.*offer", text_lower
        ):
            score += 30
            reasons.append(
                "Real companies NEVER ask for fee to confirm offer. "
                "Fee before joining = scam"
            )
            violations.append("process_sequence:fee_before_joining")
            entities_found.extend(["internship", "job"])

        if re.search(r"kyc.*whatsapp|whatsapp.*kyc", text_lower):
            score += 40
            reasons.append(
                "Real banks NEVER ask for KYC via WhatsApp. "
                "KYC via WhatsApp = scam"
            )
            violations.append("process_sequence:kyc_via_whatsapp")
            entities_found.append("bank")

        if re.search(
            r"shar(e|ing).*otp|send.*otp|otp.*shar|otp.*send"
            r"|otp.*batao|otp.*bhejo|verify.*otp",
            text_lower
        ):
            score += 45
            reasons.append(
                "Real banks NEVER ask for OTP via message/call. "
                "OTP sharing = scam"
            )
            violations.append("process_sequence:otp_sharing")
            entities_found.append("bank")

        if re.search(
            r"directly.*selected|selected.*directly"
            r"|without.*applying|no.*interview.*required",
            text_lower
        ):
            score += 30
            reasons.append(
                "Legitimate companies NEVER select without "
                "application/interview"
            )
            violations.append("process_sequence:direct_selection")
            entities_found.extend(["job", "internship"])

        if re.search(
            r"share.*password|password.*share"
            r"|send.*password|password.*bhejo",
            text_lower
        ):
            score += 50
            reasons.append(
                "No legitimate service ever asks for your password. "
                "Password request = scam"
            )
            violations.append("process_sequence:password_sharing")
            entities_found.append("account")

        if re.search(
            r"(aadhar|aadhaar|pan card|pan number).*send"
            r"|(send|share|whatsapp).*(aadhar|aadhaar|pan)",
            text_lower
        ):
            score += 35
            reasons.append(
                "Never share Aadhar/PAN via WhatsApp — "
                "high identity theft risk"
            )
            violations.append(
                "process_sequence:id_sharing_via_message"
            )
            entities_found.append("identity")

        return score, reasons, violations, entities_found

    def _check_gov_scheme(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        text_lower = text.lower()

        for entity, facts in GOV_SCHEME_FACTS.items():
            entity_pattern = entity.replace("_", ".*")
            if not re.search(
                rf"\b{entity_pattern}\b", text_lower, re.IGNORECASE
            ):
                continue

            max_monthly = facts.get("max_monthly", 99999)

            if re.search(
                r"\bfee\b|pay|processing|charge|deposit", text_lower
            ):
                score += 40
                reasons.append(
                    f"Real {entity.upper()} scholarship never charges "
                    f"fee. Processing fee = scam"
                )
                violations.append(f"gov_scheme:{entity}:fee")
                entities_found.append(entity)

            amounts = re.findall(
                r"rs\.?\s*[\d,]+|₹\s*[\d,]+", text, re.IGNORECASE
            )
            for amount in amounts:
                num = re.search(r"[\d,]+", amount)
                if num:
                    value = int(num.group().replace(",", ""))
                    if value > max_monthly * 2:
                        score += 35
                        reasons.append(
                            f"{entity.upper()} scholarship max is "
                            f"Rs.{max_monthly}/month. "
                            f"Claimed Rs.{value} is suspicious"
                        )
                        violations.append(f"gov_scheme:{entity}:amount")
                        entities_found.append(entity)
                        break

            if re.search(r"whatsapp", text_lower):
                score += 30
                reasons.append(
                    f"Real {entity.upper()} never contacts via WhatsApp"
                )
                violations.append(f"gov_scheme:{entity}:whatsapp")
                entities_found.append(entity)

            if re.search(r"@gmail\.com|@yahoo\.com", text_lower):
                score += 35
                reasons.append(
                    f"Real {entity.upper()} only uses official "
                    f"government email (.gov.in)"
                )
                violations.append(f"gov_scheme:{entity}:gmail")
                entities_found.append(entity)

        return score, reasons, violations, entities_found

    def _check_urgency_patterns(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        matched = []
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matched.append(pattern)

        if len(matched) >= 2:
            score += 20
            reasons.append(
                "Multiple urgency tactics detected — scammers use "
                "time pressure to prevent thinking"
            )
            violations.append("urgency:multiple_tactics")
        elif len(matched) == 1:
            score += 10
            reasons.append(
                "Urgency language detected — a common scam pressure tactic"
            )
            violations.append("urgency:single_tactic")

        if text.count("!") >= 3:
            score += 10
            reasons.append(
                "Excessive exclamation marks indicate panic-inducing "
                "scam messaging"
            )
            violations.append("urgency:excessive_punctuation")

        caps_words  = re.findall(r"\b[A-Z]{4,}\b", text)
        unique_caps = list(set(caps_words))
        if len(unique_caps) >= 2:
            score += 10
            reasons.append(
                f"All-caps shouting detected "
                f"({', '.join(unique_caps[:3])}) — pressure tactic"
            )
            violations.append("urgency:all_caps")

        return score, reasons, violations, entities_found

    def _check_scam_templates(
        self, text: str
    ) -> Tuple[float, List[str], List[str], List[str]]:
        score          = 0.0
        reasons        = []
        violations     = []
        entities_found = []

        text_lower        = text.lower()
        matched_templates = []

        for template in SCAM_TEMPLATES:
            if re.search(template, text_lower):
                matched_templates.append(template)

        if matched_templates:
            score += min(len(matched_templates) * 20, 60)
            reasons.append(
                f"Message matches {len(matched_templates)} known "
                f"scam template pattern(s)"
            )
            violations.append(
                f"scam_template:{len(matched_templates)}_matches"
            )

        if re.search(
            r"(like|subscribe|follow).*earn|earn.*(like|subscribe|follow)",
            text_lower
        ):
            score += 35
            reasons.append(
                "Tasks like 'like videos to earn money' are a "
                "well-known online scam"
            )
            violations.append("scam_template:like_to_earn")
            entities_found.append("online_task_scam")

        if re.search(
            r"lucky draw|lottery|won.*prize|prize.*won", text_lower
        ):
            score += 40
            reasons.append(
                "Lucky draw/lottery you never entered = guaranteed scam"
            )
            violations.append("scam_template:lottery")
            entities_found.append("lottery_scam")

        if re.search(
            r"\d+x.*return|\d+.*percent.*return"
            r"|triple.*money|double.*money",
            text_lower
        ):
            score += 45
            reasons.append(
                "Guaranteed investment returns are illegal and a "
                "textbook financial scam"
            )
            violations.append("scam_template:investment_fraud")
            entities_found.append("investment_scam")

        return score, reasons, violations, entities_found

    def get_triggered_rules(self, text: str) -> List[Dict[str, Any]]:
        triggered = []
        checks = [
            (self._check_spoofed_brands,   "spoofed_brands"),
            (self._check_fee_policy,       "fee_policy"),
            (self._check_contact_policy,   "contact_policy"),
            (self._check_process_sequence, "process_sequence"),
            (self._check_gov_scheme,       "gov_scheme"),
            (self._check_urgency_patterns, "urgency"),
            (self._check_scam_templates,   "scam_template"),
        ]
        for method, rule_name in checks:
            s, r, v, e = method(text)
            for reason in r:
                triggered.append({
                    "rule":       rule_name,
                    "reason":     reason,
                    "score":      s,
                    "violations": v,
                    "entities":   e,
                })
        return triggered

    def get_entity_info(self, entity: str) -> Dict[str, Any]:
        info = {}
        if entity in FEE_POLICIES:
            info["fee_policy"] = FEE_POLICIES[entity]
        if entity in CONTACT_POLICIES:
            info["official_channels"] = CONTACT_POLICIES[entity]["uses"]
            info["never_uses"]        = CONTACT_POLICIES[entity]["never_uses"]
        if entity in GOV_SCHEME_FACTS:
            info["scheme_facts"] = GOV_SCHEME_FACTS[entity]
        return info


# ── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    checker = CampusChecker()

    tests = [
        (
            "Pay Rs.2000 to g00gle hr@g00gle.com",
            "SCAM"
        ),
        (
            "Internship at gooogle.com pay fee 9876543210",
            "SCAM"
        ),
        (
            "payтm 9876543210 send Rs.1500 registration fee",
            "SCAM"
        ),
        (
            "Congratulations! You have been selected for internship "
            "at Internshala partner company. Pay Rs.1500 registration "
            "fee on Paytm 9876543210 to confirm your slot. "
            "Offer expires in 24 hours.",
            "SCAM"
        ),
        (
            "Your application for Google Summer of Code 2024 has "
            "been received. Results will be announced on official "
            "website gsoc.google.com",
            "SAFE"
        ),
        (
            "TCS NextStep interview scheduled for Thursday 10AM. "
            "Venue: TCS office Bangalore. Carry college ID and resume. "
            "No charges applicable.",
            "SAFE"
        ),
        (
            "SBI account will be blocked. Verify your KYC immediately "
            "by sharing OTP sent to your number. Call 9988001122 urgently.",
            "SCAM"
        ),
    ]

    print("Campus Checker Test Results:")
    print("=" * 70)

    for text, expected in tests:
        result = checker.analyze(text)
        score  = result["score"]
        label  = (
            "SCAM"            if score >= 70
            else "SUSPICIOUS" if score >= 40
            else "SAFE"
        )
        status = "✅" if label == expected else "❌"
        print(f"\n{status} Expected: {expected} | Got: {label} | Score: {score:.1f}")
        print(f"   Text: {text[:65]}...")
        print(f"   Violations: {result['violations'][:3]}")
        print(f"   Reasons:    {result['reasons'][:2]}")