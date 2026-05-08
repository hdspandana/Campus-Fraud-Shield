# core/scorer.py
# ═════════════════════════════════════════════════════════════════
# Final Weighted Scoring Engine - Final Version for Hackathon
# ═════════════════════════════════════════════════════════════════

import os
import sys
import re
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from interfaces import (
    WEIGHT_RULES,
    WEIGHT_DOMAIN,
    WEIGHT_ML,
    WEIGHT_HISTORY,
    SCORE_SCAM_THRESHOLD,
    SCORE_SUSPICIOUS_THRESHOLD,
    LABEL_SCAM,
    LABEL_SUSPICIOUS,
    LABEL_SAFE,
)

from core.rules_engine   import RulesEngine
from core.domain_checker import DomainChecker
from core.campus_checker import CampusChecker

# ── Weights ──────────────────────────────────────────────────────
WEIGHTS = {
    "rules":   WEIGHT_RULES,
    "domain":  WEIGHT_DOMAIN,
    "ml":      WEIGHT_ML,
    "history": WEIGHT_HISTORY,
}

# ── Category Display Names ───────────────────────────────────────
CATEGORY_DISPLAY = {
    "internship_fee":     "Fake Internship / Job Fee Fraud",
    "job_fee":            "Fake Job / Placement Fee Fraud",
    "scholarship_fee":    "Fake Scholarship Fee Fraud",
    "otp_fraud":          "OTP / Bank Account Fraud",
    "lottery_prize":      "Fake Lottery / Prize Scam",
    "parttime_job":       "Fake Part-Time Job Scam",
    "bank_impersonation": "Bank Impersonation Fraud",
    "gov_scheme_fraud":   "Fake Government Scheme Fraud",
    "unknown_scam":       "General Scam Pattern",
    "suspicious":         "Suspicious Message",
    "safe":               "Legitimate Message",
}


class FraudScorer:
    def __init__(self):
        self.rules_engine   = RulesEngine()
        self.domain_checker = DomainChecker()
        self.campus_checker = CampusChecker()

    def calculate(
        self,
        text:            str,
        ml_score:        float = 50.0,
        ml_reason:       str   = "",
        ml_similar:      list  = None,
        history_score:   float = 0.0,
        history_matches: list  = None,
    ) -> Dict[str, Any]:
        if ml_similar       is None: ml_similar = []
        if history_matches  is None: history_matches = []

        rules_result  = self.rules_engine.analyze(text)
        domain_result = self.domain_checker.analyze(text)
        campus_result = self.campus_checker.analyze(text)

        rules_score  = float(rules_result["score"])
        domain_score = float(domain_result["score"])
        campus_score = float(campus_result["score"])

        combined_rules_score = min(100.0, rules_score * 0.6 + campus_score * 0.4)

        weighted_score = (
            combined_rules_score * WEIGHTS["rules"]   +
            domain_score         * WEIGHTS["domain"]  +
            ml_score             * WEIGHTS["ml"]      +
            history_score        * WEIGHTS["history"]
        )

        campus_violations = campus_result.get("violations", [])
        final_score, override_applied = self._apply_overrides(
            weighted_score    = weighted_score,
            rules_score       = rules_score,
            campus_score      = campus_score,
            domain_score      = domain_score,
            campus_violations = campus_violations,
        )

        label    = self._get_label(final_score)
        category = self._get_category(rules_result, campus_result, label)

        formula = self._build_formula(
            combined_rules_score = combined_rules_score,
            domain_score         = domain_score,
            ml_score             = ml_score,
            history_score        = history_score,
            weighted_score       = weighted_score,
            final_score          = final_score,
            override_applied     = override_applied,
        )

        all_reasons = self._compile_reasons(
            rules_result  = rules_result,
            domain_result = domain_result,
            campus_result = campus_result,
            ml_reason     = ml_reason,
            label         = label,
        )

        breakdown = {
            "rules":   {"score": combined_rules_score, "weight": WEIGHTS["rules"],   "reasons": (rules_result.get("reasons", []) + campus_result.get("reasons", []))[:5]},
            "domain":  {"score": domain_score,         "weight": WEIGHTS["domain"],  "reasons": domain_result.get("reasons", [])},
            "ml":      {"score": ml_score,             "weight": WEIGHTS["ml"],      "reason":  ml_reason, "similar": ml_similar},
            "history": {"score": history_score,        "weight": WEIGHTS["history"], "matches": history_matches},
        }

        return {
            "final_score":      round(final_score, 1),
            "label":            label,
            "category":         category,
            "category_display": CATEGORY_DISPLAY.get(category, "Unknown Pattern"),
            "reasons":          all_reasons,
            "breakdown":        breakdown,
            "formula":          formula,
            "override_applied": override_applied,
            "entities_found":   campus_result.get("entities_found", []),
        }

    def _apply_overrides(
        self,
        weighted_score:    float,
        rules_score:       float,
        campus_score:      float,
        domain_score:      float,
        campus_violations: List[str],
    ) -> tuple[float, str | None]:
        
        if any("otp_sharing" in v for v in campus_violations):
            return 92.0, "OTP sharing detected — auto-classified as SCAM"

        if rules_score >= 90:
            final = max(weighted_score, 75.0)
            return final, f"Rules engine high confidence ({rules_score:.0f}/100)"

        if campus_score >= 85:
            final = max(weighted_score, 72.0)
            return final, f"Campus expert check high confidence ({campus_score:.0f}/100)"

        if rules_score >= 70 and campus_score >= 70:
            final = max(weighted_score, 71.0)
            return final, "Multiple engines agree: scam pattern detected"

        critical_patterns = ["fee_policy", "process_sequence:otp", "gov_scheme", "scam_template:lottery", "scam_template:investment"]
        has_critical = any(any(c in v for c in critical_patterns) for v in campus_violations)
        if has_critical and campus_score >= 60:
            final = max(weighted_score, 70.0)
            return final, "Critical scam pattern detected"

        fee_violations = [v for v in campus_violations if "fee_policy" in v]
        payment_violations = [v for v in campus_violations if "phone" in v]
        if fee_violations and payment_violations:
            final = max(weighted_score, 72.0)
            return final, "Fee demand with personal payment method detected"

        # NEW DOMAIN OVERRIDES
        if domain_score >= 45:
            final = max(weighted_score, 75.0)
            return final, f"Malicious/suspicious domain detected ({domain_score:.0f}/100)"

        if domain_score >= 30 and (rules_score >= 20 or campus_score >= 20):
            final = max(weighted_score, 70.0)
            return final, "Suspicious domain combined with scam content detected"

        if domain_score >= 50:
            final = max(weighted_score, 78.0)
            return final, "Typosquatting or brand impersonation domain detected"

        return weighted_score, None

    def _get_label(self, score: float) -> str:
        if score >= SCORE_SCAM_THRESHOLD:
            return LABEL_SCAM
        elif score >= SCORE_SUSPICIOUS_THRESHOLD:
            return LABEL_SUSPICIOUS
        else:
            return LABEL_SAFE

    def _get_category(self, rules_result: Dict, campus_result: Dict, label: str) -> str:
        if label == LABEL_SAFE:
            return "safe"

        violations = campus_result.get("violations", [])

        if any("otp" in v for v in violations):
            return "otp_fraud"
        if any("gov_scheme" in v for v in violations):
            return "gov_scheme_fraud"
        if any("lottery" in v for v in violations):
            return "lottery_prize"
        if any("like_to_earn" in v for v in violations):
            return "parttime_job"
        if any("investment" in v for v in violations):
            return "unknown_scam"

        if any(tld in str(violations) for tld in [".xyz", ".tk", "typosquat", "phishing_path", "suspicious_tld", "malicious"]):
            return "bank_impersonation"

        rules_category = rules_result.get("category", "unknown_scam")
        if rules_category and rules_category != "unknown_scam":
            return rules_category

        if label == LABEL_SUSPICIOUS:
            return "suspicious"

        return "unknown_scam"

    def _build_formula(self, combined_rules_score, domain_score, ml_score, history_score, weighted_score, final_score, override_applied):
        lines = [
            f"Rules Engine   {combined_rules_score:5.1f} × {WEIGHTS['rules']:.2f} = {combined_rules_score * WEIGHTS['rules']:5.1f}",
            f"Domain Check   {domain_score:5.1f} × {WEIGHTS['domain']:.2f} = {domain_score * WEIGHTS['domain']:5.1f}",
            f"Semantic AI    {ml_score:5.1f} × {WEIGHTS['ml']:.2f} = {ml_score * WEIGHTS['ml']:5.1f}",
            f"History FAISS  {history_score:5.1f} × {WEIGHTS['history']:.2f} = {history_score * WEIGHTS['history']:5.1f}",
            f"{'─' * 42}",
            f"Weighted Total                = {weighted_score:5.1f}",
        ]
        if override_applied:
            lines.append(f"Override: {override_applied}")
        lines.append(f"Final Score                   = {final_score:5.1f}")
        return "\n".join(lines)

    def _compile_reasons(self, rules_result, domain_result, campus_result, ml_reason, label):
        all_reasons = []
        all_reasons.extend(campus_result.get("reasons", [])[:2])
        all_reasons.extend(rules_result.get("reasons", [])[:2])
        all_reasons.extend(domain_result.get("reasons", [])[:1])

        if ml_reason and ml_reason not in all_reasons:
            all_reasons.append(ml_reason)

        if not all_reasons and label != LABEL_SAFE:
            all_reasons.append("Multiple weak signals detected across analysis engines")

        if label == LABEL_SAFE and not all_reasons:
            all_reasons.append("No suspicious patterns detected — message appears legitimate")

        return list(dict.fromkeys(all_reasons))[:6]


if __name__ == "__main__":
    scorer = FraudScorer()
    print("Scorer loaded successfully.")