# core/scorer.py
# ═════════════════════════════════════════════════════════════════
# Final Weighted Scoring Engine
# Combines all 4 engines into single score
# Weights: Rules 35% | Domain 30% | ML 20% | History 15%
# Applies override logic for extreme cases
# Returns score + label + full breakdown for judges
# ═════════════════════════════════════════════════════════════════

import os
import sys
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


# ═════════════════════════════════════════════════════════════════
class FraudScorer:
    """
    Final scoring engine combining all detection engines.
    Weights: Rules 35% | Domain 30% | ML 20% | History 15%
    """

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
        """
        Calculate final fraud score combining all engines.

        Args:
            text:            Message text to analyze
            ml_score:        Score from semantic ML model (0-100)
            ml_reason:       Reason from ML model
            ml_similar:      Similar examples from ML model
            history_score:   Score from FAISS history engine (0-100)
            history_matches: Matches from history engine

        Returns:
            Complete result dict with all scores and explanations
        """
        if ml_similar       is None:
            ml_similar      = []
        if history_matches  is None:
            history_matches = []

        # ── Run synchronous engines ───────────────────────────────
        rules_result  = self.rules_engine.analyze(text)
        domain_result = self.domain_checker.analyze(text)
        campus_result = self.campus_checker.analyze(text)

        rules_score  = float(rules_result["score"])
        domain_score = float(domain_result["score"])
        campus_score = float(campus_result["score"])

        # ── Blend campus into rules ───────────────────────────────
        combined_rules_score = min(
            100.0,
            rules_score * 0.6 + campus_score * 0.4
        )

        # ── Weighted formula ──────────────────────────────────────
        weighted_score = (
            combined_rules_score * WEIGHTS["rules"]   +
            domain_score         * WEIGHTS["domain"]  +
            ml_score             * WEIGHTS["ml"]      +
            history_score        * WEIGHTS["history"]
        )

        # ── Override logic ────────────────────────────────────────
        campus_violations = campus_result.get("violations", [])
        final_score, override_applied = self._apply_overrides(
            weighted_score    = weighted_score,
            rules_score       = rules_score,
            campus_score      = campus_score,
            domain_score      = domain_score,
            campus_violations = campus_violations,
        )

        # ── Label and category ────────────────────────────────────
        label    = self._get_label(final_score)
        category = self._get_category(
            rules_result, campus_result, label
        )

        # ── Formula string ────────────────────────────────────────
        formula = self._build_formula(
            combined_rules_score = combined_rules_score,
            domain_score         = domain_score,
            ml_score             = ml_score,
            history_score        = history_score,
            weighted_score       = weighted_score,
            final_score          = final_score,
            override_applied     = override_applied,
        )

        # ── All reasons ───────────────────────────────────────────
        all_reasons = self._compile_reasons(
            rules_result  = rules_result,
            domain_result = domain_result,
            campus_result = campus_result,
            ml_reason     = ml_reason,
            label         = label,
        )

        # ── Full breakdown ────────────────────────────────────────
        breakdown = {
            "rules": {
                "score":      combined_rules_score,
                "raw":        rules_score,
                "campus":     campus_score,
                "weight":     WEIGHTS["rules"],
                "reasons":    (
                    rules_result.get("reasons", []) +
                    campus_result.get("reasons", [])
                )[:5],
                "flags":      rules_result.get("flags", []),
                "violations": campus_violations,
                "extractions": rules_result.get("extractions", {}),
            },
            "domain": {
                "score":   domain_score,
                "weight":  WEIGHTS["domain"],
                "reasons": domain_result.get("reasons", []),
                "domains": domain_result.get("domains", []),
            },
            "ml": {
                "score":   ml_score,
                "weight":  WEIGHTS["ml"],
                "reason":  ml_reason,
                "similar": ml_similar,
            },
            "history": {
                "score":   history_score,
                "weight":  WEIGHTS["history"],
                "matches": history_matches,
            },
        }

        return {
            "final_score":      round(final_score, 1),
            "label":            label,
            "category":         category,
            "category_display": CATEGORY_DISPLAY.get(
                category, "Unknown Pattern"
            ),
            "reasons":          all_reasons,
            "breakdown":        breakdown,
            "formula":          formula,
            "override_applied": override_applied,
            "entities_found":   campus_result.get("entities_found", []),
            "extractions":      rules_result.get("extractions", {}),
        }

    def _apply_overrides(
        self,
        weighted_score:    float,
        rules_score:       float,
        campus_score:      float,
        domain_score:      float,
        campus_violations: List[str],
    ):
        """
        Apply override logic for extreme cases.

        Returns:
            tuple: (final_score, override_description or None)
        """
        # Override 1: OTP sharing → always SCAM
        if any("otp_sharing" in v for v in campus_violations):
            return 92.0, "OTP sharing detected — auto-classified as SCAM"

        # Override 2: Rules engine very high → force SCAM range
        if rules_score >= 90:
            final = max(weighted_score, 75.0)
            return final, f"Rules engine high confidence ({rules_score:.0f}/100)"

        # Override 3: Campus very high → force SCAM range
        if campus_score >= 85:
            final = max(weighted_score, 72.0)
            return final, (
                f"Campus expert check high confidence "
                f"({campus_score:.0f}/100)"
            )

        # Override 4: Both engines moderate → push to SCAM
        if rules_score >= 70 and campus_score >= 70:
            final = max(weighted_score, 71.0)
            return final, "Multiple engines agree: scam pattern detected"

        # Override 5: Critical campus violations
        critical_patterns = [
            "fee_policy",
            "process_sequence:otp",
            "gov_scheme",
            "scam_template:lottery",
            "scam_template:investment",
        ]
        has_critical = any(
            any(c in v for c in critical_patterns)
            for v in campus_violations
        )
        if has_critical and campus_score >= 60:
            final = max(weighted_score, 70.0)
            return final, "Critical scam pattern detected"

        # Override 6: Fee demand + payment method → SCAM
        fee_violations = [v for v in campus_violations if "fee_policy" in v]
        payment_violations = [v for v in campus_violations if "phone" in v]
        if fee_violations and payment_violations:
            final = max(weighted_score, 72.0)
            return final, "Fee demand with personal payment method detected"

        return weighted_score, None

    def _get_label(self, score: float) -> str:
        """Convert score to risk label."""
        if score >= SCORE_SCAM_THRESHOLD:
            return LABEL_SCAM
        elif score >= SCORE_SUSPICIOUS_THRESHOLD:
            return LABEL_SUSPICIOUS
        else:
            return LABEL_SAFE

    def _get_category(
        self,
        rules_result:  Dict,
        campus_result: Dict,
        label:         str,
    ) -> str:
        """Determine most specific scam category."""
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

        rules_category = rules_result.get("category", "unknown_scam")
        if rules_category and rules_category != "unknown_scam":
            return rules_category

        if label == LABEL_SUSPICIOUS:
            return "suspicious"

        return "unknown_scam"

    def _build_formula(
        self,
        combined_rules_score: float,
        domain_score:         float,
        ml_score:             float,
        history_score:        float,
        weighted_score:       float,
        final_score:          float,
        override_applied:     str,
    ) -> str:
        """Build human-readable formula string for judges."""
        lines = [
            f"Rules Engine   {combined_rules_score:5.1f} "
            f"× {WEIGHTS['rules']:.2f} = "
            f"{combined_rules_score * WEIGHTS['rules']:5.1f}",

            f"Domain Check   {domain_score:5.1f} "
            f"× {WEIGHTS['domain']:.2f} = "
            f"{domain_score * WEIGHTS['domain']:5.1f}",

            f"Semantic AI    {ml_score:5.1f} "
            f"× {WEIGHTS['ml']:.2f} = "
            f"{ml_score * WEIGHTS['ml']:5.1f}",

            f"History FAISS  {history_score:5.1f} "
            f"× {WEIGHTS['history']:.2f} = "
            f"{history_score * WEIGHTS['history']:5.1f}",

            f"{'─' * 42}",
            f"Weighted Total                = {weighted_score:5.1f}",
        ]

        if override_applied:
            lines.append(f"Override: {override_applied}")

        lines.append(f"Final Score                   = {final_score:5.1f}")

        return "\n".join(lines)

    def _compile_reasons(
        self,
        rules_result:  Dict,
        domain_result: Dict,
        campus_result: Dict,
        ml_reason:     str,
        label:         str,
    ) -> List[str]:
        """Compile top reasons from all engines."""
        all_reasons = []

        all_reasons.extend(campus_result.get("reasons", [])[:2])
        all_reasons.extend(rules_result.get("reasons", [])[:2])
        all_reasons.extend(domain_result.get("reasons", [])[:1])

        if ml_reason and ml_reason not in all_reasons:
            all_reasons.append(ml_reason)

        if not all_reasons and label != LABEL_SAFE:
            all_reasons.append(
                "Multiple weak signals detected across analysis engines"
            )

        if label == LABEL_SAFE and not all_reasons:
            all_reasons.append(
                "No suspicious patterns detected — message appears legitimate"
            )

        return list(dict.fromkeys(all_reasons))[:6]


# ── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    scorer = FraudScorer()

    tests = [
        (
            "Congratulations! You have been selected for internship "
            "at Internshala partner company. Pay Rs.1500 registration "
            "fee on Paytm 9876543210 to confirm. Offer expires 24 hours.",
            "SCAM",
            75.0,
            0.0,
        ),
        (
            "Share OTP received on your number to claim KBC prize "
            "of Rs.50000. Contact kbc.prize2024@gmail.com urgently.",
            "SCAM",
            80.0,
            60.0,
        ),
        (
            "TCS NextStep interview scheduled for Thursday 10AM. "
            "Venue: TCS office Bangalore. Carry college ID. "
            "No charges applicable.",
            "SAFE",
            15.0,
            0.0,
        ),
        (
            "NSP Scholarship of Rs.25000 approved. Pay Rs.500 "
            "processing fee to PhonePe 8765432109.",
            "SCAM",
            70.0,
            55.0,
        ),
        (
            "Earn Rs.500 per hour from home. Pay Rs.999 "
            "registration to join. WhatsApp 9123456789.",
            "SCAM",
            65.0,
            40.0,
        ),
    ]

    print("Scorer Test Results:")
    print("=" * 70)

    for text, expected, mock_ml, mock_history in tests:
        result = scorer.calculate(
            text           = text,
            ml_score       = mock_ml,
            ml_reason      = "Semantic pattern match",
            history_score  = mock_history,
        )

        match = "✅" if result["label"] == expected else "❌"
        print(f"\n{match} Text:     {text[:60]}...")
        print(f"   Expected: {expected}")
        print(f"   Score:    {result['final_score']}/100 → {result['label']}")
        print(f"   Category: {result['category_display']}")
        print(f"   Reasons:  {result['reasons'][:2]}")
        print(f"\n   Formula:\n")
        for line in result["formula"].split("\n"):
            print(f"   {line}")
        if result["override_applied"]:
            print(f"\n   Override: {result['override_applied']}")
        print("-" * 70)