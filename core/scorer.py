# core/scorer.py
# ═════════════════════════════════════════════════════════════════
# Campus Fraud Shield v3 — Hybrid Weighted Scoring Engine
# Combines:
#   • Rules Engine        → 35%
#   • Domain Checker      → 30%
#   • Semantic AI         → 20%
#   • FAISS History       → 15%
#
# Includes:
#   • Override Logic
#   • Conflicted Signal Detection
#   • Explainable Breakdown
#   • Judge-Friendly Formula Output
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

from core.rules_engine import RulesEngine
from core.domain_checker import DomainChecker
from core.campus_checker import CampusChecker


# ────────────────────────────────────────────────────────────────
# Engine Weights
# ────────────────────────────────────────────────────────────────
WEIGHTS = {
    "rules": WEIGHT_RULES,
    "domain": WEIGHT_DOMAIN,
    "ml": WEIGHT_ML,
    "history": WEIGHT_HISTORY,
}


# ────────────────────────────────────────────────────────────────
# Category Display Mapping
# ────────────────────────────────────────────────────────────────
CATEGORY_DISPLAY = {
    "internship_fee": "Fake Internship / Job Fee Fraud",
    "job_fee": "Fake Job / Placement Fee Fraud",
    "scholarship_fee": "Fake Scholarship Fee Fraud",
    "otp_fraud": "OTP / Banking Fraud",
    "lottery_prize": "Lottery / Prize Scam",
    "parttime_job": "Part-Time Earnings Scam",
    "bank_impersonation": "Bank Impersonation Scam",
    "gov_scheme_fraud": "Government Scheme Fraud",
    "unknown_scam": "General Scam Pattern",
    "suspicious": "Suspicious Message",
    "safe": "Legitimate Message",
}


# ═════════════════════════════════════════════════════════════════
# FraudScorer
# ═════════════════════════════════════════════════════════════════
class FraudScorer:
    """
    Master scoring engine for Campus Fraud Shield.

    Final weighted formula:
        Rules 35%
        Domain 30%
        ML 20%
        History 15%
    """

    def __init__(self):
        self.rules_engine = RulesEngine()
        self.domain_checker = DomainChecker()
        self.campus_checker = CampusChecker()

    # ────────────────────────────────────────────────────────────
    # Main Calculate Function
    # ────────────────────────────────────────────────────────────
    def calculate(
        self,
        text: str,
        ml_score: float = 50.0,
        ml_reason: str = "",
        ml_similar: list = None,
        history_score: float = 0.0,
        history_matches: list = None,
    ) -> Dict[str, Any]:

        if ml_similar is None:
            ml_similar = []

        if history_matches is None:
            history_matches = []

        # ────────────────────────────────────────────────────────
        # Run Engines
        # ────────────────────────────────────────────────────────
        rules_result = self.rules_engine.analyze(text)
        domain_result = self.domain_checker.analyze(text)
        campus_result = self.campus_checker.analyze(text)

        rules_score = float(rules_result["score"])
        domain_score = float(domain_result["score"])
        campus_score = float(campus_result["score"])

        # ────────────────────────────────────────────────────────
        # Hybrid Rule Score
        # ────────────────────────────────────────────────────────
        combined_rules_score = min(
            100.0,
            (rules_score * 0.60) + (campus_score * 0.40)
        )

        # ────────────────────────────────────────────────────────
        # Weighted Formula
        # ────────────────────────────────────────────────────────
        weighted_score = (
            combined_rules_score * WEIGHTS["rules"] +
            domain_score * WEIGHTS["domain"] +
            ml_score * WEIGHTS["ml"] +
            history_score * WEIGHTS["history"]
        )

        # ────────────────────────────────────────────────────────
        # Override Logic
        # ────────────────────────────────────────────────────────
        final_score, override_applied = self._apply_overrides(
            weighted_score=weighted_score,
            rules_score=rules_score,
            campus_score=campus_score,
            domain_score=domain_score,
            violations=campus_result.get("violations", [])
        )

        # ────────────────────────────────────────────────────────
        # Conflicted Signal Detection
        # ────────────────────────────────────────────────────────
        conflict_detected = abs(rules_score - ml_score) > 45

        # ────────────────────────────────────────────────────────
        # Label
        # ────────────────────────────────────────────────────────
        label = self._get_label(final_score)

        # ────────────────────────────────────────────────────────
        # Category
        # ────────────────────────────────────────────────────────
        category = self._get_category(
            rules_result,
            campus_result,
            label
        )

        # ────────────────────────────────────────────────────────
        # Formula Breakdown
        # ────────────────────────────────────────────────────────
        formula = self._build_formula(
            combined_rules_score,
            domain_score,
            ml_score,
            history_score,
            weighted_score,
            final_score,
            override_applied
        )

        # ────────────────────────────────────────────────────────
        # Reasons
        # ────────────────────────────────────────────────────────
        reasons = self._compile_reasons(
            rules_result,
            domain_result,
            campus_result,
            ml_reason,
            label
        )

        # ────────────────────────────────────────────────────────
        # Engine Breakdown
        # ────────────────────────────────────────────────────────
        breakdown = {
            "rules": {
                "score": combined_rules_score,
                "raw_score": rules_score,
                "campus_score": campus_score,
                "weight": WEIGHTS["rules"],
                "reasons": (
                    rules_result.get("reasons", []) +
                    campus_result.get("reasons", [])
                )[:5],
                "flags": rules_result.get("flags", []),
                "violations": campus_result.get("violations", []),
            },

            "domain": {
                "score": domain_score,
                "weight": WEIGHTS["domain"],
                "reasons": domain_result.get("reasons", []),
                "domains": domain_result.get("domains", []),
            },

            "ml": {
                "score": ml_score,
                "weight": WEIGHTS["ml"],
                "reason": ml_reason,
                "similar_examples": ml_similar,
            },

            "history": {
                "score": history_score,
                "weight": WEIGHTS["history"],
                "matches": history_matches,
            }
        }

        return {
            "final_score": round(final_score, 1),
            "label": label,
            "category": category,
            "category_display": CATEGORY_DISPLAY.get(
                category,
                "Unknown Pattern"
            ),
            "reasons": reasons,
            "breakdown": breakdown,
            "formula": formula,
            "override_applied": override_applied,
            "conflict_detected": conflict_detected,
            "conflict_message": (
                "Conflicted Signal Detected — Manual verification recommended."
                if conflict_detected else ""
            ),
            "entities_found": campus_result.get("entities_found", []),
            "extractions": rules_result.get("extractions", {}),
        }

    # ────────────────────────────────────────────────────────────
    # Override Logic
    # ────────────────────────────────────────────────────────────
    def _apply_overrides(
        self,
        weighted_score: float,
        rules_score: float,
        campus_score: float,
        domain_score: float,
        violations: List[str],
    ):

        # OTP always scam
        if any("otp" in v.lower() for v in violations):
            return 92.0, "OTP sharing request detected"

        # Very high rules confidence
        if rules_score >= 90:
            return max(weighted_score, 75.0), (
                f"Rules Engine high confidence ({rules_score:.0f}/100)"
            )

        # Campus expert very high
        if campus_score >= 85:
            return max(weighted_score, 72.0), (
                f"Campus Checker high confidence ({campus_score:.0f}/100)"
            )

        # Both engines moderate
        if rules_score >= 70 and campus_score >= 70:
            return max(weighted_score, 71.0), (
                "Multiple engines agree on scam pattern"
            )

        # Fee + personal payment number
        fee_flag = any("fee" in v.lower() for v in violations)
        phone_flag = any("phone" in v.lower() for v in violations)

        if fee_flag and phone_flag:
            return max(weighted_score, 72.0), (
                "Fee demand with personal payment contact detected"
            )

        # Suspicious domain + high rules
        if domain_score >= 80 and rules_score >= 70:
            return max(weighted_score, 74.0), (
                "Suspicious domain with matching scam language"
            )

        return weighted_score, None

    # ────────────────────────────────────────────────────────────
    # Label Resolver
    # ────────────────────────────────────────────────────────────
    def _get_label(self, score: float) -> str:

        if score >= SCORE_SCAM_THRESHOLD:
            return LABEL_SCAM

        elif score >= SCORE_SUSPICIOUS_THRESHOLD:
            return LABEL_SUSPICIOUS

        return LABEL_SAFE

    # ────────────────────────────────────────────────────────────
    # Scam Category Resolver
    # ────────────────────────────────────────────────────────────
    def _get_category(
        self,
        rules_result: Dict,
        campus_result: Dict,
        label: str,
    ) -> str:

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

        rules_category = rules_result.get("category")

        if rules_category:
            return rules_category

        if label == LABEL_SUSPICIOUS:
            return "suspicious"

        return "unknown_scam"

    # ────────────────────────────────────────────────────────────
    # Formula Builder
    # ────────────────────────────────────────────────────────────
    def _build_formula(
        self,
        combined_rules_score: float,
        domain_score: float,
        ml_score: float,
        history_score: float,
        weighted_score: float,
        final_score: float,
        override_applied: str,
    ) -> str:

        lines = [
            f"Rules Engine   {combined_rules_score:5.1f} × {WEIGHTS['rules']:.2f} = {(combined_rules_score * WEIGHTS['rules']):5.1f}",
            f"Domain Check   {domain_score:5.1f} × {WEIGHTS['domain']:.2f} = {(domain_score * WEIGHTS['domain']):5.1f}",
            f"Semantic AI    {ml_score:5.1f} × {WEIGHTS['ml']:.2f} = {(ml_score * WEIGHTS['ml']):5.1f}",
            f"History FAISS  {history_score:5.1f} × {WEIGHTS['history']:.2f} = {(history_score * WEIGHTS['history']):5.1f}",
            "─" * 52,
            f"Weighted Total                = {weighted_score:5.1f}"
        ]

        if override_applied:
            lines.append(f"Override Applied              = {override_applied}")

        lines.append(f"Final Score                   = {final_score:5.1f}")

        return "\n".join(lines)

    # ────────────────────────────────────────────────────────────
    # Reason Compiler
    # ────────────────────────────────────────────────────────────
    def _compile_reasons(
        self,
        rules_result: Dict,
        domain_result: Dict,
        campus_result: Dict,
        ml_reason: str,
        label: str,
    ) -> List[str]:

        reasons = []

        reasons.extend(campus_result.get("reasons", [])[:2])
        reasons.extend(rules_result.get("reasons", [])[:2])
        reasons.extend(domain_result.get("reasons", [])[:1])

        if ml_reason and ml_reason not in reasons:
            reasons.append(ml_reason)

        if not reasons and label == LABEL_SAFE:
            reasons.append(
                "No suspicious indicators detected"
            )

        if not reasons and label != LABEL_SAFE:
            reasons.append(
                "Multiple weak scam indicators detected"
            )

        return list(dict.fromkeys(reasons))[:6]


# ═════════════════════════════════════════════════════════════════
# Quick Standalone Test
# ═════════════════════════════════════════════════════════════════
if __name__ == "__main__":

    scorer = FraudScorer()

    sample = """
    Congratulations!
    You are selected for TCS internship.
    Pay Rs.1500 registration fee immediately
    to confirm your seat.
    """

    result = scorer.calculate(
        text=sample,
        ml_score=82.0,
        ml_reason="Message structure similar to known internship scams",
        history_score=65.0,
    )

    print("\nCampus Fraud Shield v3")
    print("=" * 60)

    print(f"Score      : {result['final_score']}")
    print(f"Label      : {result['label']}")
    print(f"Category   : {result['category_display']}")

    print("\nReasons:")
    for r in result["reasons"]:
        print(f" - {r}")

    print("\nFormula:")
    print(result["formula"])

    if result["override_applied"]:
        print("\nOverride:")
        print(result["override_applied"])

    if result["conflict_detected"]:
        print("\nWARNING:")
        print(result["conflict_message"])