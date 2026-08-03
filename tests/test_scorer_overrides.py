# tests/test_scorer_overrides.py
"""
Tests for the threat-intel override rules in core/scorer.py's
_apply_overrides(). These protect the specific behavior: a confirmed
VirusTotal (2+ vendors) or Google Safe Browsing hit should force a
high score rather than being averaged down by the other 3 engines —
this was added after live testing showed a Safe-Browsing-confirmed
malware URL still scoring as "SAFE" overall before this fix.
"""
import pytest

from core.scorer import FraudScorer


@pytest.fixture
def scorer():
    return FraudScorer()


def test_safe_browsing_hit_forces_high_score(scorer):
    score, override = scorer._apply_overrides(
        weighted_score=20.0,  # what the weighted average alone would give
        rules_score=0.0,
        campus_score=0.0,
        domain_score=88.0,
        violations=[],
        domain_reasons=["🚨 Google Safe Browsing: URL matches known Malware database"],
    )
    assert score >= 90.0
    assert override is not None and "Safe Browsing" in override


def test_virustotal_two_plus_vendors_forces_high_score(scorer):
    score, override = scorer._apply_overrides(
        weighted_score=25.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=48.0,
        violations=[],
        domain_reasons=["🚨 VirusTotal: 15 security vendor(s) flagged 'x.com' as malicious"],
    )
    assert score >= 85.0
    assert override is not None and "VirusTotal" in override


def test_virustotal_single_vendor_does_not_force_override(scorer):
    """
    A single VirusTotal vendor flagging something is more prone to
    being a one-off false positive — intentionally NOT an override,
    stays as an ordinary weighted signal instead.
    """
    score, override = scorer._apply_overrides(
        weighted_score=25.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=48.0,
        violations=[],
        domain_reasons=["🚨 VirusTotal: 1 security vendor(s) flagged 'x.com' as malicious"],
    )
    assert score == 25.0
    assert override is None


def test_no_threat_intel_reasons_falls_through_normally(scorer):
    """Sanity check: with no threat-intel signal at all, existing override logic is untouched."""
    score, override = scorer._apply_overrides(
        weighted_score=10.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=0.0,
        violations=[],
        domain_reasons=[],
    )
    assert score == 10.0
    assert override is None


def test_otp_override_still_works_alongside_new_rules(scorer):
    """The pre-existing OTP override must still work after this change."""
    score, override = scorer._apply_overrides(
        weighted_score=30.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=0.0,
        violations=["otp_share_request"],
        domain_reasons=[],
    )
    assert score == 92.0
    assert "OTP" in override


# ── FAISS history override ─────────────────────────────────────────
def test_near_identical_scam_history_match_forces_high_score(scorer):
    score, override = scorer._apply_overrides(
        weighted_score=15.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=0.0,
        violations=[],
        domain_reasons=[],
        history_matches=[
            {"similarity": 0.95, "label": 1, "category": "lottery_prize", "times_reported": 6},
        ],
    )
    assert score >= 80.0
    assert override is not None and "lottery_prize" in override


def test_high_similarity_safe_history_match_does_not_force_safe(scorer):
    """
    A high-similarity match to a message previously marked SAFE must
    NOT force the verdict toward safe — only scam-labeled matches get
    override power, to keep the false-negative-averse philosophy
    (escalate readily, never suppress based on a "looks safe" match).
    """
    score, override = scorer._apply_overrides(
        weighted_score=15.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=0.0,
        violations=[],
        domain_reasons=[],
        history_matches=[
            {"similarity": 0.98, "label": 0, "category": "safe", "times_reported": 3},
        ],
    )
    assert score == 15.0
    assert override is None


def test_moderate_similarity_scam_match_does_not_force_override(scorer):
    """Below the 90% threshold, history stays an ordinary weighted signal."""
    score, override = scorer._apply_overrides(
        weighted_score=15.0,
        rules_score=0.0,
        campus_score=0.0,
        domain_score=0.0,
        violations=[],
        domain_reasons=[],
        history_matches=[
            {"similarity": 0.70, "label": 1, "category": "lottery_prize", "times_reported": 6},
        ],
    )
    assert score == 15.0
    assert override is None


# ── Broadened conflict detection + SAFE-escalation ─────────────────
class _StubEngine:
    """Stand-in for rules_engine/domain_checker/campus_checker with a fixed score."""
    def __init__(self, score, reasons=None, violations=None, extractions=None, entities_found=None):
        self._result = {
            "score": score,
            "reasons": reasons or [],
            "violations": violations or [],
            "extractions": extractions or {},
            "entities_found": entities_found or [],
            "flags": [],
            "domains": [],
        }

    def analyze(self, text):
        return dict(self._result)


def test_domain_vs_history_conflict_is_now_detected(scorer):
    """
    Previously conflict detection ONLY compared rules vs ml — a
    domain-vs-history disagreement (exactly what happened in real
    testing: domain flagged via threat-intel, history said safe)
    could go completely undetected. This locks in the fix.
    """
    scorer.rules_engine = _StubEngine(score=0.0)
    scorer.domain_checker = _StubEngine(score=90.0)  # e.g. threat-intel hit
    scorer.campus_checker = _StubEngine(score=0.0)

    result = scorer.calculate(
        text="some message",
        ml_score=10.0,
        history_score=0.0,  # domain (90) vs history (0) = 90 apart
    )
    assert result["conflict_detected"] is True
    assert "domain" in result["conflict_message"] and "history" in result["conflict_message"]


def test_conflicted_verdict_never_silently_resolves_to_safe(scorer):
    """
    The core fix: if the numeric average alone would land on SAFE but
    the engines genuinely disagree, the label must be escalated to at
    least SUSPICIOUS rather than quietly staying SAFE.
    """
    scorer.rules_engine = _StubEngine(score=0.0)
    scorer.domain_checker = _StubEngine(score=95.0)  # very high
    scorer.campus_checker = _StubEngine(score=0.0)

    # Weighted average: 0*0.35 + 95*0.30 + ml*0.20 + history*0.15
    # With ml/history both low, the average lands well under the SCAM
    # threshold but domain vs the others is a >45 point conflict.
    result = scorer.calculate(text="some message", ml_score=5.0, history_score=0.0)

    assert result["conflict_detected"] is True
    assert result["label"] != "SAFE", (
        "A conflicted verdict must never silently resolve to SAFE — "
        f"got label={result['label']!r} with final_score={result['final_score']}"
    )
    assert "escalated" in result["conflict_message"].lower()


def test_no_conflict_when_engines_agree(scorer):
    """Sanity check: engines broadly agreeing should NOT trigger a false conflict."""
    scorer.rules_engine = _StubEngine(score=10.0)
    scorer.domain_checker = _StubEngine(score=15.0)
    scorer.campus_checker = _StubEngine(score=5.0)

    result = scorer.calculate(text="a normal safe message", ml_score=12.0, history_score=8.0)

    assert result["conflict_detected"] is False
    assert result["label"] == "SAFE"