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