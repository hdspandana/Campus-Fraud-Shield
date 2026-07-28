# tests/test_domain_checker.py
"""
Tests for core/domain_checker.py, including the threat-intel addition.

Key thing this file protects: when VIRUSTOTAL_KEY / GOOGLE_SAFE_BROWSING_KEY
are empty (the default, and what CI always uses via conftest.py's
autouse fixture), _check_threat_intel must make ZERO network calls and
return (0.0, []). If this regresses, every CI run and every local run
without keys configured would start hanging/failing on live HTTP calls.
"""
from unittest.mock import patch

import pytest

from core.domain_checker import DomainChecker


@pytest.fixture
def checker():
    return DomainChecker()


# ── Typosquat / impersonation detection ────────────────────────────
TYPOSQUAT_MESSAGES = [
    "Selected for internship, apply at g00gle.com to confirm",
    "Verify your account at sbi-kyc-verify.xyz immediately",
    "amazon-lucky-winner.xyz you won iPhone pay Rs.299 delivery charge",
]


@pytest.mark.parametrize("text", TYPOSQUAT_MESSAGES)
def test_typosquat_domains_score_high(checker, text):
    result = checker.analyze(text)
    assert result["score"] > 20, (
        f"Expected a known typosquat/impersonation pattern to raise the "
        f"domain score, got {result['score']}"
    )


def test_legitimate_domain_scores_low(checker):
    result = checker.analyze("Visit internshala.com to check your application status")
    assert result["score"] < 20


# ── Threat-intel opt-in behavior (the important one) ───────────────
def test_threat_intel_skipped_with_no_api_keys(checker):
    """
    With no keys configured (the conftest.py autouse fixture forces
    this), _check_threat_intel must short-circuit with zero network
    calls. We patch requests.get/post and assert they're NEVER called.
    """
    with patch("core.domain_checker.requests.get") as mock_get, \
         patch("core.domain_checker.requests.post") as mock_post:

        result = checker.analyze(
            "Check this out http://totally-fake-scam-domain.xyz/claim"
        )

        mock_get.assert_not_called()
        mock_post.assert_not_called()
        assert isinstance(result["score"], (int, float))


def test_threat_intel_fails_open_on_network_error(checker, monkeypatch):
    """
    If a key IS configured but the API call blows up (timeout, bad
    key, rate limit, DNS failure, whatever) — it must fail open
    (contribute 0 score) rather than raising and crashing the whole
    scan. Threat-intel is a bonus signal, never a single point of
    failure for the detector.
    """
    monkeypatch.setattr("core.domain_checker.VIRUSTOTAL_KEY", "fake-key-for-test")

    with patch("core.domain_checker.requests.get", side_effect=Exception("network exploded")):
        score, reasons = checker._query_virustotal("some-domain.com")
        assert score == 0.0
        assert reasons == []