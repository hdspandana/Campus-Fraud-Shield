# tests/test_domain_checker.py
"""
Tests for core/domain_checker.py, including the threat-intel addition.

Key thing this file protects: when VIRUSTOTAL_KEY / GOOGLE_SAFE_BROWSING_KEY
are empty (the default, and what CI always uses via conftest.py's
autouse fixture), _check_threat_intel must make ZERO network calls and
return (0.0, [], "not_configured"). If this regresses, every CI run and
every local run without keys configured would start hanging/failing on
live HTTP calls.

Also protects the fix for a real bug: _query_virustotal/_query_safe_browsing
used to return the identical (0.0, []) whether a domain was verified clean
OR the API call itself failed. They now return a 3rd `ok` value so those
two genuinely different outcomes are distinguishable downstream.
"""
from unittest.mock import patch, MagicMock

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
    key, rate limit, DNS failure, whatever) — the RISK SCORE must
    fail open (contribute 0 to score) rather than raising and
    crashing the whole scan, or penalizing a domain just because an
    API had an outage. Threat-intel is a bonus signal, never a
    single point of failure for the detector.

    BUT the failure must NOT be indistinguishable from a genuinely
    clean result — that was the actual bug (see test below). The
    `ok` flag exists specifically so a caller can tell "checked and
    clean" apart from "couldn't check."
    """
    monkeypatch.setattr("core.domain_checker.VIRUSTOTAL_KEY", "fake-key-for-test")

    with patch("core.domain_checker.requests.get", side_effect=Exception("network exploded")):
        score, reasons, ok = checker._query_virustotal("some-domain.com")
        assert score == 0.0          # risk score still fails open
        assert reasons == []
        assert ok is False           # but this was NOT a successful check


def test_threat_intel_clean_result_is_distinguishable_from_failure(checker, monkeypatch):
    """
    This is the actual regression test for the bug: a verified-clean
    VirusTotal result and a failed VirusTotal call used to produce the
    exact same (0.0, []) output, making them indistinguishable to
    every downstream consumer (scorer.py's fusion, eventually the UI).
    A clean check and a failed check are different facts and must
    produce different `ok` values even though the score is 0.0 either way.
    """
    monkeypatch.setattr("core.domain_checker.VIRUSTOTAL_KEY", "fake-key-for-test")

    mock_clean_response = MagicMock()
    mock_clean_response.status_code = 200
    mock_clean_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
    }

    with patch("core.domain_checker.requests.get", return_value=mock_clean_response):
        clean_score, clean_reasons, clean_ok = checker._query_virustotal("genuinely-clean.com")

    with patch("core.domain_checker.requests.get", side_effect=Exception("network exploded")):
        failed_score, failed_reasons, failed_ok = checker._query_virustotal("unreachable.com")

    assert clean_score == failed_score == 0.0   # scores happen to match...
    assert clean_ok is True                      # ...but ok must differ
    assert failed_ok is False                     # this is the whole fix


def test_analyze_surfaces_ti_status_when_lookup_fails(checker, monkeypatch):
    """
    End-to-end: analyze()'s returned dict must expose ti_status so
    scorer.py (and eventually the UI) can reduce CONFIDENCE without
    touching the risk score itself when threat-intel couldn't be
    verified.
    """
    monkeypatch.setattr("core.domain_checker.VIRUSTOTAL_KEY", "fake-key-for-test")

    with patch("core.domain_checker.requests.get", side_effect=Exception("network exploded")):
        result = checker.analyze("check http://some-random-domain-xyz123.tk/login now")

    assert result["ti_status"] == "unavailable"
    assert any("did not complete" in r for r in result["reasons"])


# ── Regression test: bare (no http://) shortened URLs ──────────────
# The actual bug: _extract_urls("Claim now: bit.ly/claim2500") == []
# before this fix — none of the 3 original patterns matched a known
# shortener domain typed bare, exactly as it would appear in a real
# forwarded SMS (nobody types "http://" in a text message). This
# meant the entire domain engine (20% weight) contributed ZERO signal
# for one of the most common real scam-link formats.
BARE_SHORTENER_MESSAGES = [
    "Claim your prize now: bit.ly/claim2500 register fast",
    "Click here: rb.gy/xyz123 for details",
    "Check out shorturl.at/abc123 for the form",
    "Limited time offer, go to cutt.ly/scamlink now",
]


@pytest.mark.parametrize("text", BARE_SHORTENER_MESSAGES)
def test_bare_shortener_url_is_extracted_and_scored(checker, text):
    result = checker.analyze(text)
    assert result["score"] > 0, (
        f"Bare shortener URL was invisible to the domain engine: {text!r} "
        f"scored {result['score']}"
    )
    assert any("shortened" in r.lower() for r in result["reasons"])


def test_ordinary_phrase_with_short_cctld_word_not_falsely_extracted(checker):
    """
    Guard against the false-positive risk this fix deliberately avoided:
    matching the LITERAL known shortener domains (a curated list) rather
    than broadening the generic bare-domain pattern's TLD list to include
    every short ccTLD used by shorteners (.at, .to, .gl, etc.) — that
    broader approach would have made ordinary phrases like "look.at" or
    "go.to" get mis-extracted as URLs.
    """
    urls = checker._extract_urls("I will look.at your assignment and get back to you.")
    assert urls == []