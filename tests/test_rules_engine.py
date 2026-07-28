# tests/test_rules_engine.py
"""
Tests for core/rules_engine.py — the pure regex/pattern-based engine.
No ML model, no network calls, no API keys needed: these should run
fast and always pass in CI regardless of environment.
"""
import pytest

from core.rules_engine import RulesEngine


@pytest.fixture
def engine():
    return RulesEngine()


# ── Scam messages that SHOULD score high ──────────────────────────
SCAM_MESSAGES = [
    ("Pay Rs.999 registration fee to confirm your internship slot",
     "internship_fee"),
    ("Share your OTP to claim KBC prize of Rs.25 lakh urgently",
     "otp_fraud"),
    ("Limited seats! Offer expires in 24 hours, act now and pay Rs.500",
     "urgency+fee"),
    ("Congratulations you won lottery, pay processing fee to claim",
     "lottery_prize"),
    ("panjikaran shulk bhejo abhi karo jaldi karo",  # Hinglish fee + urgency
     "hinglish_fee"),
]


@pytest.mark.parametrize("text,category", SCAM_MESSAGES)
def test_scam_messages_score_high(engine, text, category):
    result = engine.analyze(text)
    assert result["score"] > 30, (
        f"Expected a meaningfully elevated score for a {category} scam, "
        f"got {result['score']}. Reasons: {result.get('reasons')}"
    )
    assert result["reasons"], "A high-scoring scam message should always have reasons attached"


# ── Safe messages that SHOULD score low ────────────────────────────
SAFE_MESSAGES = [
    "Your TCS interview is scheduled at nextstep.tcs.com on Monday 10AM. No fee required.",
    "Your Amazon order has been confirmed. Track at amazon.in. No additional charges.",
    "Reminder: Assignment 3 submission deadline extended to Friday, submit via Google Classroom.",
]


@pytest.mark.parametrize("text", SAFE_MESSAGES)
def test_safe_messages_score_low(engine, text):
    result = engine.analyze(text)
    assert result["score"] < 30, (
        f"Expected a low score for a legitimate message, got {result['score']}. "
        f"Reasons: {result.get('reasons')}. This would be a FALSE POSITIVE "
        f"in production — flag and investigate rather than adjust the "
        f"threshold to make this pass."
    )


# ── Explicit safety-signal override ─────────────────────────────────
def test_otp_share_warning_reduces_score(engine):
    """
    'OTP share mat karo' (Hindi for 'don't share your OTP') is a
    *warning against* fraud, not fraud itself — the negative-weighted
    pattern in OTP_PATTERNS exists specifically to avoid a false
    positive here. This test protects that specific design intent.
    """
    result = engine.analyze("Bank ne bola OTP share mat karo kisi ko bhi")
    assert result["score"] < 40


def test_empty_text_does_not_crash(engine):
    result = engine.analyze("")
    assert result["score"] >= 0


def test_analyze_returns_expected_shape(engine):
    result = engine.analyze("Pay Rs.500 registration fee now")
    assert "score" in result
    assert "reasons" in result
    assert isinstance(result["reasons"], list)