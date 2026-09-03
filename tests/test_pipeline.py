# tests/test_pipeline.py
"""
Tests for core/pipeline.py's orchestration logic, using the
dependency-injection seam (scorer/ml_clf/history params) instead of
the real ML model — so these run in milliseconds in CI with no
huggingface download and no GPU/CPU-heavy inference.
"""
import time

import core.pipeline as pipeline


class FakeScorer:
    def __init__(self, response=None):
        self._response = response or {
            "final_score": 88.0,
            "label": "SCAM",
            "category": "fake_category",
            "category_display": "Fake Category",
            "reasons": ["fake reason"],
            "breakdown": {},
            "formula": "",
            "override_applied": None,
            "conflict_detected": False,
            "conflict_message": "",
            "entities_found": [],
            "extractions": {},
            # Real scorer.calculate() always includes this — the
            # history-write gate in pipeline.py (see its comment)
            # skips writing a SCAM verdict to history unless
            # confidence is HIGH, specifically to avoid a low-
            # confidence false-SCAM call becoming a future FAISS-
            # override precedent. Fixture defaults to HIGH so
            # existing tests exercise the "normal" write path;
            # see test_pipeline.py's dedicated gate tests below for
            # the LOW/MEDIUM-confidence skip behavior itself.
            "confidence_label": "HIGH",
        }

    def calculate(self, **kwargs):
        return dict(self._response)


class FakeMLClf:
    def predict_proba(self, text):
        return 90.0, "fake ml reason"

    def get_similar_training_examples(self, text, n=3):
        return []


class FakeHistory:
    def __init__(self):
        self.reports = []

    def search_and_explain(self, text, k=5):
        return {"score": 10.0, "matches": []}

    def add_report(self, **kwargs):
        self.reports.append(kwargs)


def test_run_full_pipeline_uses_injected_engines(monkeypatch):
    """
    The whole point of the DI refactor: passing scorer/ml_clf/history
    explicitly must use THOSE, not silently fall back to the real
    cached loaders.
    """
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)

    fake_scorer = FakeScorer()
    fake_history = FakeHistory()

    result = pipeline.run_full_pipeline(
        "any text",
        scorer=fake_scorer,
        ml_clf=FakeMLClf(),
        history=fake_history,
    )

    assert result["label"] == "SCAM"
    assert result["category"] == "fake_category"
    assert result["reasons"] == ["fake reason"]


# ── History self-contamination gate ─────────────────────────────────
# See core/pipeline.py's comment above skip_history_write for the
# full reasoning: scorer.py has a hard override where >=0.90 FAISS
# similarity to a SCAM-labeled history entry forces a future score to
# >=80. Auto-writing every scan's own verdict back into that index
# with no confidence check meant a single low-confidence false SCAM
# call could become a self-reinforcing precedent for future near-
# identical (possibly legitimate) messages.

def test_low_confidence_scam_verdict_is_not_written_to_history(monkeypatch):
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)
    fake_history = FakeHistory()

    result = pipeline.run_full_pipeline(
        "ambiguous text",
        scorer=FakeScorer({
            "final_score": 72.0, "label": "SCAM", "category": "otp_fraud",
            "category_display": "Otp Fraud", "reasons": [], "breakdown": {},
            "formula": "", "override_applied": None, "conflict_detected": True,
            "conflict_message": "", "entities_found": [], "extractions": {},
            "confidence_label": "LOW",
        }),
        ml_clf=FakeMLClf(),
        history=fake_history,
    )

    assert result["label"] == "SCAM"
    assert len(fake_history.reports) == 0, (
        "A LOW-confidence SCAM verdict must NOT be written to history — "
        "it would become a hard-override precedent for future similar text."
    )


def test_high_confidence_scam_verdict_is_written_to_history(monkeypatch):
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)
    fake_history = FakeHistory()

    pipeline.run_full_pipeline(
        "clear cut scam text",
        scorer=FakeScorer({
            "final_score": 95.0, "label": "SCAM", "category": "otp_fraud",
            "category_display": "Otp Fraud", "reasons": [], "breakdown": {},
            "formula": "", "override_applied": "Rules Engine high confidence",
            "conflict_detected": False, "conflict_message": "",
            "entities_found": [], "extractions": {},
            "confidence_label": "HIGH",
        }),
        ml_clf=FakeMLClf(),
        history=fake_history,
    )

    assert len(fake_history.reports) == 1, (
        "A HIGH-confidence SCAM verdict SHOULD still be written to history "
        "— the gate only blocks low/medium-confidence writes."
    )


def test_low_confidence_safe_verdict_is_still_written_to_history(monkeypatch):
    """
    The gate is asymmetric on purpose: SAFE-labeled writes carry no
    equivalent hard-override risk (scorer.py has no "similar-to-a-past-
    SAFE-report" score-suppression path), so they're written regardless
    of confidence — only SCAM verdicts need the confidence gate.
    """
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)
    fake_history = FakeHistory()

    pipeline.run_full_pipeline(
        "borderline safe text",
        scorer=FakeScorer({
            "final_score": 15.0, "label": "SAFE", "category": "unknown",
            "category_display": "Unknown", "reasons": [], "breakdown": {},
            "formula": "", "override_applied": None, "conflict_detected": True,
            "conflict_message": "", "entities_found": [], "extractions": {},
            "confidence_label": "LOW",
        }),
        ml_clf=FakeMLClf(),
        history=fake_history,
    )

    assert len(fake_history.reports) == 1


def test_run_full_pipeline_falls_back_to_simulation_on_engine_error(monkeypatch):
    """
    If an injected engine blows up mid-scan, the pipeline must not
    propagate the exception to the caller — it should fall back to
    the simulation result, with the original error preserved for
    debugging in _fallback_error.
    """
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)

    class BrokenScorer:
        def calculate(self, **kwargs):
            raise RuntimeError("scorer exploded")

    result = pipeline.run_full_pipeline(
        "any text",
        scorer=BrokenScorer(),
        ml_clf=FakeMLClf(),
        history=FakeHistory(),
    )

    assert result["label"] in ("SCAM", "SAFE", "SUSPICIOUS")
    assert "_fallback_error" in result
    assert "scorer exploded" in result["_fallback_error"]


def test_simulation_mode_returns_consistent_shape(monkeypatch):
    """
    _simulate_scan's return shape must match the real pipeline's shape
    (same keys), or callers like the FastAPI response model would
    break whenever the app happens to be in simulation mode.
    """
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", True)

    result = pipeline.run_full_pipeline("You won lottery, share OTP now")

    required_keys = {
        "final_score", "label", "category", "category_display",
        "reasons", "breakdown", "formula", "override_applied",
        "conflict_detected", "conflict_message", "entities_found",
        "extractions", "action",
    }
    missing = required_keys - result.keys()
    assert not missing, f"Simulation result is missing keys the real pipeline provides: {missing}"


def test_get_action_safe_never_raises(monkeypatch):
    """get_action_safe must degrade gracefully, never propagate an exception."""
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)
    monkeypatch.setattr(
        pipeline, "get_action",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=False,
    )

    result = pipeline.get_action_safe(90.0, "otp_fraud", "some text")
    assert "steps" in result
    assert "helpline" in result


# ── ScanCache: real efficiency feature, see core/pipeline.py's docstring ──

def test_scan_cache_hit_returns_stored_result():
    cache = pipeline.ScanCache(maxsize=10, ttl_seconds=3600)
    result = {"final_score": 90.0, "label": "SCAM"}
    cache.set("Pay Rs.500 now", result)

    assert cache.get("Pay Rs.500 now") == result
    assert cache.stats()["hits"] == 1
    assert cache.stats()["misses"] == 0


def test_scan_cache_normalizes_whitespace_and_case():
    """Trivial forwarding differences (extra spaces, ALL CAPS) should still hit."""
    cache = pipeline.ScanCache(maxsize=10, ttl_seconds=3600)
    cache.set("Pay   Rs.500 NOW", {"final_score": 90.0})

    assert cache.get("pay rs.500 now") is not None
    assert cache.get("PAY RS.500 NOW") is not None


def test_scan_cache_miss_on_unseen_text():
    cache = pipeline.ScanCache(maxsize=10, ttl_seconds=3600)
    assert cache.get("never seen this before") is None
    assert cache.stats()["misses"] == 1


def test_scan_cache_expires_after_ttl(monkeypatch):
    cache = pipeline.ScanCache(maxsize=10, ttl_seconds=1)
    cache.set("some scam text", {"final_score": 90.0})

    # Simulate time passing past the TTL without a real sleep.
    fake_now = time.time() + 10
    monkeypatch.setattr(pipeline.time, "time", lambda: fake_now)

    assert cache.get("some scam text") is None


def test_scan_cache_evicts_least_recently_used_when_full():
    cache = pipeline.ScanCache(maxsize=2, ttl_seconds=3600)
    cache.set("text A", {"id": "A"})
    cache.set("text B", {"id": "B"})
    cache.get("text A")  # touch A so B becomes the least-recently-used
    cache.set("text C", {"id": "C"})  # should evict B, not A

    assert cache.get("text A") is not None
    assert cache.get("text B") is None
    assert cache.get("text C") is not None


def test_run_full_pipeline_cache_hit_skips_engines_and_history_write(monkeypatch):
    """
    The actual integration point: a second identical scan through the
    real (non-DI) code path must not re-invoke the engines or write a
    second near-duplicate entry to history — only the cheap
    get_action_safe() call should re-run (for a fresh complaint-text
    timestamp).
    """
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)
    pipeline.clear_scan_cache()

    call_count = {"calculate": 0}

    class CountingScorer:
        def calculate(self, **kwargs):
            call_count["calculate"] += 1
            return {
                "final_score": 88.0, "label": "SCAM", "category": "otp_fraud",
                "category_display": "Otp Fraud", "reasons": [], "breakdown": {},
                "formula": "", "override_applied": None, "conflict_detected": False,
                "conflict_message": "", "entities_found": [], "extractions": {},
                "confidence_label": "HIGH",  # see FakeScorer's comment above
            }

    fake_history = FakeHistory()
    monkeypatch.setattr(pipeline, "load_scorer", lambda: CountingScorer())
    monkeypatch.setattr(pipeline, "load_ml_model", lambda: FakeMLClf())
    monkeypatch.setattr(pipeline, "load_history", lambda: fake_history)

    text = "Share your OTP to claim the prize"
    result1 = pipeline.run_full_pipeline(text)
    result2 = pipeline.run_full_pipeline(text)

    assert call_count["calculate"] == 1  # NOT called twice
    assert len(fake_history.reports) == 1  # NOT written twice
    assert result1["label"] == result2["label"] == "SCAM"
    pipeline.clear_scan_cache()  # don't leak state into other tests


def test_run_full_pipeline_with_injected_engines_bypasses_cache(monkeypatch):
    """
    Dependency-injected calls (tests, or any future caller passing its
    own engines) must NEVER be cached — a test expecting different
    results across calls to the same text shouldn't get a stale hit.
    """
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)
    pipeline.clear_scan_cache()

    call_count = {"calculate": 0}

    class CountingScorer:
        def calculate(self, **kwargs):
            call_count["calculate"] += 1
            return FakeScorer()._response

    pipeline.run_full_pipeline("same text", scorer=CountingScorer(), ml_clf=FakeMLClf(), history=FakeHistory())
    pipeline.run_full_pipeline("same text", scorer=CountingScorer(), ml_clf=FakeMLClf(), history=FakeHistory())

    assert call_count["calculate"] == 2  # both calls actually ran, no caching