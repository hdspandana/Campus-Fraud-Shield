# tests/test_pipeline.py
"""
Tests for core/pipeline.py's orchestration logic, using the
dependency-injection seam (scorer/ml_clf/history params) instead of
the real ML model — so these run in milliseconds in CI with no
huggingface download and no GPU/CPU-heavy inference.
"""
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
    # confirms history.add_report was actually called with the result
    assert len(fake_history.reports) == 1
    assert fake_history.reports[0]["category"] == "fake_category"


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