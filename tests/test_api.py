# tests/test_api.py
"""
Tests for api.py using FastAPI's dependency_overrides — the exact
mechanism the DI refactor was done to enable. No real ML model gets
loaded, no huggingface download, no network calls: these should run
in well under a second in CI.
"""
import pytest
from fastapi.testclient import TestClient

from api import app, get_scorer, get_ml_clf, get_history


class FakeScorer:
    def calculate(self, **kwargs):
        return {
            "final_score": 91.5,
            "label": "SCAM",
            "category": "otp_fraud",
            "category_display": "Otp Fraud",
            "reasons": ["Real banks never ask for OTP"],
            "breakdown": {"rules": {"score": 90, "weight": 0.35, "reasons": []}},
            "formula": "test formula",
            "override_applied": "OTP sharing detected",
            "conflict_detected": False,
            "conflict_message": "",
            "entities_found": [],
            "extractions": {},
        }


class FakeMLClf:
    def predict_proba(self, text):
        return 88.0, "fake reason"

    def get_similar_training_examples(self, text, n=3):
        return []


class FakeHistory:
    def search_and_explain(self, text, k=5):
        return {"score": 0.0, "matches": []}

    def add_report(self, **kwargs):
        pass


@pytest.fixture
def client(monkeypatch):
    # core.pipeline.run_full_pipeline checks its OWN module-level
    # SIMULATION_MODE (set once at import time, based on whether the
    # real engines imported successfully). Force it False here so this
    # test deterministically exercises the injected fakes via
    # dependency_overrides, rather than depending on whatever state
    # happened to be true when this process started.
    import core.pipeline as pipeline
    monkeypatch.setattr(pipeline, "SIMULATION_MODE", False)

    app.dependency_overrides[get_scorer] = lambda: FakeScorer()
    app.dependency_overrides[get_ml_clf] = lambda: FakeMLClf()
    app.dependency_overrides[get_history] = lambda: FakeHistory()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health_endpoint(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "simulation_mode" in body


def test_scan_endpoint_returns_expected_shape(client):
    r = client.post("/api/v1/scan", json={"text": "Share your OTP to claim prize"})
    assert r.status_code == 200
    body = r.json()
    assert body["label"] == "SCAM"
    assert body["category"] == "otp_fraud"
    assert body["final_score"] == 91.5
    assert "Real banks never ask for OTP" in body["reasons"]


def test_scan_endpoint_rejects_empty_text(client):
    r = client.post("/api/v1/scan", json={"text": ""})
    assert r.status_code == 422  # pydantic min_length validation


def test_scan_endpoint_rejects_missing_field(client):
    r = client.post("/api/v1/scan", json={})
    assert r.status_code == 422


def test_scan_endpoint_rejects_oversized_text(client):
    r = client.post("/api/v1/scan", json={"text": "a" * 6000})
    assert r.status_code == 422  # pydantic max_length validation


def test_old_unversioned_routes_are_gone(client):
    """
    Confirms the versioning migration actually happened — /scan and
    /health should 404 now that everything lives under /api/v1/.
    """
    assert client.get("/health").status_code == 404
    assert client.post("/scan", json={"text": "x"}).status_code == 404


def test_root_endpoint_points_to_versioned_paths(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert "/api/v1" in body["health"]


def test_metrics_endpoint_reports_request_and_cache_stats(client):
    """
    /metrics is used with FakeScorer/FakeMLClf/FakeHistory injected via
    dependency_overrides — the same fixture as every other test here —
    which means the scan-cache in core/pipeline.py is bypassed (by
    design, see ScanCache's docstring) for these calls. This test
    checks the endpoint's SHAPE and that request counting works, not
    real cache hit behavior (that's covered in test_pipeline.py against
    ScanCache directly, and in
    test_run_full_pipeline_cache_hit_skips_engines_and_history_write
    against the real non-DI code path).
    """
    client.get("/api/v1/health")
    client.post("/api/v1/scan", json={"text": "Share your OTP to claim prize"})

    r = client.get("/api/v1/metrics")
    assert r.status_code == 200
    body = r.json()

    assert body["requests_total"] >= 2  # the two calls above, plus this /metrics call gets counted after
    assert body["scan_count"] >= 1
    assert body["avg_scan_latency_ms"] is not None
    assert body["avg_scan_latency_ms"] >= 0
    assert "cache" in body
    assert "hit_rate" in body["cache"]
    assert any(ep.endswith("/api/v1/scan") for ep in body["requests_by_endpoint"])