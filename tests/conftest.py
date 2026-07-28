# tests/conftest.py
import os
import sys

import pytest

# So `pytest` run from the repo root can `import core.xxx` / `import app`
# the same way the app itself does.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def no_real_threat_intel_calls(monkeypatch):
    """
    Auto-applied to every test. Forces the VirusTotal / Google Safe
    Browsing keys to empty during tests, so:
      1. Tests never make real network calls to third-party APIs
         (would make CI slow, flaky, and dependent on secrets).
      2. Tests never accidentally burn through your API quota.
    core/domain_checker.py already no-ops cleanly when these are
    empty, which is exactly the behavior this fixture exercises.
    """
    monkeypatch.setattr("core.domain_checker.VIRUSTOTAL_KEY", "", raising=False)
    monkeypatch.setattr("core.domain_checker.GOOGLE_SAFE_BROWSING_KEY", "", raising=False)