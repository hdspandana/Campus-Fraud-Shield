# 🛡️ Campus Fraud Shield

**AI-assisted fraud detection for Indian college students** — detects fake internships, scholarship scams, OTP fraud, lottery/prize scams, bank impersonation, delivery scams, QR scams, UPI fraud, tech-support scams, and more, and explains *why* a message is dangerous instead of just labeling it.

![CI](https://github.com/hdspandana/Campus-Fraud-Shield/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Built for the Samsung PRISM Research Program. Now maintained as an ongoing engineering project, with an emphasis on **honest, verifiable metrics over inflated claims** — every accuracy number in this README is cross-validated, not measured on training data.

---

## Why this exists

Scam messages targeting Indian college students follow recognizable patterns — fake placement offers, "pay a small registration fee" internships, OTP-sharing requests disguised as KYC updates, and more. Campus Fraud Shield combines deterministic rules, real-time threat intelligence, and machine learning to catch these patterns and explain the reasoning in plain language, so users learn to recognize scams themselves rather than just trusting a black-box verdict.

---

## How it works

A message is scored by **4 independent engines**, combined with weighted scoring, plus a small set of high-confidence overrides that can bypass the weighted average entirely when a signal is strong enough to be trusted on its own:

```
                         User Message
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │           Shared Detection Pipeline       │
        │              (core/pipeline.py)           │
        ├─────────────────────────────────────────┤
        │  Rules Engine        25%   regex/keyword  │
        │  Domain/URL Check    20%   + threat-intel │
        │  Semantic ML         45%   sentence embed │
        │  History (FAISS)     10%   past reports   │
        └─────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │   Override Layer   │
                    │  (bypasses weights │
                    │  when confidence   │
                    │  is very high)     │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
            SAFE        SUSPICIOUS          SCAM
```

**Overrides** — some signals are reliable enough to skip the averaging entirely:
- OTP-sharing requests → always flagged SCAM (real banks never ask for this)
- VirusTotal: 2+ security vendors flag a domain as malicious → forced high score
- Google Safe Browsing: confirmed match → forced high score
- Near-identical (90%+ similarity) match to a previously reported scam → forced high score

**Conflict detection** — if the 4 engines significantly disagree with each other (not just rules-vs-ML, every pair is checked), the verdict is escalated to at least SUSPICIOUS rather than silently defaulting to SAFE. This project prioritizes catching real scams over minimizing false alarms.

An optional **Gemini LLM layer** generates a plain-language explanation grounded in the retrieved similar cases (retrieval-augmented, not free-form) — it explains a verdict, it doesn't decide one.

---

## Features

**Detection**
- 4-engine weighted scoring pipeline with a high-confidence override layer
- Rules engine covering 14+ scam categories, including Hinglish/code-mixed patterns and homoglyph/Unicode obfuscation detection
- Domain analysis: typosquatting, brand impersonation, suspicious TLDs, multi-hyphen domains, HTTPS checks
- **Real-time threat intelligence**: VirusTotal + Google Safe Browsing integration — optional (works with zero setup, activates automatically once API keys are added), fails open on any error so a flaky third-party API can never break a scan
- Semantic ML classification (sentence-transformer embeddings + tuned logistic regression) with FAISS-based similarity search against previously reported scams
- Broadened conflict detection across all 4 engines, with an explicit anti-false-negative design: ambiguous verdicts escalate toward caution rather than defaulting to "safe"

**Explainability**
- Human-readable reasons for every score component
- RAG-style LLM explanation grounded in retrieved similar cases
- Per-engine score breakdown and the exact scoring formula shown for every scan

**Engineering**
- Streamlit web UI + a versioned FastAPI REST API (`/api/v1/...`), both calling the exact same shared pipeline (`core/pipeline.py`) so they can never drift out of sync
- Dependency injection (FastAPI `Depends()`) for the detection engines, enabling fast, isolated unit tests without loading the full ML stack
- Structured logging instead of silent failure — errors are logged, not swallowed
- 39 automated tests (pytest) covering rules, domain checks, the API, and scoring/override logic, run automatically on every push via GitHub Actions CI
- Honest ML metrics: cross-validated (not training-set) accuracy, a real confusion matrix with precision/recall/F1, and a per-category example-count dashboard that flags which scam categories have too little data to be reliable yet

---

## Model performance — honest numbers

This is intentionally reported plainly, including the limitation:

| Metric | Value |
|---|---|
| Cross-validated accuracy | ~76% (5-fold, stratified) |
| Training examples | 66, across 14 categories |
| Categories with < 5 examples | `invest_scam`, `telegram_job`, `upi_request`, `credential_harvesting`, `job_fee`, `scholarship_fee`, `sextortion` |

**Why report a number this modest instead of a bigger one:** the semantic ML engine is one of 4 engines, not the sole decision-maker — the rules engine, domain/threat-intel checks, and override logic all compensate for its current limitations. The honest path to a higher number is adding more labeled examples to the weak categories above, not tuning around a small dataset until the number looks better than it is. Run `python train/train_model.py` after adding data to regenerate all of these metrics, including a full confusion matrix, viewable in the app's "📊 Model Performance" panel.

**Why the ML engine's weight is the real bottleneck, not the architecture:** with only 86 labeled examples, no classifier — logistic regression, a bigger transformer, or otherwise — can learn much more than this from the raw text alone. Two changes address that directly instead of just tuning around it:

- **Structured feature fusion** (`core/ml_model.py`) — a small set of deterministic lexical signals (OTP mention, currency amount, payment-app name, phone number, urgency language, "congratulations/won" phrasing) is concatenated onto the sentence embedding before the classifier sees it. These are exactly the signals a linear model struggles to reliably learn from a few dozen examples but which a hand-written regex always catches correctly — so the classifier gets them for free instead of hoping the embedding space encodes them.
- **`data/augment_dataset.py`** — generates template-based synthetic candidates for the thinnest categories (job/fee/lottery/OTP-style patterns), written to a separate `data/scam_dataset_augmented.csv` for human review, never auto-merged. Sextortion is deliberately excluded from this — see `data/dataset.md`'s "Why sextortion wasn't padded to 5" for the reasoning, which this script follows rather than overrides. If you do merge reviewed candidates into the training set, use `GroupKFold` on the `template_group` column instead of the default stratified split, so near-duplicate template variants can't land on both sides of a cross-validation fold and quietly inflate the accuracy number.
- **Swappable embedding model** — `SEMANTIC_MODEL_NAME` (env var, defaults to `all-MiniLM-L6-v2`) is read by both `core/ml_model.py` and `core/history_engine.py`, so a stronger or multilingual model (e.g. `paraphrase-multilingual-mpnet-base-v2`, given the Hinglish/code-mixed scam text this project targets) can be tried without touching code — just re-run `train_model.py` after setting it.

---

## Tech stack

| Layer | Technology |
|---|---|
| Web UI | Streamlit |
| REST API | FastAPI, Uvicorn |
| ML | sentence-transformers, scikit-learn, FAISS |
| LLM explanation | Google Gemini |
| Threat intel | VirusTotal API, Google Safe Browsing API |
| Testing | pytest, GitHub Actions CI |
| Data | pandas, NumPy |

---

## Project structure

```
Campus-Fraud-Shield/
├── app.py                    # Streamlit UI
├── api.py                    # FastAPI REST API (/api/v1/...)
├── config.py                 # environment/config constants
├── requirements.txt          # pinned production dependencies
├── requirements-dev.txt      # test-only dependencies
├── pytest.ini
├── core/
│   ├── pipeline.py           # shared orchestration used by app.py AND api.py
│   ├── scorer.py             # weighted scoring + override logic
│   ├── rules_engine.py
│   ├── domain_checker.py     # + threat-intel integration
│   ├── history_engine.py     # FAISS similarity search
│   └── ml_model.py           # semantic classifier
├── utils/
│   ├── llm_explainer.py      # Gemini-based explanation (RAG-grounded)
│   └── action_advisor.py
├── train/
│   └── train_model.py        # regenerates the model + honest metrics
├── data/
│   ├── scam_dataset.csv
│   └── model_metrics.json    # generated by train_model.py
├── tests/                    # pytest suite
├── .github/workflows/ci.yml  # GitHub Actions
└── models/                   # gitignored — regenerated by train_model.py
```

---

## Quick start

```bash
git clone https://github.com/hdspandana/Campus-Fraud-Shield.git
cd Campus-Fraud-Shield

pip install -r requirements.txt

# Add your API keys to a .env file in the project root:
#   GEMINI_API_KEY=...                     (required for LLM explanations)
#   VIRUSTOTAL_API_KEY=...                 (optional — threat-intel)
#   GOOGLE_SAFE_BROWSING_API_KEY=...       (optional — threat-intel)

python train/train_model.py    # trains the model, writes honest metrics
python -m streamlit run app.py
```

**Run the API separately:**
```bash
python -m uvicorn api:app --reload --port 8000
```
Interactive docs: `http://127.0.0.1:8000/docs`

**Run tests:**
```bash
pip install -r requirements-dev.txt
python -m pytest
```

> **Windows note:** if `streamlit`/`uvicorn`/`pytest` aren't recognized as commands after installing, your Python Scripts folder likely isn't on PATH — use `python -m streamlit run app.py` etc. as shown above, or add `%APPDATA%\Python\PythonXX\Scripts` to your PATH permanently.

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Service info |
| GET | `/api/v1/health` | Health check — reports whether real engines loaded or the app is in simulation mode |
| GET | `/api/v1/metrics` | Request volume, average `/scan` latency, and scan-cache hit rate |
| POST | `/api/v1/scan` | Analyze a message, returns full score breakdown + explanation |

Example:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "You won Rs.25000 lottery! Pay Rs.500 processing fee to claim"}'
```

---

## Deployment

```bash
docker compose up --build
```

Runs both the FastAPI service (`localhost:8000/docs`) and the Streamlit UI (`localhost:8501`) from a single multi-stage image — see `Dockerfile`/`docker-compose.yml`. Both share `core/pipeline.py`'s code path directly (no HTTP hop between them), so there's no risk of behavior drifting between the two surfaces. Named volumes persist the trained model and reported-scam history across restarts.

---

## Efficiency: scan result caching

The same scam text gets forwarded verbatim to many students — that's the actual real-world traffic pattern, not random unique messages. `core/pipeline.py` keeps a thread-safe, in-memory LRU+TTL cache (`SCAN_CACHE_MAXSIZE`/`SCAN_CACHE_TTL_SECONDS` env vars, default 500 entries / 1 hour) keyed on whitespace/case-normalized text. A cache hit skips the sentence-transformer encode call, the FAISS search, and all 4 engines entirely — and also skips writing a near-duplicate entry to the history index for what's already been recorded. Check `/api/v1/metrics`'s `cache.hit_rate` to see how much real traffic this is absorbing. Bypassed automatically for dependency-injected calls (tests) so it can never interfere with test isolation.

---

## Security notes

- All secrets live in `.env` (gitignored) — never commit real API keys.
- The threat-intel integration fails open by design: if VirusTotal/Safe Browsing are unreachable, rate-limited, or misconfigured, scans continue normally using the other 3 engines rather than breaking.
- If you fork this repo: check `git log --all --full-history -- .env` before assuming your `.env` was never accidentally committed in your own history — rotate any key that was ever exposed, regardless of whether it's since been removed from the latest commit.

---

## Known limitations

Stated plainly, not hidden:
- ML accuracy (~76% cross-validated) reflects a genuinely small dataset — several scam categories currently have only 1-2 training examples and are not yet reliably detected by the ML engine specifically (the rules engine and overrides provide a safety net, but category-level ML accuracy for those is weak).
- Threat-intel checks require the message to contain a URL; text-only scams (e.g. a phone-based OTP request with no link) rely entirely on the rules/ML/history engines.
- Free-tier VirusTotal/Safe Browsing quotas are limited (VirusTotal: 500 requests/day) — heavy usage will need a paid tier.

---

## Roadmap

- [ ] Expand training data for underrepresented categories (see the in-app dashboard for the current list)
- [ ] Docker containerization
- [ ] Chrome extension
- [ ] Mobile app
- [ ] Crowdsourced campus threat-intelligence feed

---

## License

MIT License