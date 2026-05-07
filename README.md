# Campus Fraud Shield 🛡️

> AI-powered scam detection for Indian college students.  
> Detects fake internships, OTP frauds, prize scams, and scholarship frauds in real time.

[![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-ff4b4b?logo=streamlit)](https://streamlit.io)
[![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/yourname/campus-fraud-shield.git
cd campus-fraud-shield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train the model (one time only)
python train/train_model.py

# 4. Run the app
streamlit run app.py
```

---

## 🧠 How It Works

```
Your Message
     │
     ▼
┌─────────────────────────────────────────────────────┐
│           4-Engine Detection Pipeline               │
│                                                     │
│  ⚖️ Rules Engine    35%  — 50+ regex scam patterns  │
│  🌐 Domain Check   30%  — URL/email verification    │
│  🤖 Semantic AI    20%  — all-MiniLM-L6-v2 model   │
│  📚 FAISS History  15%  — community scam reports    │
│                                                     │
│  Final = 0.35×Rules + 0.30×Domain                  │
│        + 0.20×ML   + 0.15×History                  │
└─────────────────────────────────────────────────────┘
     │
     ▼
🚨 SCAM  /  ⚠️ SUSPICIOUS  /  ✅ SAFE
+ Confidence score (0–100)
+ Explanation of why
+ Action steps + complaint text
```

---

## 📁 Project Structure

```
campus-fraud-shield/
│
├── app.py                    ← Main Streamlit app
├── interfaces.py             ← Shared data formats
├── requirements.txt
│
├── core/
│   ├── ml_model.py           ← Semantic classifier
│   ├── history_engine.py     ← FAISS community engine
│   ├── campus_checker.py     ← India-specific rules
│   ├── rules_engine.py       ← Regex pattern engine
│   ├── domain_checker.py     ← URL/domain analyzer
│   └── scorer.py             ← Weighted final scorer
│
├── utils/
│   ├── action_advisor.py     ← What to do now
│   ├── explainer.py          ← Student explanations
│   ├── architecture_viz.py   ← Pipeline diagram
│   └── trend_chart.py        ← Scam trend charts
│
├── train/
│   └── train_model.py        ← One-time training script
│
├── data/
│   ├── campus_entities.json  ← 25+ verified entities
│   ├── scam_dataset.csv      ← 120+ labeled messages
│   └── model_metrics.json    ← Auto-generated metrics
│
├── models/                   ← Auto-generated after training
│   ├── semantic_classifier.pkl
│   ├── training_embeddings.npy
│   └── training_texts.json
│
└── .streamlit/
    └── config.toml           ← Dark theme config
```

---

## 🎯 Scam Categories Detected

| Category | Example |
|---|---|
| 🎭 Fake Internship | "Pay ₹999 registration fee to confirm slot" |
| 💼 Fake Job | "Pay ₹5000 training fee before joining TCS" |
| 🏆 Prize/Lottery | "You won KBC ₹25 lakh — pay ₹1500 to claim" |
| 🔐 OTP Fraud | "Share OTP to unblock your SBI account" |
| 📚 Scholarship Fraud | "NSP scholarship ₹25000 — pay ₹500 to release" |
| 🏦 Bank Impersonation | "HDFC account blocked — verify KYC on sbi-kyc.xyz" |
| 🏛️ Govt Scheme Fraud | "Free laptop scheme — pay ₹1500 delivery charge" |
| ⏰ Part-Time Scam | "Earn ₹500/hr liking YouTube videos — pay ₹999" |

---

## ⚙️ Engine Details

### ⚖️ Rules Engine (35%)
- 50+ regex patterns across 8 categories
- Fee demands, OTP requests, urgency tactics
- Safe signal detection (negative scoring)
- Instant results — no ML required

### 🌐 Domain Checker (30%)
- Extracts all URLs and emails from message
- Checks against whitelist of 60+ safe domains
- Detects brand impersonation (fake internshala.co)
- Flags URL shorteners (bit.ly, tinyurl)
- Detects suspicious TLDs (.xyz, .tk, .ml)

### 🤖 Semantic AI (20%)
- Model: `all-MiniLM-L6-v2` (384-dim embeddings)
- Classifier: Logistic Regression with balanced weights
- Trained on 120+ labeled Indian scam messages
- Returns similar examples for explainability

### 📚 FAISS History (15%)
- Vector similarity search against community reports
- SQLite backend for persistence
- Overlap phrase detection for explainability
- KMeans clustering to find scam pattern groups

---

## 🛡️ Override Logic

```python
# These always force SCAM regardless of weighted score
OTP sharing detected          → score = 92  (forced SCAM)
Rules engine score ≥ 90       → score ≥ 75  (forced SCAM range)
Campus check score ≥ 85       → score ≥ 72  (forced SCAM range)
Both engines ≥ 70             → score ≥ 71  (forced SCAM range)
Fee demand + personal payment → score ≥ 72  (forced SCAM range)
```

---

## 📊 Model Performance

After training on `scam_dataset.csv`:

| Metric | Score |
|---|---|
| Accuracy | ~94% |
| Precision | ~96% |
| Recall | ~93% |
| F1 Score | ~94% |

---

## 🆘 Emergency Resources

| Resource | Details |
|---|---|
| 📞 Cyber Crime Helpline | **1930** (24×7) |
| 🌐 Report Online | [cybercrime.gov.in](https://cybercrime.gov.in) |
| 🏦 SBI Fraud | 1800-11-2211 |
| 🏦 HDFC Fraud | 1800-202-6161 |
| 🏦 ICICI Fraud | 1800-1080 |

---

## 🏆 Built For

Indian college students hackathon — protecting students from:
- Fake internship fee frauds
- WhatsApp job scams
- OTP theft attempts
- Fake scholarship schemes
- Prize/lottery frauds

---

## 📄 License

MIT License — free to use, modify, and distribute.