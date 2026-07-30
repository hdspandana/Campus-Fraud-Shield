# Campus Fraud Shield

An AI-assisted fraud detection platform designed to help Indian college students identify phishing attempts, fake internship offers, scholarship scams, OTP fraud, impersonation attacks, and other social engineering threats.

> **Note:** This is a starter professional README template tailored to your project. It intentionally excludes VirusTotal integration so it can be added in a later feature commit.

## Features

- Multi-engine fraud detection pipeline
- Explainable AI with confidence scoring
- Rule-based scam detection
- Domain and URL analysis
- Semantic ML classification
- FAISS-based historical similarity search
- FastAPI REST API
- Streamlit web interface
- Modular shared detection pipeline

## Architecture

User Message
    │
    ▼
Shared Detection Pipeline
 ├── Rule Engine (35%)
 ├── Domain Analysis (30%)
 ├── Semantic ML (20%)
 └── History Engine (15%)
        │
        ▼
 SAFE / SUSPICIOUS / SCAM

## Technology Stack

**Backend**
- Python
- FastAPI
- Streamlit

**Machine Learning**
- Sentence Transformers
- scikit-learn
- FAISS

**Storage**
- SQLite
- NumPy
- Pandas

## Project Structure

```
Campus-Fraud-Shield/
├── api.py
├── app.py
├── config.py
├── requirements.txt
├── core/
│   ├── pipeline.py
│   ├── scorer.py
│   ├── rules_engine.py
│   ├── domain_checker.py
│   ├── history_engine.py
│   └── ml_model.py
├── utils/
├── train/
├── data/
├── models/
└── .streamlit/
```

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Service information |
| GET | /health | Health status |
| POST | /scan | Analyze a message |

Interactive documentation:

`http://localhost:8000/docs`

## Quick Start

```bash
git clone https://github.com/hdspandana/Campus-Fraud-Shield.git
cd Campus-Fraud-Shield

pip install -r requirements.txt

python train/train_model.py

streamlit run app.py
```

Run API

```bash
python -m uvicorn api:app --reload --port 8000
```

## Detection Capabilities

- Fake internship scams
- Fake placement offers
- Scholarship scams
- Prize and lottery scams
- OTP fraud
- Bank impersonation
- Government scheme fraud
- Part-time job scams

## Engineering Highlights

- Modular architecture
- Shared detection pipeline
- API-first backend
- Explainable AI
- Weighted risk scoring
- Vector similarity search
- Production-ready REST API
- Separation of concerns
- Model persistence
- Cached model loading

## Roadmap

- Browser extension
- Mobile application
- Threat intelligence integration
- Advanced analytics dashboard
- CI/CD enhancements

## License

MIT License
