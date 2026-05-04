# core/history_engine.py
import os
import json
import numpy as np
import streamlit as st
from datetime import datetime
from config import REPORTED_SCAMS_FILE

# ─── Optional: sentence-transformers for semantic search ─────────────────────
try:
    from sentence_transformers import SentenceTransformer
    import faiss
    SEMANTIC_AVAILABLE = True
except ImportError:
    SEMANTIC_AVAILABLE = False


# ─── Load reported scams ──────────────────────────────────────────────────────
def load_reported_scams() -> list[dict]:
    if not os.path.exists(REPORTED_SCAMS_FILE):
        return []
    try:
        with open(REPORTED_SCAMS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


# ─── Save a new report ────────────────────────────────────────────────────────
def save_report(text: str, label: str, score: int,
                scam_type: str, reasons: list[str], source: str) -> bool:
    reports = load_reported_scams()

    # Avoid exact duplicates
    if any(r.get("text") == text for r in reports):
        return False

    new_report = {
        "id":        len(reports) + 1,
        "text":      text,
        "label":     label,
        "score":     score,
        "scam_type": scam_type,
        "reasons":   reasons,
        "source":    source,
        "timestamp": datetime.now().isoformat(),
    }

    reports.append(new_report)

    os.makedirs(os.path.dirname(REPORTED_SCAMS_FILE), exist_ok=True)
    try:
        with open(REPORTED_SCAMS_FILE, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


# ─── Semantic model loader ────────────────────────────────────────────────────
@st.cache_resource(show_spinner="📚 Loading history search engine...")
def load_embedding_model():
    if not SEMANTIC_AVAILABLE:
        return None
    try:
        return SentenceTransformer("all-MiniLM-L6-v2")
    except Exception:
        return None


# ─── Build FAISS index from history ──────────────────────────────────────────
@st.cache_resource(show_spinner="🗂️ Building scam history index...")
def build_faiss_index(_model):
    """Build searchable vector index from reported scams."""
    if _model is None:
        return None, []

    reports = load_reported_scams()
    scam_reports = [r for r in reports if r.get("label") in ["Scam", "Suspicious"]]

    if not scam_reports:
        return None, []

    texts = [r["text"] for r in scam_reports]

    try:
        embeddings = _model.encode(texts, convert_to_tensor=False)
        embeddings = np.array(embeddings).astype("float32")

        index = faiss.IndexFlatL2(embeddings.shape[1])
        index.add(embeddings)

        return index, scam_reports
    except Exception:
        return None, []


# ─── Keyword-based fallback history search ────────────────────────────────────
def keyword_history_search(text: str, reports: list[dict]) -> tuple[int, str]:
    """Simple fallback when semantic search unavailable."""
    if not reports:
        return 0, ""

    text_words = set(text.lower().split())
    best_score = 0
    best_match = None

    for report in reports:
        if report.get("label") not in ["Scam", "Suspicious"]:
            continue
        report_words = set(report["text"].lower().split())
        common = text_words & report_words
        similarity = len(common) / max(len(text_words), 1)

        if similarity > best_score:
            best_score = similarity
            best_match = report

    if best_score > 0.4 and best_match:
        confidence = int(best_score * 100)
        preview    = best_match["text"][:60] + "..."
        return confidence, f"📋 History Match ({confidence}% similar): '{preview}'"

    return 0, ""


# ─── Master history check ────────────────────────────────────────────────────
def check_history(text: str) -> tuple[int, str]:
    """
    Returns (score 0-100, reason string)
    Uses semantic search if available, keyword fallback otherwise.
    """
    model  = load_embedding_model()
    reports = load_reported_scams()

    if not reports:
        return 0, ""

    # ── Semantic search (preferred) ───────────────────────────────────────
    if model is not None and SEMANTIC_AVAILABLE:
        index, scam_reports = build_faiss_index(model)

        if index is not None and scam_reports:
            try:
                query_embedding = model.encode([text])[0]
                query_embedding = np.array([query_embedding]).astype("float32")

                D, I = index.search(query_embedding, k=1)
                distance = float(D[0][0])
                match_idx = int(I[0][0])

                # Distance threshold tuning
                # Distance < 0.5 → very similar
                # Distance 0.5-1.5 → somewhat similar
                if distance < 1.5:
                    similarity = max(0, 100 * (1 - distance / 1.5))
                    if similarity > 40:
                        matched   = scam_reports[match_idx]
                        preview   = matched["text"][:60] + "..."
                        return int(similarity), (
                            f"🚨 History Match ({int(similarity)}% similar to known scam): '{preview}'"
                        )
            except Exception:
                pass

    # ── Keyword fallback ──────────────────────────────────────────────────
    return keyword_history_search(text, reports)


# ─── Trending scams ──────────────────────────────────────────────────────────
def get_trending_scams(limit: int = 5) -> list[dict]:
    """Get most recently reported scams for display."""
    reports = load_reported_scams()
    scams   = [r for r in reports if r.get("label") == "Scam"]
    return scams[-limit:][::-1]


# ─── Stats ───────────────────────────────────────────────────────────────────
def get_history_stats() -> dict:
    reports = load_reported_scams()
    total   = len(reports)
    scams   = sum(1 for r in reports if r.get("label") == "Scam")
    susp    = sum(1 for r in reports if r.get("label") == "Suspicious")
    safe    = sum(1 for r in reports if r.get("label") == "Safe")

    return {
        "total":      total,
        "scams":      scams,
        "suspicious": susp,
        "safe":       safe,
    }