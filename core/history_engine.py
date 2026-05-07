# core/history_engine.py
# ═════════════════════════════════════════════════════════════════
# Unified FAISS History Engine
# Single index for similarity search + pattern clustering
# Shares same embedding model as ml_model.py (loaded once)
# Provides explainability via overlap phrase detection
# ═════════════════════════════════════════════════════════════════

import os
import json
import sqlite3
import numpy as np
import faiss
from typing import List, Dict, Any, Optional, Tuple
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans

# ── Configuration ────────────────────────────────────────────────
MODEL_NAME    = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384
DB_PATH       = "data/fraud_shield.db"

# Stopwords (inline, no NLTK needed)
STOPWORDS = {
    # English
    "the", "a", "an", "is", "are", "was", "were",
    "to", "of", "and", "in", "for", "on", "with",
    "at", "by", "from", "your", "you", "will", "can",
    "this", "that", "have", "has", "had", "not", "be",
    "it", "its", "we", "our", "us", "do", "did", "get",
    "all", "or", "but", "so", "if", "as", "up", "out",
    "my", "me", "he", "she", "they", "them", "their",
    "i", "am", "been", "being", "about", "after", "more",
    "also", "into", "than", "then", "now", "just", "any",
    "would", "could", "should", "may", "might", "shall",
    # Hindi/Hinglish
    "ke", "ka", "ki", "hai", "ho", "karo", "aap", "se",
    "mein", "ko", "ne", "bhi", "aur", "ya", "nahi", "koi",
    "ek", "jo", "kya", "toh", "ab", "hi", "hain", "tha",
    "agar", "sab", "sirf", "yeh", "woh", "par", "pe",
}

# Words that strongly indicate scam patterns
SCAM_SIGNAL_WORDS = {
    "fee", "otp", "urgent", "prize", "won", "register",
    "pay", "send", "verify", "claim", "offer", "free",
    "guaranteed", "limited", "click", "link", "wallet",
    "deposit", "paytm", "phonepe", "gpay", "transfer",
    "registration", "joining", "security", "processing",
    "activation", "lottery", "selected", "winner",
    "scholarship", "approved", "blocked", "expired",
    "immediate", "today", "hours", "refund", "award",
    "shulk", "bhejo", "jaldi", "turant", "abhi",
}


# ── Main Class ───────────────────────────────────────────────────
class UnifiedHistoryEngine:
    """
    Unified FAISS-based history engine.
    Handles:
    1. Similarity search against past reports
    2. Explainable matching via phrase overlap
    3. Scam pattern clustering via KMeans
    """

    def __init__(self):
        """Initialize empty FAISS index and storage."""
        self.embedder: Optional[SentenceTransformer] = None

        # FAISS index using inner product (cosine after normalize)
        self.index = faiss.IndexFlatIP(EMBEDDING_DIM)

        # Parallel array to FAISS index
        # Each record corresponds to one vector in index
        self.records: List[Dict[str, Any]] = []

        # Load existing data from SQLite
        self._load_from_db()

    # ── Embedder ─────────────────────────────────────────────────
    def _get_embedder(self) -> SentenceTransformer:
        """Lazy load embedder. Same model as ml_model.py."""
        if self.embedder is None:
            self.embedder = SentenceTransformer(MODEL_NAME)
        return self.embedder

    # ── Database Operations ──────────────────────────────────────
    def _get_db(self) -> sqlite3.Connection:
        """Get SQLite connection with WAL mode for performance."""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they do not exist."""
        conn = self._get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                text         TEXT    NOT NULL,
                text_hash    TEXT    UNIQUE,
                label        INTEGER NOT NULL,
                category     TEXT    DEFAULT 'unknown',
                source       TEXT    DEFAULT 'user',
                score        REAL    DEFAULT 0.0,
                report_count INTEGER DEFAULT 1,
                upvotes      INTEGER DEFAULT 0,
                downvotes    INTEGER DEFAULT 0,
                verified     INTEGER DEFAULT 0,
                created_at   TEXT    DEFAULT (datetime('now','localtime')),
                updated_at   TEXT    DEFAULT (datetime('now','localtime'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event      TEXT NOT NULL,
                value      REAL DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now','localtime'))
            )
        """)
        conn.commit()
        conn.close()

    def _load_from_db(self) -> None:
        """Load all existing reports from SQLite into FAISS index."""
        self._init_db()

        conn = self._get_db()
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY id ASC"
        ).fetchall()
        conn.close()

        if not rows:
            return

        texts = [row["text"] for row in rows]
        embedder = self._get_embedder()

        # Encode all texts
        embeddings = embedder.encode(
            texts,
            convert_to_numpy=True,
            show_progress_bar=False,
            batch_size=32
        )

        # Normalize for cosine similarity
        faiss.normalize_L2(embeddings)

        # Add to FAISS index
        self.index.add(embeddings)

        # Store records parallel to index
        for row in rows:
            self.records.append({
                "id":           row["id"],
                "text":         row["text"],
                "label":        row["label"],
                "category":     row["category"],
                "source":       row["source"],
                "score":        row["score"],
                "report_count": row["report_count"],
                "upvotes":      row["upvotes"],
                "downvotes":    row["downvotes"],
                "verified":     row["verified"],
                "embedding":    embeddings[len(self.records)]
            })

    # ── Core Search ──────────────────────────────────────────────
    def search_and_explain(
        self,
        text: str,
        k: int = 5,
        min_similarity: float = 0.60
    ) -> Dict[str, Any]:
        """
        Search for similar past scams and explain why they matched.

        Args:
            text: Input message to search for
            k: Number of nearest neighbors to retrieve
            min_similarity: Minimum cosine similarity threshold

        Returns:
            dict with keys: score, matches, explanation
        """
        if self.index.ntotal == 0:
            return {
                "score":       0.0,
                "matches":     [],
                "explanation": "No community reports yet"
            }

        embedder = self._get_embedder()

        # Encode and normalize query
        query_vec = embedder.encode([text], convert_to_numpy=True)
        faiss.normalize_L2(query_vec)

        # Search index
        k_actual = min(k, self.index.ntotal)
        distances, indices = self.index.search(query_vec, k_actual)

        matches = []
        scam_scores = []

        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1:
                continue
            similarity = float(dist)
            if similarity < min_similarity:
                continue

            record = self.records[idx]
            overlap = self._find_overlap(text, record["text"])

            match = {
                "similarity":      similarity,
                "category":        record["category"],
                "label":           record["label"],
                "overlap_phrases": overlap,
                "times_reported":  record["report_count"],
                "upvotes":         record["upvotes"],
                "verified":        bool(record["verified"]),
                "explanation":     self._build_explanation(
                    record, similarity, overlap
                )
            }
            matches.append(match)

            if record["label"] == 1:
                scam_scores.append(similarity * 100)

        # Calculate history score
        if scam_scores:
            history_score = min(
                100.0,
                float(np.mean(scam_scores)) * (1 + len(scam_scores) * 0.05)
            )
        else:
            history_score = 0.0

        # Build overall explanation
        if matches:
            scam_matches = [m for m in matches if m["label"] == 1]
            if scam_matches:
                best = scam_matches[0]
                explanation = (
                    f"Found {len(scam_matches)} similar scam report(s). "
                    f"Best match: {best['similarity']:.0%} similar "
                    f"({best['category'].replace('_', ' ')} pattern)"
                )
            else:
                explanation = (
                    f"Found {len(matches)} similar safe message(s). "
                    f"No scam pattern matched."
                )
        else:
            explanation = "No similar messages found in community reports"

        return {
            "score":       history_score,
            "matches":     matches,
            "explanation": explanation
        }

    # ── Add New Report ───────────────────────────────────────────
    def add_report(
        self,
        text: str,
        label: int,
        category: str = "unknown",
        source: str   = "user",
        score: float  = 0.0
    ) -> bool:
        """
        Add a new report to both FAISS index and SQLite.

        Args:
            text: Message text
            label: 1 for scam, 0 for safe
            category: Scam category
            source: Where message came from
            score: Risk score assigned

        Returns:
            True if added, False if duplicate
        """
        import hashlib

        # Create hash to detect duplicates
        text_hash = hashlib.md5(text.strip().lower().encode()).hexdigest()

        conn = self._get_db()

        # Check for duplicate
        existing = conn.execute(
            "SELECT id, report_count FROM reports WHERE text_hash = ?",
            (text_hash,)
        ).fetchone()

        if existing:
            # Increment report count
            conn.execute(
                """UPDATE reports
                   SET report_count = report_count + 1,
                       updated_at   = datetime('now','localtime')
                   WHERE text_hash  = ?""",
                (text_hash,)
            )
            conn.commit()
            conn.close()
            return False

        # Insert new record
        conn.execute(
            """INSERT INTO reports
               (text, text_hash, label, category, source, score)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (text.strip(), text_hash, label, category, source, score)
        )
        conn.commit()

        # Get new record id
        row_id = conn.execute(
            "SELECT id FROM reports WHERE text_hash = ?",
            (text_hash,)
        ).fetchone()["id"]

        conn.close()

        # Add to FAISS index
        embedder = self._get_embedder()
        embedding = embedder.encode([text], convert_to_numpy=True)
        faiss.normalize_L2(embedding)
        self.index.add(embedding)

        # Add to records array
        self.records.append({
            "id":           row_id,
            "text":         text.strip(),
            "label":        label,
            "category":     category,
            "source":       source,
            "score":        score,
            "report_count": 1,
            "upvotes":      0,
            "downvotes":    0,
            "verified":     False,
            "embedding":    embedding[0]
        })

        # Log to analytics
        self._log_event("report_added", score)

        return True

    # ── Clustering ───────────────────────────────────────────────
    def get_scam_clusters(self) -> List[Dict[str, Any]]:
        """
        Group scam reports by pattern using KMeans clustering.
        Shows judges: 'We identified X distinct scam patterns.'

        Returns:
            List of cluster dicts with count, category, sample
        """
        # Get only scam records
        scam_records = [r for r in self.records if r["label"] == 1]

        if len(scam_records) < 6:
            return []

        # Get embeddings for scam records
        embeddings = np.array([r["embedding"] for r in scam_records])

        # Determine optimal cluster count
        n_clusters = min(7, len(scam_records) // 3)
        if n_clusters < 2:
            return []

        # Run KMeans
        kmeans = KMeans(
            n_clusters=n_clusters,
            random_state=42,
            n_init=10
        )
        cluster_labels = kmeans.fit_predict(embeddings)

        # Build cluster summary
        clusters: Dict[int, Dict] = {}
        for record, cluster_id in zip(scam_records, cluster_labels):
            cid = int(cluster_id)
            if cid not in clusters:
                clusters[cid] = {
                    "count":      0,
                    "categories": [],
                    "sample":     record["text"][:80] + "...",
                    "cluster_id": cid
                }
            clusters[cid]["count"] += 1
            clusters[cid]["categories"].append(record["category"])

        # Add dominant category to each cluster
        result = []
        for cid, cluster in clusters.items():
            categories = cluster["categories"]
            dominant = max(set(categories), key=categories.count)
            cluster["dominant_category"] = dominant.replace("_", " ").title()
            cluster["category_display"] = dominant
            result.append(cluster)

        # Sort by count descending
        result.sort(key=lambda x: x["count"], reverse=True)
        return result

    # ── Voting ───────────────────────────────────────────────────
    def upvote(self, text_hash: str) -> None:
        """Increment upvote count for a report."""
        conn = self._get_db()
        conn.execute(
            """UPDATE reports
               SET upvotes = upvotes + 1
               WHERE text_hash = ?""",
            (text_hash,)
        )
        conn.commit()
        conn.close()

    def downvote(self, text_hash: str) -> None:
        """Increment downvote count for a report."""
        conn = self._get_db()
        conn.execute(
            """UPDATE reports
               SET downvotes = downvotes + 1
               WHERE text_hash = ?""",
            (text_hash,)
        )
        conn.commit()
        conn.close()

    # ── Analytics ────────────────────────────────────────────────
    def _log_event(self, event: str, value: float = 0) -> None:
        """Log analytics event to SQLite."""
        try:
            conn = self._get_db()
            conn.execute(
                "INSERT INTO analytics (event, value) VALUES (?, ?)",
                (event, value)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_stats(self) -> Dict[str, Any]:
        """
        Get community statistics for homepage display.

        Returns:
            dict with total_reports, scam_count, safe_count, etc.
        """
        conn = self._get_db()

        total = conn.execute(
            "SELECT COUNT(*) FROM reports"
        ).fetchone()[0]

        scam_count = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE label = 1"
        ).fetchone()[0]

        safe_count = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE label = 0"
        ).fetchone()[0]

        recent_scams = conn.execute(
            """SELECT COUNT(*) FROM reports
               WHERE label = 1
               AND created_at >= datetime('now', '-1 hour', 'localtime')"""
        ).fetchone()[0]

        today_scams = conn.execute(
            """SELECT COUNT(*) FROM reports
               WHERE label = 1
               AND DATE(created_at) = DATE('now', 'localtime')"""
        ).fetchone()[0]

        top_categories = conn.execute(
            """SELECT category, COUNT(*) as cnt
               FROM reports
               WHERE label = 1
               GROUP BY category
               ORDER BY cnt DESC
               LIMIT 5"""
        ).fetchall()

        conn.close()

        return {
            "total_reports":  total,
            "scam_count":     scam_count,
            "safe_count":     safe_count,
            "recent_scams":   recent_scams,
            "today_scams":    today_scams,
            "top_categories": [
                {"category": row[0], "count": row[1]}
                for row in top_categories
            ]
        }

    # ── Helpers ──────────────────────────────────────────────────
    def _find_overlap(
        self,
        text1: str,
        text2: str
    ) -> List[str]:
        """
        Find meaningful overlapping words between two texts.
        Prioritizes scam signal words for more useful explanations.

        Args:
            text1: First text
            text2: Second text

        Returns:
            List of overlapping meaningful words
        """
        words1 = set(text1.lower().split()) - STOPWORDS
        words2 = set(text2.lower().split()) - STOPWORDS

        overlap = words1 & words2

        # Prioritize scam signal words
        priority_overlap = overlap & SCAM_SIGNAL_WORDS
        other_overlap    = overlap - SCAM_SIGNAL_WORDS

        # Return up to 5 words, prioritizing signal words
        result = list(priority_overlap)[:3] + list(other_overlap)[:2]
        return result

    def _build_explanation(
        self,
        record: Dict[str, Any],
        similarity: float,
        overlap: List[str]
    ) -> str:
        """
        Build human-readable explanation for a match.

        Args:
            record: Matched record from self.records
            similarity: Cosine similarity score (0-1)
            overlap: Overlapping words

        Returns:
            Explanation string
        """
        category_display = record["category"].replace("_", " ").title()
        sim_pct = f"{similarity:.0%}"

        parts = [
            f"Matches {category_display} pattern ({sim_pct} similar)"
        ]

        if overlap:
            parts.append(
                f"Key phrases: {', '.join(overlap)}"
            )

        if record["report_count"] > 1:
            parts.append(
                f"Reported {record['report_count']} times"
            )

        if record["upvotes"] > 0:
            parts.append(
                f"{record['upvotes']} students confirmed scam"
            )

        if record["verified"]:
            parts.append("✅ Verified by Campus Fraud Shield team")

        return ". ".join(parts)

    def seed_from_dataset(
        self,
        csv_path: str = "data/scam_dataset.csv"
    ) -> int:
        """
        Seed the FAISS index and SQLite from the CSV dataset.
        Called on app startup to ensure consistent state.

        Args:
            csv_path: Path to scam_dataset.csv

        Returns:
            Number of records added
        """
        import pandas as pd

        if not os.path.exists(csv_path):
            print(f"⚠️  Dataset not found at {csv_path}")
            return 0

        df = pd.read_csv(csv_path)
        added = 0

        for _, row in df.iterrows():
            success = self.add_report(
                text     = str(row["text"]),
                label    = int(row["label"]),
                category = str(row.get("category", "unknown")),
                source   = str(row.get("source", "dataset")),
                score    = 80.0 if row["label"] == 1 else 10.0
            )
            if success:
                added += 1

        print(f"✅ Seeded {added} records from dataset")
        return added


# ── Streamlit Caching ────────────────────────────────────────────
def get_history_engine() -> UnifiedHistoryEngine:
    """
    Get or create history engine instance.
    Not cached with st.cache_resource because FAISS
    index needs to accept new records during session.
    """
    return UnifiedHistoryEngine()


# ── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing UnifiedHistoryEngine...")

    engine = UnifiedHistoryEngine()

    # Seed from dataset
    added = engine.seed_from_dataset("data/scam_dataset.csv")
    print(f"Records in index: {engine.index.ntotal}")

    # Test search
    test_text = (
        "Pay Rs.1500 registration fee to confirm "
        "your internship at our company via Paytm"
    )
    result = engine.search_and_explain(test_text)

    print(f"\nSearch result for test message:")
    print(f"  Score:       {result['score']:.1f}/100")
    print(f"  Matches:     {len(result['matches'])}")
    print(f"  Explanation: {result['explanation']}")

    if result["matches"]:
        print("\nTop match:")
        top = result["matches"][0]
        print(f"  Similarity:  {top['similarity']:.0%}")
        print(f"  Category:    {top['category']}")
        print(f"  Overlap:     {top['overlap_phrases']}")
        print(f"  Explanation: {top['explanation']}")

    # Test clusters
    clusters = engine.get_scam_clusters()
    print(f"\nScam clusters found: {len(clusters)}")
    for c in clusters[:3]:
        print(f"  Cluster {c['cluster_id']}: "
              f"{c['count']} reports, "
              f"{c['dominant_category']}")

    # Test stats
    stats = engine.get_stats()
    print(f"\nCommunity stats:")
    print(f"  Total reports: {stats['total_reports']}")
    print(f"  Scam count:    {stats['scam_count']}")
    print(f"  Safe count:    {stats['safe_count']}")