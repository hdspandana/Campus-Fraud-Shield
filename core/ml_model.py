# core/ml_model.py
# ═════════════════════════════════════════════════════════════════
# Semantic Scam Classifier using Sentence Transformers
# Replaces TF-IDF with all-MiniLM-L6-v2 embeddings
# Provides explainability via similar examples
# ═════════════════════════════════════════════════════════════════

import os
import pickle
import numpy as np
from typing import List, Tuple, Dict, Any
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
import streamlit as st

# ── Configuration ────────────────────────────────────────────────
MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384
MODELS_DIR = "models"
CLASSIFIER_PATH = os.path.join(MODELS_DIR, "semantic_classifier.pkl")
EMBEDDINGS_PATH = os.path.join(MODELS_DIR, "training_embeddings.npy")
TEXTS_PATH = os.path.join(MODELS_DIR, "training_texts.json")

# ── Main Class ───────────────────────────────────────────────────
class SemanticScamClassifier:
    """
    Semantic Scam Classifier using sentence embeddings.
    Same model as FAISS (all-MiniLM-L6-v2) for architectural coherence.
    Provides explainability via similar training examples.
    """

    def __init__(self):
        """Initialize embedder and classifier. Model loaded lazily."""
        self.embedder: SentenceTransformer = None
        self.classifier: LogisticRegression = None
        self.is_trained = False

        # Training data storage for similarity lookup
        self.training_texts: List[str] = []
        self.training_labels: List[int] = []
        self.training_embeddings: np.ndarray = None

    def _load_embedder(self) -> SentenceTransformer:
        """Load sentence transformer model (cached by Streamlit)."""
        if self.embedder is None:
            self.embedder = SentenceTransformer(MODEL_NAME)
        return self.embedder

    def fit(self, texts: List[str], labels: List[int]) -> "SemanticScamClassifier":
        """
        Train the semantic classifier.

        Args:
            texts: List of message strings
            labels: List of 0 (safe) or 1 (scam)

        Returns:
            self
        """
        if len(texts) != len(labels):
            raise ValueError("Texts and labels must have same length")

        if len(set(labels)) < 2:
            raise ValueError("Both classes (0 and 1) must be present in training data")

        print(f"🤖 Training semantic classifier on {len(texts)} samples...")
        embedder = self._load_embedder()

        # Generate embeddings with progress bar
        embeddings = embedder.encode(
            texts,
            show_progress_bar=True,
            batch_size=32,
            convert_to_numpy=True
        )

        # Train classifier with balanced class weights
        self.classifier = LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        self.classifier.fit(embeddings, labels)

        # Store training data for similarity lookup
        self.training_texts = texts
        self.training_labels = labels
        self.training_embeddings = embeddings
        self.is_trained = True

        print(f"✅ Training complete. Accuracy on training set: {self.classifier.score(embeddings, labels):.2%}")
        return self

    def predict_proba(self, text: str) -> Tuple[float, str]:
        """
        Predict scam probability for a single text.

        Args:
            text: Message string to analyze

        Returns:
            tuple: (score 0-100, reason/explanation string)
        """
        if not self.is_trained:
            return 50.0, "⚠️ Model not trained yet. Please train first."

        embedder = self._load_embedder()
        embedding = embedder.encode([text], convert_to_numpy=True)

        # Get probability
        proba = self.classifier.predict_proba(embedding)[0]
        scam_prob = float(proba[1])

        # Convert to score 0-100
        score = scam_prob * 100

        # Generate confidence-based reason
        if score >= 85:
            reason = "Language pattern strongly matches known scam messages"
        elif score >= 65:
            reason = "Language pattern similar to reported scam patterns"
        elif score <= 30:
            reason = "Language pattern matches legitimate messages"
        else:
            reason = "Language pattern inconclusive — requires human review"

        return score, reason

    def get_similar_training_examples(
        self,
        text: str,
        n: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Find most similar training examples for explainability.
        Shows judges WHY the model made this prediction.

        Args:
            text: Input message
            n: Number of similar examples to return

        Returns:
            List of dicts with keys: text, label, similarity
        """
        if not self.is_trained:
            return []

        if len(self.training_texts) == 0:
            return []

        embedder = self._load_embedder()
        query_embedding = embedder.encode([text], convert_to_numpy=True)

        # Compute cosine similarity with all training embeddings
        # Normalize for cosine similarity
        from sklearn.metrics.pairwise import cosine_similarity

        similarities = cosine_similarity(
            query_embedding,
            self.training_embeddings
        )[0]

        # Get top n indices
        top_indices = np.argsort(similarities)[-n:][::-1]

        results = []
        for i in top_indices:
            results.append({
                "text": self.training_texts[i][:100] + (
                    "..." if len(self.training_texts[i]) > 100 else ""
                ),
                "label": self.training_labels[i],
                "similarity": float(similarities[i])
            })

        return results

    def save(self) -> None:
        """Save trained model and embeddings to disk."""
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")

        os.makedirs(MODELS_DIR, exist_ok=True)

        # Save classifier
        with open(CLASSIFIER_PATH, "wb") as f:
            pickle.dump(self.classifier, f)

        # Save embeddings
        np.save(EMBEDDINGS_PATH, self.training_embeddings)

        # Save texts and labels as JSON
        import json
        with open(TEXTS_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "texts": self.training_texts,
                "labels": self.training_labels
            }, f, ensure_ascii=False, indent=2)

        print(f"✅ Model saved to {MODELS_DIR}/")

    def load(self) -> bool:
        """
        Load trained model and training data from disk.
        Returns True if successful, False otherwise.
        """
        if not os.path.exists(CLASSIFIER_PATH):
            print("⚠️  No saved model found. Train first.")
            return False

        try:
            # Load classifier
            with open(CLASSIFIER_PATH, "rb") as f:
                self.classifier = pickle.load(f)

            # Load embeddings
            self.training_embeddings = np.load(EMBEDDINGS_PATH)

            # Load texts and labels
            import json
            with open(TEXTS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.training_texts = data["texts"]
                self.training_labels = data["labels"]

            self.is_trained = True
            print(f"✅ Model loaded from {MODELS_DIR}/")
            print(f"   Trained on {len(self.training_texts)} samples")
            return True

        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            return False

    def get_classification_report(self, texts: List[str],
                                   labels: List[int]) -> str:
        """
        Generate detailed classification report for evaluation.
        Used by train/train_model.py to show performance metrics.
        """
        if not self.is_trained:
            return "Model not trained yet."

        embedder = self._load_embedder()
        embeddings = embedder.encode(texts, convert_to_numpy=True)
        predictions = self.classifier.predict(embeddings)

        return classification_report(
            labels,
            predictions,
            target_names=["SAFE", "SCAM"],
            digits=4
        )


# ── Streamlit Caching (IMPORTANT for performance) ────────────────
@st.cache_resource
def get_semantic_classifier() -> SemanticScamClassifier:
    """
    Get or create cached classifier instance.
    This ensures the model is loaded only once per app run.
    """
    return SemanticScamClassifier()


# ── Example Usage (for testing) ──────────────────────────────────
if __name__ == "__main__":
    # Quick test
    classifier = SemanticScamClassifier()

    # Sample training data
    train_texts = [
        "Pay registration fee to get internship",
        "Send OTP to claim your prize money",
        "Your offer letter is ready. No fee required.",
        "Interview scheduled for Monday 3PM",
    ]
    train_labels = [1, 1, 0, 0]

    # Train
    classifier.fit(train_texts, train_labels)

    # Predict
    test_text = "Pay Rs 2000 fee to confirm your job offer"
    score, reason = classifier.predict_proba(test_text)
    print(f"\nTest: '{test_text}'")
    print(f"Score: {score:.1f}/100")
    print(f"Reason: {reason}")

    # Get similar examples
    similar = classifier.get_similar_training_examples(test_text, n=2)
    print("\nSimilar training examples:")
    for ex in similar:
        label_str = "SCAM" if ex["label"] == 1 else "SAFE"
        print(f"  - {ex['text']} ({label_str}, {ex['similarity']:.0%} similar)")

    # Save model
    classifier.save()

    # Load model
    new_classifier = SemanticScamClassifier()
    new_classifier.load()
    score2, _ = new_classifier.predict_proba(test_text)
    print(f"\nAfter save/load: Score = {score2:.1f}")