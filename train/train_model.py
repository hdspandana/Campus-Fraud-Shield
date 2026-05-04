import os
import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report


def train():
    print("📚 Loading dataset...")
    df = pd.read_csv("data/scam_dataset.csv")
    print(f"   Total samples: {len(df)}")
    print(f"   Labels: {df['label'].value_counts().to_dict()}")

    X = df["text"].astype(str)
    y = df["label"].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n🔧 Building pipeline...")
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=15000,
            sublinear_tf=True,
            analyzer="word",
        )),
        ("clf", LogisticRegression(
            C=2.0,
            class_weight="balanced",
            max_iter=1000,
            solver="lbfgs",
        )),
    ])

    print("🏋️ Training model...")
    pipeline.fit(X_train, y_train)

    # Cross-validation
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5)
    print(f"\n✅ Cross-validation accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # Test set evaluation
    y_pred = pipeline.predict(X_test)
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred))

    # Save model
    os.makedirs("models", exist_ok=True)
    joblib.dump(pipeline, "models/scam_classifier.pkl")
    print("\n💾 Model saved to models/scam_classifier.pkl")


if __name__ == "__main__":
    train()