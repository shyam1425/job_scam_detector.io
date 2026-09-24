import argparse
import os
import re

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split


def preprocess(text):
    return re.sub(r"[^a-zA-Z\s]", "", str(text).lower())


def main():
    parser = argparse.ArgumentParser(description="Train the job scam classifier")
    parser.add_argument("--dataset", default=os.getenv("JOB_DATASET"), help="CSV dataset path")
    parser.add_argument("--output", default=os.getenv("MODEL_PATH", "job_classifier.pkl"))
    args = parser.parse_args()

    if not args.dataset:
        raise SystemExit("Provide --dataset or set JOB_DATASET")

    df = pd.read_csv(args.dataset).dropna(subset=["title", "description", "fraudulent"])
    df["text"] = (df["title"].fillna("") + " " + df["description"].fillna("")).map(preprocess)
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["fraudulent"].astype(int), test_size=0.2, random_state=42, stratify=df["fraudulent"]
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000)),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")),
    ])
    pipeline.fit(X_train, y_train)
    print(f"Accuracy: {pipeline.score(X_test, y_test):.2f}")
    joblib.dump(pipeline, args.output)
    print(f"Model written to {args.output}")


if __name__ == "__main__":
    main()
