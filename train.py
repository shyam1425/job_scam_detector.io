import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import pickle
import joblib
import re

# Load dataset
df = pd.read_csv(r"C:\Users\Lenovo\Downloads\real_or_fake_fake_jobposting_prediction.csv")
df = df.dropna(subset=['title', 'description', 'fraudulent'])
df['text'] = df['title'] + ' ' + df['description'].fillna('')

# Preprocess
def preprocess(text):
    text = re.sub(r'[^a-zA-Z\s]', '', str(text).lower())
    return text

df['text'] = df['text'].apply(preprocess)

# Scam keywords (common in fakes)
scam_keywords = ['urgent', 'immediate hire', 'no experience', 'work from home money', 'apply now fee', 'guaranteed salary', 'too good']
def count_scam_keywords(text):
    return sum(1 for kw in scam_keywords if kw in text.lower())

df['scam_count'] = df['text'].apply(count_scam_keywords)

X = df['text'] + ' ' + df['scam_count'].astype(str)
y = df['fraudulent'].astype(int)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=5000)),
    ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
])

pipeline.fit(X_train, y_train)
print(f"Accuracy: {pipeline.score(X_test, y_test):.2f}")

joblib.dump(pipeline, 'job_classifier.pkl')
