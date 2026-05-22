"""
train_model.py  —  IoT IDS training pipeline
Dataset: CICIDS2017  (https://www.unb.ca/cic/datasets/ids-2017.html)
         Download the CSV files from the "MachineLearningCVE" folder.
         Place them all in a single directory and set DATASET_DIR below.

Attack mapping (CICIDS2017 labels → our 5 classes):
  BENIGN           → 0  Normal
  DoS / DDoS       → 1  DDoS
  PortScan         → 2  PortScan
  Brute Force / SSH-Patator / FTP-Patator → 3  BruteForce
  Bot / Infiltration / Web Attack / Heartbleed → 4  Botnet/Other
"""

import os
import glob
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
DATASET_DIR = r"C:\Users\Rohan\Downloads\ScanNet\dataset"   # ← change to your path
MODEL_PATH  = "iot_ids_model.pkl"
TEST_SIZE   = 0.25
N_ESTIMATORS = 200
RANDOM_STATE = 42

# ──────────────────────────────────────────────
# LABEL MAPPING
# ──────────────────────────────────────────────
LABEL_MAP = {
    "BENIGN":                    0,
    "DoS Hulk":                  1, "DoS GoldenEye": 1, "DoS slowloris": 1,
    "DoS Slowhttptest": 1, "DDoS": 1, "Heartbleed": 1,
    "PortScan":                  2,
    "FTP-Patator":               3, "SSH-Patator": 3,
    "Brute Force":               3, "XSS": 3, "Sql Injection": 3,
    "Bot":                       4, "Infiltration": 4, "Web Attack – Brute Force": 3,
    "Web Attack – XSS": 3, "Web Attack – Sql Injection": 3,
}
CLASS_NAMES = {0: "Normal", 1: "DDoS", 2: "PortScan", 3: "BruteForce", 4: "Botnet/Other"}

# ──────────────────────────────────────────────
# FEATURES  (subset that maps to live packets)
# ──────────────────────────────────────────────
FEATURE_COLS = [
    " Flow Duration",           # dur in microseconds
    " Total Fwd Packets",       # spkts
    " Total Backward Packets",  # dpkts
    " Total Length of Fwd Packets",   # sbytes
    " Total Length of Bwd Packets",   # dbytes
    " Fwd Packet Length Mean",
    " Bwd Packet Length Mean",
    " Flow Bytes/s",
    " Flow Packets/s",
    " Flow IAT Mean",           # inter-arrival time mean
    " Flow IAT Std",
    " Fwd IAT Mean",
    " Bwd IAT Mean",
    " Fwd Header Length",
    " Bwd Header Length",
    " SYN Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    " FIN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    "Destination Port",
    " Protocol",
]

# ──────────────────────────────────────────────
# LOAD & MERGE ALL CSVs
# ──────────────────────────────────────────────
def load_dataset(directory: str) -> pd.DataFrame:
    files = glob.glob(os.path.join(directory, "*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in: {directory}")

    frames = []
    for f in files:
        print(f"  Loading {os.path.basename(f)} …")
        chunk = pd.read_csv(f, low_memory=False)
        chunk.columns = chunk.columns.str.strip()
        frames.append(chunk)

    df = pd.concat(frames, ignore_index=True)
    print(f"  Total rows: {len(df):,}")
    return df


# ──────────────────────────────────────────────
# PREPROCESS
# ──────────────────────────────────────────────
def preprocess(df: pd.DataFrame):
    # Strip whitespace from column names (CICIDS CSVs often have leading spaces)
    df.columns = df.columns.str.strip()

    # Map labels
    label_col = "Label"
    df[label_col] = df[label_col].str.strip()
    df["target"] = df[label_col].map(LABEL_MAP)

    # Drop rows with unmapped labels
    unmapped = df["target"].isna().sum()
    if unmapped:
        print(f"  Dropping {unmapped} rows with unknown labels")
    df = df.dropna(subset=["target"])
    df["target"] = df["target"].astype(int)

    print("\nClass distribution:")
    for k, v in CLASS_NAMES.items():
        n = (df["target"] == k).sum()
        print(f"  {v:15s} {n:>8,}")

    # Select features
    available = [c for c in FEATURE_COLS if c in df.columns]
    missing   = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"\n  WARNING: missing columns (will be skipped): {missing}")

    X = df[available].copy()
    y = df["target"].copy()

    # Coerce to numeric, replace inf/nan with 0
    X = X.apply(pd.to_numeric, errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    return X, y, available


# ──────────────────────────────────────────────
# TRAIN
# ──────────────────────────────────────────────
def train(X, y, feature_cols):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    print(f"\nTraining RandomForest ({N_ESTIMATORS} trees) on {len(X_train):,} samples …")
    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=20,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification report:")
    target_names = [CLASS_NAMES[i] for i in sorted(CLASS_NAMES)]
    print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))

    bundle = {
        "model": clf,
        "features": feature_cols,
        "class_names": CLASS_NAMES,
    }
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    print(f"\n✅ Model saved → {MODEL_PATH}")
    return bundle


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== IoT IDS Training Pipeline ===\n")
    print("Loading dataset …")
    df = load_dataset(DATASET_DIR)

    print("\nPreprocessing …")
    X, y, feature_cols = preprocess(df)

    train(X, y, feature_cols)
