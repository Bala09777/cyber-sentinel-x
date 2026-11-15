import csv
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets" / "unsw_nb15"

PROTOCOLS = {"tcp": 0, "udp": 1, "icmp": 2}


def load_dataset(split):
    path = DATA / f"UNSW_NB15_{split}-set.csv"
    features, labels = [], []

    with path.open(newline="", encoding="utf-8-sig") as file:
        for row in csv.DictReader(file):
            proto = row["proto"].lower()

            if proto not in PROTOCOLS:
                continue

            features.append([
                float(row["spkts"]),
                float(row["sbytes"]),
                float(row["dur"]),
                float(PROTOCOLS[proto]),
            ])
            labels.append(int(row["label"]))

    return np.asarray(features), np.asarray(labels)


def main():
    print("Loading UNSW-NB15 datasets...")
    X_train, y_train = load_dataset("training")
    X_test, y_test = load_dataset("testing")

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples : {len(X_test)}")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    print("Training Random Forest...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nCONFUSION MATRIX")
    print(confusion_matrix(y_test, predictions))

    print("\nCLASSIFICATION REPORT")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attack"],
        zero_division=0,
    ))

    import joblib

    output = ROOT / "models" / "unsw_nb15_experimental.joblib"
    joblib.dump(model, output)
    print(f"Experimental model saved: {output}")
    print("Live ML model not modified.")


if __name__ == "__main__":
    main()
