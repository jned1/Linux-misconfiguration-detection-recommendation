"""
train_ml_model.py
-----------------
Trains a Random Forest classifier to predict severity of Linux
security misconfigurations, then saves the model + label encoder
to the models/ directory.

Usage:
    python3 scripts/training/train_ml_model.py
"""

import os
import json
import pickle
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings("ignore")

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRAIN_CSV   = os.path.join(BASE_DIR, "dataset", "final", "train",      "train_data.csv")
VAL_CSV     = os.path.join(BASE_DIR, "dataset", "final", "validation", "validation_data.csv")
TEST_CSV    = os.path.join(BASE_DIR, "dataset", "final", "test",       "test_data.csv")
MODELS_DIR  = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(MODELS_DIR,  exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Feature columns ────────────────────────────────────────────────────────
# All 17 features from create_features.py
FEATURE_COLS = [
    # Binary flags
    "feature_network_exposed",
    "feature_affects_auth",
    "feature_critical_file",
    "feature_root_access",
    "feature_weak_auth",
    "feature_kernel_hardening",
    "feature_network_stack",
    "feature_firewall_weak",
    "feature_world_writable",
    "feature_weak_protocol",
    "feature_is_vulnerable",
    "feature_high_risk_param",
    # Numeric scores
    "feature_category_risk",
    "feature_ssh_risk_score",
    "feature_perm_risk_score",
    "feature_pwd_weakness_score",
    "feature_combined_risk",        # most important — correlates directly with severity
]
TARGET_COL = "severity"
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


# ── Helpers ────────────────────────────────────────────────────────────────

def load_split(path: str, split_name: str) -> pd.DataFrame:
    if os.path.exists(path):
        df = pd.read_csv(path)
        print(f"  Loaded {split_name}: {len(df)} rows from {path}")
        return df
    fallback = os.path.join(BASE_DIR, "dataset", "processed", "features",
                            "dataset_with_features.csv")
    if not os.path.exists(fallback):
        raise FileNotFoundError(f"Neither {path} nor fallback {fallback} found.")
    print(f"  WARNING: {path} not found – using fallback split")
    full = pd.read_csv(fallback).sample(frac=1, random_state=42).reset_index(drop=True)
    n = len(full)
    if split_name == "train":      return full.iloc[: int(0.70 * n)]
    elif split_name == "validation": return full.iloc[int(0.70 * n): int(0.85 * n)]
    else:                           return full.iloc[int(0.85 * n):]


def encode_target(train_series, *other_series):
    le = LabelEncoder()
    le.fit(SEVERITY_ORDER)
    encoded = [le.transform(s) for s in (train_series, *other_series)]
    return le, *encoded


def get_available_features(df: pd.DataFrame) -> list:
    """Return only the feature columns that exist in the dataframe."""
    available = [c for c in FEATURE_COLS if c in df.columns]
    missing   = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"  ⚠ Missing features (will be skipped): {missing}")
    print(f"  Using {len(available)} features.")
    return available


def plot_confusion_matrix(cm, classes, save_path):
    fig, ax = plt.subplots(figsize=(7, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=classes, yticklabels=classes, ax=ax)
    ax.set_xlabel("Predicted", fontsize=12)
    ax.set_ylabel("Actual",    fontsize=12)
    ax.set_title("Confusion Matrix – Random Forest Severity Classifier", fontsize=13)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved confusion matrix → {save_path}")


def plot_feature_importance(model, feature_names, save_path):
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    fig, ax = plt.subplots(figsize=(10, 5))
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(feature_names)))
    ax.bar(range(len(feature_names)),
           importances[indices],
           color=[colors[i] for i in range(len(feature_names))])
    ax.set_xticks(range(len(feature_names)))
    ax.set_xticklabels(
        [feature_names[i].replace('feature_', '') for i in indices],
        rotation=35, ha="right", fontsize=9
    )
    ax.set_ylabel("Importance")
    ax.set_title("Feature Importances – Random Forest")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved feature importance chart → {save_path}")


def plot_severity_distribution(y_true_labels, y_pred_labels, classes, save_path):
    true_counts = {c: 0 for c in classes}
    pred_counts = {c: 0 for c in classes}
    for lbl in y_true_labels:
        if lbl in true_counts: true_counts[lbl] += 1
    for lbl in y_pred_labels:
        if lbl in pred_counts: pred_counts[lbl] += 1
    x = np.arange(len(classes))
    width = 0.35
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - width/2, [true_counts[c] for c in classes], width, label="Actual",    color="#4C72B0")
    ax.bar(x + width/2, [pred_counts[c] for c in classes], width, label="Predicted", color="#DD8452")
    ax.set_xticks(x)
    ax.set_xticklabels(classes)
    ax.set_ylabel("Count")
    ax.set_title("Actual vs Predicted Severity Distribution (Test Set)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved severity distribution chart → {save_path}")


# ── Main Training Routine ──────────────────────────────────────────────────

def train():
    print("\n" + "=" * 60)
    print("  Linux Misconfiguration – ML Model Training")
    print("=" * 60)

    # 1. Load data
    print("\n[1/5] Loading datasets...")
    train_df = load_split(TRAIN_CSV, "train")
    val_df   = load_split(VAL_CSV,   "validation")
    test_df  = load_split(TEST_CSV,  "test")

    # Drop rows with unknown severity
    for df in [train_df, val_df, test_df]:
        df.drop(df[~df[TARGET_COL].isin(SEVERITY_ORDER)].index, inplace=True)

    # Resolve available features (handles old CSVs with only 5 features)
    use_features = get_available_features(train_df)

    X_train    = train_df[use_features].fillna(0).values
    y_train_raw = train_df[TARGET_COL].values
    X_val      = val_df[use_features].fillna(0).values
    y_val_raw   = val_df[TARGET_COL].values
    X_test     = test_df[use_features].fillna(0).values
    y_test_raw  = test_df[TARGET_COL].values

    # 2. Encode labels
    print("\n[2/5] Encoding labels...")
    le, y_train, y_val, y_test = encode_target(y_train_raw, y_val_raw, y_test_raw)
    present_classes = np.unique(y_train)
    print(f"  Classes: {le.inverse_transform(present_classes)}")

    class_weights = compute_class_weight(
        class_weight="balanced", classes=present_classes, y=y_train
    )
    weight_dict = dict(zip(present_classes, class_weights))
    print(f"  Class weights: { {le.inverse_transform([k])[0]: round(v, 2) for k, v in weight_dict.items()} }")

    # 3. Train
    print("\n[3/5] Training Random Forest classifier...")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features='sqrt',
        class_weight=weight_dict,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    print("  Training complete.")

    y_val_pred = rf.predict(X_val)
    val_acc = accuracy_score(y_val, y_val_pred)
    val_f1  = f1_score(y_val, y_val_pred, average="weighted", zero_division=0)
    print(f"  Validation Accuracy      : {val_acc:.4f}")
    print(f"  Validation F1 (weighted) : {val_f1:.4f}")

    # 4. Evaluate
    print("\n[4/5] Evaluating on test set...")
    y_test_pred = rf.predict(X_test)
    test_acc = accuracy_score(y_test, y_test_pred)
    test_f1  = f1_score(y_test, y_test_pred, average="weighted", zero_division=0)

    present_test = np.unique(np.concatenate([y_test, y_test_pred]))
    class_names  = le.inverse_transform(present_test)

    print(f"  Test Accuracy        : {test_acc:.4f}")
    print(f"  Test F1 (weighted)   : {test_f1:.4f}")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_test_pred,
                                labels=present_test,
                                target_names=class_names,
                                zero_division=0))

    # Show top 5 most important features
    top_idx = np.argsort(rf.feature_importances_)[::-1][:5]
    print("  Top 5 features by importance:")
    for i in top_idx:
        print(f"    {use_features[i]:40s}  {rf.feature_importances_[i]:.4f}")

    cm = confusion_matrix(y_test, y_test_pred, labels=present_test)

    # 5. Save
    print("\n[5/5] Saving model and artefacts...")
    model_path   = os.path.join(MODELS_DIR, "random_forest_severity.pkl")
    encoder_path = os.path.join(MODELS_DIR, "label_encoder.pkl")
    meta_path    = os.path.join(MODELS_DIR, "model_metadata.json")

    with open(model_path,   "wb") as f: pickle.dump(rf, f)
    with open(encoder_path, "wb") as f: pickle.dump(le, f)
    print(f"  Model saved    → {model_path}")
    print(f"  Encoder saved  → {encoder_path}")

    metadata = {
        "model_type"      : "RandomForestClassifier",
        "n_estimators"    : 300,
        "feature_columns" : use_features,
        "target_column"   : TARGET_COL,
        "classes"         : list(le.classes_),
        "train_samples"   : int(len(X_train)),
        "val_accuracy"    : round(float(val_acc),  4),
        "val_f1_weighted" : round(float(val_f1),   4),
        "test_accuracy"   : round(float(test_acc), 4),
        "test_f1_weighted": round(float(test_f1),  4),
        "class_weights"   : {le.inverse_transform([k])[0]: round(v, 4)
                             for k, v in weight_dict.items()},
    }
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata saved → {meta_path}")

    plot_confusion_matrix(cm, class_names,
                          os.path.join(REPORTS_DIR, "confusion_matrix.png"))
    plot_feature_importance(rf, use_features,
                            os.path.join(REPORTS_DIR, "feature_importance.png"))
    plot_severity_distribution(
        y_test_raw,
        le.inverse_transform(y_test_pred),
        [c for c in SEVERITY_ORDER
         if c in set(y_test_raw) | set(le.inverse_transform(y_test_pred))],
        os.path.join(REPORTS_DIR, "severity_distribution.png"),
    )

    print("\n" + "=" * 60)
    print("  ✓ Training complete!")
    print(f"  Test Accuracy : {test_acc:.4f}")
    print(f"  Test F1       : {test_f1:.4f}")
    print("=" * 60 + "\n")

    return rf, le, metadata


if __name__ == "__main__":
    train()
