#!/usr/bin/env python3
"""
Feature engineering for ML model
"""

import pandas as pd
import os


def create_ml_features(df):
    """Create features for ML model"""

    # Feature 1: Is network-exposed (SSH category)
    df["feature_network_exposed"] = (df["category"] == "SSH").astype(int)

    # Feature 2: Affects authentication
    auth_params = [
        "PermitRootLogin",
        "PasswordAuthentication",
        "PermitEmptyPasswords",
    ]
    df["feature_affects_auth"] = df["parameter"].isin(auth_params).astype(int)

    # Feature 3: Critical file
    critical_files = ["/etc/shadow"]
    df["feature_critical_file"] = df["parameter"].isin(critical_files).astype(int)

    # Feature 4: Root access enabled
    df["feature_root_access"] = (
        (df["parameter"] == "PermitRootLogin")
        & (df["actual_value"] == "yes")
    ).astype(int)

    # Feature 5: Weak authentication
    df["feature_weak_auth"] = (
        (
            (df["parameter"] == "PasswordAuthentication")
            & (df["actual_value"] == "yes")
        )
        |
        (
            (df["parameter"] == "PermitEmptyPasswords")
            & (df["actual_value"] == "yes")
        )
    ).astype(int)

    return df


def save_feature_dataset(df):
    """Save dataset with features"""

    output_path = "dataset/processed/features/dataset_with_features.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    df.to_csv(output_path, index=False)

    print(f"✓ Saved feature dataset: {output_path}")

    feature_cols = [c for c in df.columns if c.startswith("feature_")]
    print(f"  Features created: {len(feature_cols)}")

    return df


def main():
    print("Creating ML features...\n")

    labeled_path = "dataset/processed/labeled/master_labeled_dataset.csv"

    if not os.path.exists(labeled_path):
        print(f"Error: File not found -> {labeled_path}")
        return

    df = pd.read_csv(labeled_path)
    print(f"Loaded {len(df)} labeled samples")

    df_with_features = create_ml_features(df)
    save_feature_dataset(df_with_features)

    print("\n✓ Feature engineering completed successfully")


if __name__ == "__main__":
    main()
