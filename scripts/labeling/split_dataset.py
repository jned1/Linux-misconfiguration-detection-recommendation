#!/usr/bin/env python3
"""
Split dataset into train / validation / test sets.
Handles class imbalance and small classes gracefully.
"""

import pandas as pd
import os
from sklearn.model_selection import train_test_split


def split_dataset(df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15):
    print(f'Dataset size : {len(df)} rows')
    print(f'Severity distribution:\n{df["severity"].value_counts().to_string()}\n')

    # Check if any class has too few samples for stratification
    min_samples = df['severity'].value_counts().min()
    use_stratify = min_samples >= 3  # need at least 3 to split into 3 sets

    if not use_stratify:
        print('⚠ Some classes have < 3 samples — disabling stratification.')

    stratify_col = df['severity'] if use_stratify else None

    # Split off test set
    train_val_df, test_df = train_test_split(
        df,
        test_size=test_ratio,
        stratify=stratify_col,
        random_state=42,
    )

    # Split remaining into train + validation
    val_ratio_adjusted = val_ratio / (train_ratio + val_ratio)
    stratify_col2 = train_val_df['severity'] if use_stratify else None

    train_df, val_df = train_test_split(
        train_val_df,
        test_size=val_ratio_adjusted,
        stratify=stratify_col2,
        random_state=42,
    )

    print('Split results:')
    print(f'  Training set   : {len(train_df)} samples')
    print(f'  Validation set : {len(val_df)} samples')
    print(f'  Test set       : {len(test_df)} samples')

    print('\nTrain severity distribution:')
    print(train_df['severity'].value_counts().to_string())

    return train_df, val_df, test_df


def save_splits(train_df, val_df, test_df):
    output_dir = 'dataset/final'
    os.makedirs(f'{output_dir}/train',      exist_ok=True)
    os.makedirs(f'{output_dir}/validation', exist_ok=True)
    os.makedirs(f'{output_dir}/test',       exist_ok=True)

    train_df.to_csv(f'{output_dir}/train/train_data.csv',           index=False)
    val_df.to_csv(  f'{output_dir}/validation/validation_data.csv', index=False)
    test_df.to_csv( f'{output_dir}/test/test_data.csv',             index=False)

    print(f'\n✓ Saved split datasets to {output_dir}/')


def main():
    print('=== Dataset Splitting ===\n')

    features_path = 'dataset/processed/features/dataset_with_features.csv'
    if not os.path.exists(features_path):
        print(f'Error: File not found → {features_path}')
        return

    df = pd.read_csv(features_path)
    train_df, val_df, test_df = split_dataset(df)
    save_splits(train_df, val_df, test_df)

    print('\n✓ Dataset splitting completed')


if __name__ == '__main__':
    main()
