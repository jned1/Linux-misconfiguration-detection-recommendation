#!/usr/bin/env python3
"""
Split dataset into train/validation/test sets
"""

import pandas as pd
import os
from sklearn.model_selection import train_test_split

def split_dataset(df, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15):
    """Split dataset with stratification"""
    
    print(f"Dataset size: {len(df)}")
    
    # First split: separate test set
    train_val_df, test_df = train_test_split(
        df,
        test_size=test_ratio,
        stratify=df['severity'],
        random_state=42
    )
    
    # Second split: separate train and validation
    val_ratio_adjusted = val_ratio / (train_ratio + val_ratio)
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=val_ratio_adjusted,
        stratify=train_val_df['severity'],
        random_state=42
    )
    
    print(f"\nSplit results:")
    print(f"  Training set: {len(train_df)} samples")
    print(f"  Validation set: {len(val_df)} samples")
    print(f"  Test set: {len(test_df)} samples")
    
    return train_df, val_df, test_df

def save_splits(train_df, val_df, test_df):
    """Save split datasets"""
    
    output_dir = 'dataset/final'
    
    train_df.to_csv(f'{output_dir}/train/train_data.csv', index=False)
    val_df.to_csv(f'{output_dir}/validation/validation_data.csv', index=False)
    test_df.to_csv(f'{output_dir}/test/test_data.csv', index=False)
    
    print(f"\n✓ Saved split datasets to {output_dir}/")

def main():
    print("=== Dataset Splitting ===\n")
    
    features_path = 'dataset/processed/features/dataset_with_features.csv'
    df = pd.read_csv(features_path)
    
    train_df, val_df, test_df = split_dataset(df)
    save_splits(train_df, val_df, test_df)
    
    print("\n✓ Dataset splitting completed")

if __name__ == '__main__':
    main()
