#!/usr/bin/env python3
"""
Master pipeline script (works with any shell)
"""

import subprocess
import sys
import os

def run_command(description, command):
    """Run a command and handle errors"""
    print(f"\n{description}")
    print("=" * 60)
    
    result = subprocess.run(
        command,
        shell=True,
        capture_output=False,
        text=True
    )
    
    if result.returncode != 0:
        print(f"ERROR: {description} failed!")
        sys.exit(1)
    
    print(f"✓ {description} completed")
    return result

def main():
    # Change to repo root
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    print("=" * 60)
    print("  DATASET CREATION PIPELINE")
    print("=" * 60)
    
    # Phase 1
    run_command(
        "Phase 1: Extracting CIS rules",
        "python3 scripts/collection/extract_cis_rules.py"
    )
    
    # Phase 2
    run_command(
        "Phase 2: Generating synthetic data",
        "python3 scripts/generation/generate_synthetic_configs.py"
    )
    
    # Phase 3
    run_command(
        "Phase 3: Labeling data",
        "python3 scripts/labeling/label_all_data.py"
    )
    
    # Phase 4
    run_command(
        "Phase 4: Creating features",
        "python3 scripts/labeling/create_features.py"
    )
    
    # Phase 5
    run_command(
        "Phase 5: Splitting dataset",
        "python3 scripts/labeling/split_dataset.py"
    )
    
    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETED!")
    print("=" * 60)
    print("\nDataset location: dataset/final/")
    print("\nFiles created:")
    
    for split in ['train', 'validation', 'test']:
        path = f'dataset/final/{split}/'
        if os.path.exists(path):
            files = os.listdir(path)
            print(f"\n{split}/:")
            for f in files:
                if f.endswith('.csv'):
                    size = os.path.getsize(os.path.join(path, f))
                    print(f"  - {f} ({size} bytes)")

if __name__ == '__main__':
    main()
