#!/usr/bin/env python3
"""
Process external datasets and convert to our format
"""

import os
import json
import pandas as pd
from pathlib import Path

def process_linux_baseline():
    """Process dev-sec/linux-baseline"""
    
    baseline_path = 'dataset/external/public/linux-baseline/controls'
    
    if not os.path.exists(baseline_path):
        print("linux-baseline not found, skipping")
        return []
    
    samples = []
    
    # Count .rb files
    control_files = list(Path(baseline_path).glob('*.rb'))
    
    for control_file in control_files:
        # Simple extraction - each file is a control
        control_id = control_file.stem
        
        samples.append({
            'config_id': f'BASELINE-{control_id}',
            'category': 'HARDENING',
            'severity': 'MEDIUM',
            'source': 'linux-baseline',
            'is_vulnerable': False  # These are secure configs
        })
    
    print(f" Processed {len(samples)} from linux-baseline")
    return samples

def process_debian_cis():
    """Process ovh/debian-cis"""
    
    cis_path = 'dataset/external/public/debian-cis/bin/hardening'
    
    if not os.path.exists(cis_path):
        print("debian-cis not found, skipping")
        return []
    
    samples = []
    
    # Each .sh file is a CIS check
    for script in Path(cis_path).glob('*.sh'):
        script_name = script.stem
        
        samples.append({
            'config_id': f'DEB-CIS-{script_name}',
            'category': 'CIS',
            'severity': 'HIGH',
            'source': 'debian-cis',
            'is_vulnerable': False
        })
    
    print(f" Processed {len(samples)} from debian-cis")
    return samples

def process_nsl_kdd():
    """Process NSL-KDD dataset"""
    
    nsl_path = 'dataset/external/public/nsl-kdd/KDDTrain+.txt'
    
    if not os.path.exists(nsl_path):
        print("NSL-KDD not found, skipping")
        return []
    
    # NSL-KDD is network intrusion data
    # We'll just count it as reference data
    
    df = pd.read_csv(nsl_path, header=None)
    
    print(f" Found NSL-KDD with {len(df)} records (reference data)")
    
    return [{
        'config_id': 'NSL-KDD-REF',
        'category': 'NETWORK',
        'source': 'nsl-kdd',
        'record_count': len(df)
    }]

def process_sample_external():
    """Process our created sample data"""
    
    sample_path = 'dataset/external/public/sample_external/external_configs.json'
    
    if not os.path.exists(sample_path):
        print("Sample external data not found, skipping")
        return []
    
    with open(sample_path, 'r') as f:
        samples = json.load(f)
    
    print(f" Processed {len(samples)} from sample external data")
    return samples

def save_processed_data(all_samples):
    """Save all processed external data"""
    
    if not all_samples:
        print("No external data to save")
        return
    
    output_path = 'dataset/external/cleaned/processed_external_data.json'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(all_samples, f, indent=2)
    
    print(f"\n✓ Saved {len(all_samples)} external samples")
    print(f"  Output: {output_path}")

def main():
    print("=== Processing External Datasets ===\n")
    
    all_samples = []
    
    # Process all available sources
    all_samples.extend(process_linux_baseline())
    all_samples.extend(process_debian_cis())
    all_samples.extend(process_nsl_kdd())
    all_samples.extend(process_sample_external())
    
    # Save
    save_processed_data(all_samples)
    
    if all_samples:
        print(f"\n✓ Total external samples collected: {len(all_samples)}")
    else:
        print("\n No external data found. Run download script first:")
        print("  bash scripts/collection/download_github_datasets.sh")

if __name__ == '__main__':
    main()
