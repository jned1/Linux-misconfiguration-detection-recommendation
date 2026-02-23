#!/usr/bin/env python3
"""Integrate external datasets with your existing dataset"""

import pandas as pd
import json
import os

class ExternalDataIntegrator:
    def __init__(self):
        self.external_samples = []
    
    def load_processed_external_configs(self):
        external_file = 'dataset/external/cleaned/processed_external_data.json'
        
        if not os.path.exists(external_file):
            print(f"No external configs found")
            return []
        
        with open(external_file, 'r') as f:
            external_data = json.load(f)
        
        print(f"✓ Loaded {len(external_data)} external configurations")
        
        labeled_samples = []
        for config in external_data:
            labeled_samples.append({
                'config_id': config.get('config_id', 'UNKNOWN'),
                'category': config.get('category', 'GENERAL'),
                'parameter': config.get('config_id', 'unknown'),
                'expected_value': 'secure',
                'actual_value': 'secure',
                'is_compliant': True,
                'is_vulnerable': False,
                'severity': config.get('severity', 'MEDIUM'),
                'cis_reference': 'External',
                'timestamp': '2026-02-16',
                'source': config.get('source', 'external')
            })
        
        self.external_samples = labeled_samples
        return labeled_samples
    
    def merge_with_existing_dataset(self):
        existing_path = 'dataset/processed/labeled/master_labeled_dataset.csv'
        
        if os.path.exists(existing_path):
            existing_df = pd.read_csv(existing_path)
            print(f"Loaded {len(existing_df)} existing samples")
        else:
            existing_df = pd.DataFrame()
        
        if self.external_samples:
            external_df = pd.DataFrame(self.external_samples)
            
            all_columns = set(existing_df.columns) | set(external_df.columns)
            for col in all_columns:
                if col not in existing_df.columns:
                    existing_df[col] = None
                if col not in external_df.columns:
                    external_df[col] = None
            
            external_df = external_df[existing_df.columns]
            combined_df = pd.concat([existing_df, external_df], ignore_index=True)
            combined_df.to_csv(existing_path, index=False)
            
            print(f"\n✓ Merged: {len(existing_df)} + {len(external_df)} = {len(combined_df)} samples")
            return combined_df
        return existing_df

def main():
    print("=== External Dataset Integration ===\n")
    integrator = ExternalDataIntegrator()
    external_samples = integrator.load_processed_external_configs()
    
    if not external_samples:
        print("❌ No external data found!")
        print("Run: python3 scripts/collection/process_external_data.py")
        return
    
    integrator.merge_with_existing_dataset()
    print("\n✓ Integration complete!")

if __name__ == '__main__':
    main()
