#!/usr/bin/env python3
import json
import os
import pandas as pd

labeled_data = []

# Load SSH configs
with open('dataset/generated/ssh_configs.json', 'r') as f:
    ssh_configs = json.load(f)

# Label each SSH config
for config in ssh_configs:
    params = config['parameters']
    
    for param_name, expected, severity, rule_id in [
        ('PermitRootLogin', 'no', 'CRITICAL', 'CIS-5.2.8'),
        ('PasswordAuthentication', 'no', 'HIGH', 'CIS-5.2.10'),
        ('PermitEmptyPasswords', 'no', 'CRITICAL', 'CIS-5.2.9'),
    ]:
        actual = str(params.get(param_name, 'NOT_SET'))
        compliant = (actual == expected)
        
        labeled_data.append({
            'config_id': config['config_id'],
            'category': 'SSH',
            'parameter': param_name,
            'expected_value': expected,
            'actual_value': actual,
            'is_compliant': compliant,
            'is_vulnerable': not compliant,
            'severity': 'NONE' if compliant else severity,
            'cis_reference': rule_id,
            'timestamp': config['timestamp']
        })

print(f"✓ Labeled {len(ssh_configs)} SSH configs")

# Load permission configs
with open('dataset/generated/file_permission_configs.json', 'r') as f:
    perm_configs = json.load(f)

# Label each permission config
for config in perm_configs:
    filepath = config['file']
    actual = config['actual_permissions']
    expected = config['expected_permissions']
    compliant = (actual == expected)
    
    if actual in ['777', '666']:
        severity = 'CRITICAL'
    elif not compliant:
        severity = 'HIGH'
    else:
        severity = 'NONE'
    
    labeled_data.append({
        'config_id': config['config_id'],
        'category': 'FILE_PERMISSIONS',
        'parameter': filepath,
        'expected_value': expected,
        'actual_value': actual,
        'is_compliant': compliant,
        'is_vulnerable': not compliant,
        'severity': severity,
        'cis_reference': 'CIS-6.1.2' if 'passwd' in filepath else 'CIS-6.1.3',
        'timestamp': config['timestamp']
    })

print(f"✓ Labeled {len(perm_configs)} permission configs")

# Save to CSV
os.makedirs('dataset/processed/labeled', exist_ok=True)
df = pd.DataFrame(labeled_data)
df.to_csv('dataset/processed/labeled/master_labeled_dataset.csv', index=False)

print(f"\n✓ Saved {len(df)} labeled samples")
print(f"Vulnerable: {df['is_vulnerable'].sum()}")
print(f"\nSeverity:\n{df['severity'].value_counts()}")

