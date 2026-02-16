#!/usr/bin/env python3
"""
Generate synthetic configuration variations
"""

import json
import os
import random
from itertools import product

def generate_ssh_configs():
    """Generate variations of SSH configurations"""
    configs = []
    
    # Parameter variations (smaller set for quick testing)
    permit_root = ['yes', 'no']
    password_auth = ['yes', 'no']
    empty_passwords = ['yes', 'no']
    
    config_id = 1
    
    # Generate combinations
    for root, pwd, empty in product(permit_root, password_auth, empty_passwords):
        config = {
            'config_id': f'SSH-{config_id:04d}',
            'category': 'SSH',
            'parameters': {
                'PermitRootLogin': root,
                'PasswordAuthentication': pwd,
                'PermitEmptyPasswords': empty,
            },
            'timestamp': f'2026-02-{random.randint(1, 28):02d}'
        }
        
        # Determine if vulnerable
        vulnerabilities = []
        severity = 'NONE'
        
        if root == 'yes':
            vulnerabilities.append('Root login enabled')
            severity = 'CRITICAL'
        if pwd == 'yes' and root == 'yes':
            vulnerabilities.append('Password auth for root')
            severity = 'CRITICAL'
        if empty == 'yes':
            vulnerabilities.append('Empty passwords allowed')
            severity = 'CRITICAL'
        
        config['vulnerabilities'] = vulnerabilities
        config['severity'] = severity
        config['is_vulnerable'] = len(vulnerabilities) > 0
        
        configs.append(config)
        config_id += 1
    
    return configs

def generate_file_permission_configs():
    """Generate file permission configurations"""
    configs = []
    
    critical_files = [
        ('/etc/passwd', '644', ['644', '666', '777']),
        ('/etc/shadow', '640', ['640', '644', '777']),
    ]
    
    config_id = 1
    
    for filepath, expected, variations in critical_files:
        for perm in variations:
            config = {
                'config_id': f'PERM-{config_id:04d}',
                'category': 'FILE_PERMISSIONS',
                'file': filepath,
                'actual_permissions': perm,
                'expected_permissions': expected,
                'is_vulnerable': perm != expected,
                'timestamp': f'2026-02-{random.randint(1, 28):02d}'
            }
            
            # Determine severity
            if perm in ['777', '666']:
                config['severity'] = 'CRITICAL'
                config['vulnerabilities'] = ['World readable/writable']
            elif perm != expected:
                config['severity'] = 'HIGH'
                config['vulnerabilities'] = ['Incorrect permissions']
            else:
                config['severity'] = 'NONE'
                config['vulnerabilities'] = []
            
            configs.append(config)
            config_id += 1
    
    return configs

def save_generated_data():
    """Save all generated configurations"""
    output_dir = 'dataset/generated'
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate SSH configs
    ssh_configs = generate_ssh_configs()
    with open(f'{output_dir}/ssh_configs.json', 'w') as f:
        json.dump(ssh_configs, f, indent=2)
    print(f"✓ Generated {len(ssh_configs)} SSH configurations")
    
    # Generate file permission configs
    perm_configs = generate_file_permission_configs()
    with open(f'{output_dir}/file_permission_configs.json', 'w') as f:
        json.dump(perm_configs, f, indent=2)
    print(f"✓ Generated {len(perm_configs)} file permission configurations")
    
    # Print statistics
    total = len(ssh_configs) + len(perm_configs)
    vulnerable = (
        sum(1 for c in ssh_configs if c['is_vulnerable']) +
        sum(1 for c in perm_configs if c['is_vulnerable'])
    )
    
    print(f"\n✓ Total configurations generated: {total}")
    print(f"  - Vulnerable: {vulnerable}")
    print(f"  - Secure: {total - vulnerable}")

if __name__ == '__main__':
    save_generated_data()
