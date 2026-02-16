#!/usr/bin/env python3
"""
Extract CIS benchmark rules into structured CSV format
Manual extraction based on CIS PDF document
"""

import csv
import os

# CIS Rules extracted from benchmark document
CIS_RULES = [
    {
        'rule_id': 'CIS-5.2.1',
        'category': 'SSH',
        'severity': 'HIGH',
        'title': 'Ensure permissions on /etc/ssh/sshd_config are configured',
        'parameter': 'file_permissions',
        'expected_value': '600',
        'check_command': 'stat /etc/ssh/sshd_config',
        'remediation': 'chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config'
    },
    {
        'rule_id': 'CIS-5.2.4',
        'category': 'SSH',
        'severity': 'HIGH',
        'title': 'Ensure SSH Protocol is set to 2',
        'parameter': 'Protocol',
        'expected_value': '2',
        'check_command': 'grep "^Protocol" /etc/ssh/sshd_config',
        'remediation': 'Edit /etc/ssh/sshd_config and set Protocol 2'
    },
    {
        'rule_id': 'CIS-5.2.8',
        'category': 'SSH',
        'severity': 'CRITICAL',
        'title': 'Ensure SSH root login is disabled',
        'parameter': 'PermitRootLogin',
        'expected_value': 'no',
        'check_command': 'grep "^PermitRootLogin" /etc/ssh/sshd_config',
        'remediation': 'Edit /etc/ssh/sshd_config and set PermitRootLogin no'
    },
    {
        'rule_id': 'CIS-5.2.9',
        'category': 'SSH',
        'severity': 'CRITICAL',
        'title': 'Ensure SSH PermitEmptyPasswords is disabled',
        'parameter': 'PermitEmptyPasswords',
        'expected_value': 'no',
        'check_command': 'grep "^PermitEmptyPasswords" /etc/ssh/sshd_config',
        'remediation': 'Edit /etc/ssh/sshd_config and set PermitEmptyPasswords no'
    },
    {
        'rule_id': 'CIS-5.2.10',
        'category': 'SSH',
        'severity': 'HIGH',
        'title': 'Ensure SSH PasswordAuthentication is disabled',
        'parameter': 'PasswordAuthentication',
        'expected_value': 'no',
        'check_command': 'grep "^PasswordAuthentication" /etc/ssh/sshd_config',
        'remediation': 'Edit /etc/ssh/sshd_config and set PasswordAuthentication no'
    },
    {
        'rule_id': 'CIS-6.1.2',
        'category': 'FILE_PERM',
        'severity': 'HIGH',
        'title': 'Ensure permissions on /etc/passwd are configured',
        'parameter': 'file_permissions',
        'expected_value': '644',
        'check_command': 'stat /etc/passwd',
        'remediation': 'chmod 644 /etc/passwd'
    },
    {
        'rule_id': 'CIS-6.1.3',
        'category': 'FILE_PERM',
        'severity': 'CRITICAL',
        'title': 'Ensure permissions on /etc/shadow are configured',
        'parameter': 'file_permissions',
        'expected_value': '640',
        'check_command': 'stat /etc/shadow',
        'remediation': 'chmod 640 /etc/shadow'
    },
]

def save_cis_rules():
    """Save CIS rules to CSV file"""
    output_path = 'dataset/external/cleaned/cis_benchmark_rules.csv'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w', newline='') as f:
        fieldnames = ['rule_id', 'category', 'severity', 'title', 'parameter', 
                     'expected_value', 'check_command', 'remediation']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(CIS_RULES)
    
    print(f"✓ Saved {len(CIS_RULES)} CIS rules to {output_path}")
    
    # Print statistics
    from collections import Counter
    severity_counts = Counter([rule['severity'] for rule in CIS_RULES])
    category_counts = Counter([rule['category'] for rule in CIS_RULES])
    
    print("\nRule Statistics:")
    print(f"Total Rules: {len(CIS_RULES)}")
    print("\nBy Severity:")
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")
    print("\nBy Category:")
    for category, count in category_counts.items():
        print(f"  {category}: {count}")

if __name__ == '__main__':
    save_cis_rules()
