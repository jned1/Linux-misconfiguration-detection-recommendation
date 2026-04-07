#!/usr/bin/env python3
"""
Label all generated configurations into a master dataset.
Handles: SSH, FILE_PERMISSIONS, PASSWORD_POLICY, FIREWALL, SYSCTL
"""

import json
import os
import pandas as pd

labeled_data = []
generated_dir = 'dataset/generated'

# CIS references per parameter
CIS_MAP = {
    'PermitRootLogin':           'CIS-5.2.8',
    'PasswordAuthentication':    'CIS-5.2.10',
    'PermitEmptyPasswords':      'CIS-5.2.9',
    'Protocol':                  'CIS-5.2.2',
    'MaxAuthTries':              'CIS-5.2.5',
    'X11Forwarding':             'CIS-5.2.6',
    'PermitUserEnvironment':     'CIS-5.2.11',
    'Port':                      'CIS-5.2.1',
    '/etc/passwd':               'CIS-6.1.2',
    '/etc/shadow':               'CIS-6.1.3',
    '/etc/group':                'CIS-6.1.4',
    '/etc/gshadow':              'CIS-6.1.5',
    '/etc/ssh/sshd_config':      'CIS-5.2.1',
    '/etc/sudoers':              'CIS-5.3.1',
    '/etc/crontab':              'CIS-5.1.2',
    '/etc/hosts':                'CIS-3.4.1',
    '/boot/grub/grub.cfg':       'CIS-1.4.1',
    '/etc/fstab':                'CIS-1.1.1',
    'PASS_MIN_LEN':              'CIS-5.4.1',
    'PASS_MAX_DAYS':             'CIS-5.4.1',
    'enabled':                   'CIS-3.6.1',
    'default_policy':            'CIS-3.6.2',
    'net.ipv4.ip_forward':       'CIS-3.1.1',
    'kernel.randomize_va_space': 'CIS-1.5.3',
    'net.ipv4.tcp_syncookies':   'CIS-3.2.8',
    'kernel.core_dumps':         'CIS-1.5.1',
}

def get_cis(param):
    return CIS_MAP.get(param, 'CIS-GENERAL')


# ─── SSH ──────────────────────────────────────────────────────────────────────

ssh_rules = [
    # (param_name, expected_value, severity_if_wrong)
    ('PermitRootLogin',       'no',  'CRITICAL'),
    ('PasswordAuthentication','no',  'HIGH'),
    ('PermitEmptyPasswords',  'no',  'CRITICAL'),
    ('Protocol',              '2',   'CRITICAL'),
    ('MaxAuthTries',          '3',   'MEDIUM'),     # anything > 3 is bad
    ('X11Forwarding',         'no',  'LOW'),
    ('PermitUserEnvironment', 'no',  'LOW'),
]

ssh_path = f'{generated_dir}/ssh_configs.json'
if os.path.exists(ssh_path):
    with open(ssh_path) as f:
        ssh_configs = json.load(f)

    for config in ssh_configs:
        params = config['parameters']
        for param_name, expected, severity in ssh_rules:
            if param_name not in params:
                continue
            actual = str(params[param_name])

            # MaxAuthTries: compliant if <= 3
            if param_name == 'MaxAuthTries':
                try:
                    compliant = int(actual) <= 3
                except ValueError:
                    compliant = False
            else:
                compliant = (actual.lower() == expected.lower())

            labeled_data.append({
                'config_id':    config['config_id'],
                'category':     'SSH',
                'parameter':    param_name,
                'expected_value': expected,
                'actual_value': actual,
                'is_compliant': compliant,
                'is_vulnerable': not compliant,
                'severity':     'NONE' if compliant else severity,
                'cis_reference': get_cis(param_name),
                'timestamp':    config['timestamp'],
            })

    print(f'✓ Labeled {len(ssh_configs)} SSH configs  →  {sum(1 for r in labeled_data if r["category"]=="SSH")} rows')


# ─── File Permissions ─────────────────────────────────────────────────────────

perm_path = f'{generated_dir}/file_permission_configs.json'
if os.path.exists(perm_path):
    before = len(labeled_data)
    with open(perm_path) as f:
        perm_configs = json.load(f)

    for config in perm_configs:
        filepath = config['file']
        actual   = config['actual_permissions']
        expected = config['expected_permissions']
        compliant = (actual == expected)

        if actual in ['777', '666']:
            severity = 'CRITICAL'
        elif actual in ['664', '660', '646'] and not compliant:
            severity = 'HIGH'
        elif not compliant:
            severity = 'MEDIUM'
        else:
            severity = 'NONE'

        labeled_data.append({
            'config_id':     config['config_id'],
            'category':      'FILE_PERMISSIONS',
            'parameter':     filepath,
            'expected_value': expected,
            'actual_value':  actual,
            'is_compliant':  compliant,
            'is_vulnerable': not compliant,
            'severity':      severity,
            'cis_reference': get_cis(filepath),
            'timestamp':     config['timestamp'],
        })

    print(f'✓ Labeled {len(perm_configs)} permission configs  →  {len(labeled_data)-before} rows')


# ─── Password Policy ──────────────────────────────────────────────────────────

pwd_path = f'{generated_dir}/password_policy_configs.json'
if os.path.exists(pwd_path):
    before = len(labeled_data)
    with open(pwd_path) as f:
        pwd_configs = json.load(f)

    pwd_rules = [
        ('PASS_MIN_LEN',  '14',    'HIGH'),
        ('PASS_MAX_DAYS', '90',    'MEDIUM'),
        ('PASS_MIN_DAYS', '1',     'LOW'),
        ('PASS_WARN_AGE', '7',     'LOW'),
        ('complexity',    'yes',   'MEDIUM'),
    ]

    for config in pwd_configs:
        params = config['parameters']
        for param_name, expected, severity in pwd_rules:
            if param_name not in params:
                continue
            actual = str(params[param_name])

            if param_name == 'PASS_MIN_LEN':
                try:
                    compliant = int(actual) >= int(expected)
                except ValueError:
                    compliant = False
            elif param_name == 'PASS_MAX_DAYS':
                try:
                    compliant = int(actual) <= int(expected)
                except ValueError:
                    compliant = False
            elif param_name in ('PASS_MIN_DAYS', 'PASS_WARN_AGE'):
                try:
                    compliant = int(actual) >= int(expected)
                except ValueError:
                    compliant = False
            else:
                compliant = (actual.lower() == expected.lower())

            labeled_data.append({
                'config_id':     config['config_id'],
                'category':      'PASSWORD_POLICY',
                'parameter':     param_name,
                'expected_value': expected,
                'actual_value':  actual,
                'is_compliant':  compliant,
                'is_vulnerable': not compliant,
                'severity':      'NONE' if compliant else severity,
                'cis_reference': get_cis(param_name),
                'timestamp':     config['timestamp'],
            })

    print(f'✓ Labeled {len(pwd_configs)} password policy configs  →  {len(labeled_data)-before} rows')


# ─── Firewall ─────────────────────────────────────────────────────────────────

fw_path = f'{generated_dir}/firewall_configs.json'
if os.path.exists(fw_path):
    before = len(labeled_data)
    with open(fw_path) as f:
        fw_configs = json.load(f)

    fw_rules = [
        ('enabled',        'yes',    'CRITICAL'),
        ('default_policy', 'DROP',   'HIGH'),
        ('logging',        'yes',    'LOW'),
    ]

    for config in fw_configs:
        params = config['parameters']
        for param_name, expected, severity in fw_rules:
            if param_name not in params:
                continue
            actual = str(params[param_name])
            compliant = (actual.lower() == expected.lower())

            labeled_data.append({
                'config_id':     config['config_id'],
                'category':      'FIREWALL',
                'parameter':     param_name,
                'expected_value': expected,
                'actual_value':  actual,
                'is_compliant':  compliant,
                'is_vulnerable': not compliant,
                'severity':      'NONE' if compliant else severity,
                'cis_reference': get_cis(param_name),
                'timestamp':     config['timestamp'],
            })

    print(f'✓ Labeled {len(fw_configs)} firewall configs  →  {len(labeled_data)-before} rows')


# ─── Sysctl ───────────────────────────────────────────────────────────────────

sysctl_path = f'{generated_dir}/sysctl_configs.json'
if os.path.exists(sysctl_path):
    before = len(labeled_data)
    with open(sysctl_path) as f:
        sysctl_configs = json.load(f)

    sysctl_expected = {
        'net.ipv4.ip_forward':               ('0', 'MEDIUM'),
        'net.ipv4.conf.all.send_redirects':   ('0', 'MEDIUM'),
        'net.ipv4.conf.all.accept_redirects': ('0', 'MEDIUM'),
        'net.ipv4.conf.all.log_martians':     ('1', 'LOW'),
        'kernel.randomize_va_space':          ('2', 'HIGH'),
        'kernel.core_dumps':                  ('0', 'MEDIUM'),
        'net.ipv4.tcp_syncookies':            ('1', 'HIGH'),
        'fs.suid_dumpable':                   ('0', 'MEDIUM'),
    }

    for config in sysctl_configs:
        params = config['parameters']
        for param_name, actual in params.items():
            if param_name not in sysctl_expected:
                continue
            expected, severity = sysctl_expected[param_name]
            compliant = (str(actual) == expected)

            labeled_data.append({
                'config_id':     config['config_id'],
                'category':      'SYSCTL',
                'parameter':     param_name,
                'expected_value': expected,
                'actual_value':  str(actual),
                'is_compliant':  compliant,
                'is_vulnerable': not compliant,
                'severity':      'NONE' if compliant else severity,
                'cis_reference': get_cis(param_name),
                'timestamp':     config['timestamp'],
            })

    print(f'✓ Labeled {len(sysctl_configs)} sysctl configs  →  {len(labeled_data)-before} rows')


# ─── Save ─────────────────────────────────────────────────────────────────────

os.makedirs('dataset/processed/labeled', exist_ok=True)
df = pd.DataFrame(labeled_data)
df.to_csv('dataset/processed/labeled/master_labeled_dataset.csv', index=False)

print(f'\n✓ Saved {len(df)} labeled samples to master_labeled_dataset.csv')
print(f'  Vulnerable : {df["is_vulnerable"].sum()}')
print(f'  Compliant  : {(~df["is_vulnerable"]).sum()}')
print(f'\nSeverity distribution:')
print(df['severity'].value_counts().to_string())
print(f'\nCategory distribution:')
print(df['category'].value_counts().to_string())
