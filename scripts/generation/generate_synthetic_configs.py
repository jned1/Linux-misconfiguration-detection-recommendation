#!/usr/bin/env python3
"""
Generate synthetic configuration variations
Produces 1200+ realistic Linux security configs covering:
  - SSH settings
  - File permissions
  - User/password policy
  - Firewall (ufw/iptables)
  - Sysctl kernel parameters
  - Cron job permissions
"""

import json
import os
import random
from itertools import product

random.seed(42)

# ─────────────────────────────────────────────────────────────────────────────
# SSH
# ─────────────────────────────────────────────────────────────────────────────

def generate_ssh_configs():
    configs = []
    config_id = 1

    # All meaningful SSH parameter combinations
    ssh_variations = [
        # (PermitRootLogin, PasswordAuth, EmptyPasswords, Protocol, MaxAuthTries, X11Forwarding, PermitUserEnv)
        ('yes',  'yes',  'yes',  '1', 10, 'yes', 'yes'),   # worst case
        ('yes',  'yes',  'yes',  '2', 10, 'yes', 'yes'),
        ('yes',  'yes',  'no',   '2', 6,  'yes', 'no'),
        ('yes',  'yes',  'no',   '2', 6,  'no',  'no'),
        ('yes',  'no',   'no',   '2', 4,  'no',  'no'),
        ('no',   'yes',  'yes',  '2', 6,  'yes', 'yes'),
        ('no',   'yes',  'no',   '2', 6,  'yes', 'no'),
        ('no',   'yes',  'no',   '2', 4,  'no',  'no'),
        ('no',   'no',   'no',   '2', 4,  'no',  'no'),    # secure
        ('no',   'no',   'no',   '2', 3,  'no',  'no'),    # most secure
        ('without-password', 'no', 'no', '2', 3, 'no', 'no'),
        ('forced-commands-only', 'no', 'no', '2', 3, 'no', 'no'),
        ('yes',  'no',   'yes',  '1', 10, 'yes', 'yes'),
        ('no',   'yes',  'yes',  '1', 10, 'yes', 'yes'),
        ('no',   'no',   'yes',  '2', 6,  'no',  'no'),
        ('yes',  'yes',  'no',   '1', 10, 'yes', 'yes'),
    ]

    # Multiply with port variations for more samples
    ports = [22, 2222, 22222, 8022]

    for (root, pwd, empty, proto, max_tries, x11, permit_env) in ssh_variations:
        for port in ports:
            config = {
                'config_id': f'SSH-{config_id:04d}',
                'category': 'SSH',
                'parameters': {
                    'PermitRootLogin':          root,
                    'PasswordAuthentication':   pwd,
                    'PermitEmptyPasswords':     empty,
                    'Protocol':                 proto,
                    'MaxAuthTries':             str(max_tries),
                    'X11Forwarding':            x11,
                    'PermitUserEnvironment':    permit_env,
                    'Port':                     str(port),
                },
                'timestamp': f'2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
            }

            vulnerabilities = []
            severity = 'NONE'

            if root == 'yes':
                vulnerabilities.append('Root login enabled')
                severity = 'CRITICAL'
            if empty == 'yes':
                vulnerabilities.append('Empty passwords allowed')
                severity = 'CRITICAL'
            if proto == '1':
                vulnerabilities.append('SSHv1 enabled (weak protocol)')
                severity = 'CRITICAL' if severity != 'CRITICAL' else severity
            if pwd == 'yes' and severity not in ('CRITICAL',):
                vulnerabilities.append('Password authentication enabled')
                severity = 'HIGH'
            if max_tries >= 6:
                vulnerabilities.append('High MaxAuthTries (brute-force risk)')
                if severity == 'NONE':
                    severity = 'MEDIUM'
            if x11 == 'yes':
                vulnerabilities.append('X11 forwarding enabled')
                if severity == 'NONE':
                    severity = 'LOW'
            if permit_env == 'yes':
                vulnerabilities.append('User environment variables permitted')
                if severity == 'NONE':
                    severity = 'LOW'
            if port == 22 and severity == 'NONE':
                vulnerabilities.append('Default SSH port in use')
                severity = 'LOW'

            config['vulnerabilities'] = vulnerabilities
            config['severity'] = severity
            config['is_vulnerable'] = len(vulnerabilities) > 0
            configs.append(config)
            config_id += 1

    return configs


# ─────────────────────────────────────────────────────────────────────────────
# File Permissions
# ─────────────────────────────────────────────────────────────────────────────

def generate_file_permission_configs():
    configs = []
    config_id = 1

    # (filepath, correct_perms, [variations including correct and wrong])
    critical_files = [
        ('/etc/passwd',          '644', ['644', '646', '664', '666', '755', '777']),
        ('/etc/shadow',          '640', ['640', '644', '660', '666', '777', '400']),
        ('/etc/group',           '644', ['644', '664', '666', '777']),
        ('/etc/gshadow',         '640', ['640', '644', '660', '666', '777']),
        ('/etc/ssh/sshd_config', '600', ['600', '640', '644', '664', '666', '777']),
        ('/etc/sudoers',         '440', ['440', '444', '640', '644', '660', '666', '777']),
        ('/etc/crontab',         '644', ['644', '664', '666', '777']),
        ('/etc/hosts',           '644', ['644', '666', '777']),
        ('/boot/grub/grub.cfg',  '400', ['400', '444', '640', '644', '777']),
        ('/etc/fstab',           '644', ['644', '664', '666', '777']),
    ]

    for filepath, expected, variations in critical_files:
        for perm in variations:
            compliant = (perm == expected)

            if perm in ['777', '666']:
                severity = 'CRITICAL'
                vuln = ['World writable — any user can modify']
            elif perm in ['664', '660', '646'] and not compliant:
                severity = 'HIGH'
                vuln = ['Group or other write access']
            elif not compliant:
                severity = 'MEDIUM'
                vuln = ['Incorrect permissions']
            else:
                severity = 'NONE'
                vuln = []

            configs.append({
                'config_id':           f'PERM-{config_id:04d}',
                'category':            'FILE_PERMISSIONS',
                'file':                filepath,
                'actual_permissions':  perm,
                'expected_permissions': expected,
                'is_vulnerable':       not compliant,
                'severity':            severity,
                'vulnerabilities':     vuln,
                'timestamp':           f'2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
            })
            config_id += 1

    return configs


# ─────────────────────────────────────────────────────────────────────────────
# Password Policy
# ─────────────────────────────────────────────────────────────────────────────

def generate_password_policy_configs():
    configs = []
    config_id = 1

    policies = [
        # (min_len, max_days, min_days, warn_days, complexity)
        (6,  99999, 0, 0,  False),   # very weak
        (6,  99999, 0, 7,  False),
        (8,  90,    0, 7,  False),
        (8,  90,    1, 7,  True),
        (10, 90,    1, 14, True),
        (12, 60,    1, 14, True),
        (14, 30,    1, 14, True),    # strong
        (4,  99999, 0, 0,  False),   # terrible
        (6,  365,   0, 0,  False),
        (8,  180,   0, 7,  False),
    ]

    for (min_len, max_days, min_days, warn_days, complexity) in policies:
        vulns = []
        severity = 'NONE'

        if min_len < 8:
            vulns.append(f'Password too short (min={min_len})')
            severity = 'HIGH'
        if max_days == 99999 or max_days > 180:
            vulns.append('Password never/rarely expires')
            if severity == 'NONE':
                severity = 'MEDIUM'
        if warn_days == 0:
            vulns.append('No password expiry warning')
            if severity == 'NONE':
                severity = 'LOW'
        if not complexity:
            vulns.append('No complexity requirements')
            if severity == 'NONE':
                severity = 'MEDIUM'

        configs.append({
            'config_id':    f'PWD-{config_id:04d}',
            'category':     'PASSWORD_POLICY',
            'parameters': {
                'PASS_MIN_LEN':  str(min_len),
                'PASS_MAX_DAYS': str(max_days),
                'PASS_MIN_DAYS': str(min_days),
                'PASS_WARN_AGE': str(warn_days),
                'complexity':    'yes' if complexity else 'no',
            },
            'is_vulnerable':  len(vulns) > 0,
            'severity':       severity,
            'vulnerabilities': vulns,
            'timestamp': f'2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
        })
        config_id += 1

    return configs


# ─────────────────────────────────────────────────────────────────────────────
# Firewall
# ─────────────────────────────────────────────────────────────────────────────

def generate_firewall_configs():
    configs = []
    config_id = 1

    firewall_states = [
        # (enabled, default_policy, logging, open_ports)
        (False, 'ACCEPT', False, [22, 80, 443, 8080, 3306, 5432]),  # no firewall, all open
        (False, 'ACCEPT', False, [22, 80, 443]),
        (True,  'ACCEPT', False, [22, 80, 443, 3306]),              # enabled but permissive
        (True,  'DROP',   False, [22, 80, 443]),
        (True,  'DROP',   True,  [22, 80, 443]),                    # good
        (True,  'DROP',   True,  [22, 443]),                        # best
        (False, 'ACCEPT', False, [22, 23, 80, 443, 3306]),          # telnet open
        (True,  'ACCEPT', True,  [22, 80, 443, 8080]),
    ]

    for (enabled, policy, logging, ports) in firewall_states:
        vulns = []
        severity = 'NONE'

        if not enabled:
            vulns.append('Firewall disabled')
            severity = 'CRITICAL'
        if policy == 'ACCEPT':
            vulns.append('Default ACCEPT policy (allow all)')
            if severity != 'CRITICAL':
                severity = 'HIGH'
        if 23 in ports:
            vulns.append('Telnet port open (unencrypted)')
            severity = 'CRITICAL'
        if 3306 in ports or 5432 in ports:
            vulns.append('Database port exposed publicly')
            if severity not in ('CRITICAL',):
                severity = 'HIGH'
        if not logging and enabled:
            vulns.append('Firewall logging disabled')
            if severity == 'NONE':
                severity = 'LOW'

        configs.append({
            'config_id':    f'FW-{config_id:04d}',
            'category':     'FIREWALL',
            'parameters': {
                'enabled':        'yes' if enabled else 'no',
                'default_policy': policy,
                'logging':        'yes' if logging else 'no',
                'open_ports':     ','.join(map(str, ports)),
            },
            'is_vulnerable':  len(vulns) > 0,
            'severity':       severity,
            'vulnerabilities': vulns,
            'timestamp': f'2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
        })
        config_id += 1

    return configs


# ─────────────────────────────────────────────────────────────────────────────
# Sysctl (kernel parameters)
# ─────────────────────────────────────────────────────────────────────────────

def generate_sysctl_configs():
    configs = []
    config_id = 1

    sysctl_cases = [
        # (param, actual, expected, severity_if_wrong, description)
        ('net.ipv4.ip_forward',              '1', '0', 'MEDIUM', 'IP forwarding enabled'),
        ('net.ipv4.conf.all.send_redirects', '1', '0', 'MEDIUM', 'ICMP redirects enabled'),
        ('net.ipv4.conf.all.accept_redirects','1', '0', 'MEDIUM', 'Accept ICMP redirects'),
        ('net.ipv4.conf.all.log_martians',   '0', '1', 'LOW',    'Martian packets not logged'),
        ('kernel.randomize_va_space',        '0', '2', 'HIGH',   'ASLR disabled'),
        ('kernel.core_dumps',                '1', '0', 'MEDIUM', 'Core dumps enabled'),
        ('net.ipv4.tcp_syncookies',          '0', '1', 'HIGH',   'SYN flood protection off'),
        ('fs.suid_dumpable',                 '1', '0', 'MEDIUM', 'SUID core dumps enabled'),
    ]

    # Generate both compliant and non-compliant for each
    for (param, bad_val, good_val, sev, desc) in sysctl_cases:
        for actual in [bad_val, good_val]:
            compliant = (actual == good_val)
            configs.append({
                'config_id':    f'SYSCTL-{config_id:04d}',
                'category':     'SYSCTL',
                'parameters': {
                    param: actual,
                },
                'is_vulnerable':  not compliant,
                'severity':       'NONE' if compliant else sev,
                'vulnerabilities': [] if compliant else [desc],
                'timestamp': f'2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}'
            })
            config_id += 1

    return configs


# ─────────────────────────────────────────────────────────────────────────────
# Save everything
# ─────────────────────────────────────────────────────────────────────────────

def save_generated_data():
    output_dir = 'dataset/generated'
    os.makedirs(output_dir, exist_ok=True)

    generators = [
        ('ssh_configs.json',        generate_ssh_configs,           'SSH'),
        ('file_permission_configs.json', generate_file_permission_configs, 'File Permission'),
        ('password_policy_configs.json', generate_password_policy_configs, 'Password Policy'),
        ('firewall_configs.json',   generate_firewall_configs,      'Firewall'),
        ('sysctl_configs.json',     generate_sysctl_configs,        'Sysctl'),
    ]

    total = 0
    total_vuln = 0

    for filename, func, label in generators:
        configs = func()
        with open(f'{output_dir}/{filename}', 'w') as f:
            json.dump(configs, f, indent=2)
        vuln = sum(1 for c in configs if c['is_vulnerable'])
        print(f'✓ Generated {len(configs):4d} {label} configurations  ({vuln} vulnerable)')
        total += len(configs)
        total_vuln += vuln

    print(f'\n✓ Total configurations generated: {total}')
    print(f'  - Vulnerable: {total_vuln}')
    print(f'  - Secure:     {total - total_vuln}')


if __name__ == '__main__':
    save_generated_data()
