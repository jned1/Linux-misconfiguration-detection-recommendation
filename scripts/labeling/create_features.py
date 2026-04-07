#!/usr/bin/env python3
"""
Feature engineering for ML model.
Uses numeric + categorical encoding so the model can actually
distinguish CRITICAL / HIGH / MEDIUM / LOW / NONE properly.
"""

import pandas as pd
import numpy as np
import os


# ── Value risk maps ────────────────────────────────────────────────────────

SSH_RISK = {
    'PermitRootLogin': {
        'no': 0, 'forced-commands-only': 1, 'without-password': 2,
        'prohibit-password': 2, 'yes': 4,
    },
    'PasswordAuthentication': {'no': 0, 'yes': 3},
    'PermitEmptyPasswords':   {'no': 0, 'yes': 4},
    'Protocol':               {'2': 0, '1': 4},
    'X11Forwarding':          {'no': 0, 'yes': 1},
    'PermitUserEnvironment':  {'no': 0, 'yes': 1},
}

PERM_RISK = {
    '400': 0, '440': 0, '600': 0, '640': 0, '644': 0,
    '660': 2, '664': 2, '646': 2,
    '666': 4, '755': 1, '777': 4,
}

CATEGORY_RISK = {
    'SSH': 3, 'FILE_PERMISSIONS': 2, 'PASSWORD_POLICY': 2,
    'FIREWALL': 3, 'SYSCTL': 2,
}

HIGH_RISK_PARAMS = {
    'PermitRootLogin', 'PermitEmptyPasswords', 'Protocol',
    '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
    '/boot/grub/grub.cfg', 'kernel.randomize_va_space',
    'net.ipv4.tcp_syncookies', 'enabled',
}

AUTH_PARAMS = {
    'PermitRootLogin', 'PasswordAuthentication',
    'PermitEmptyPasswords', 'PASS_MIN_LEN', 'PASS_MAX_DAYS', 'complexity',
}

NETWORK_PARAMS = {
    'net.ipv4.ip_forward', 'net.ipv4.conf.all.send_redirects',
    'net.ipv4.conf.all.accept_redirects', 'net.ipv4.conf.all.log_martians',
    'net.ipv4.tcp_syncookies',
}

CRITICAL_FILES = {
    '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config',
    '/boot/grub/grub.cfg', '/etc/gshadow',
}


def create_ml_features(df: pd.DataFrame) -> pd.DataFrame:

    # ── Binary features ───────────────────────────────────────────────────
    df['feature_network_exposed']  = df['category'].isin(['SSH', 'FIREWALL']).astype(int)
    df['feature_affects_auth']     = df['parameter'].isin(AUTH_PARAMS).astype(int)
    df['feature_critical_file']    = df['parameter'].isin(CRITICAL_FILES).astype(int)
    df['feature_root_access']      = (
        (df['parameter'] == 'PermitRootLogin') &
        (df['actual_value'].isin(['yes', 'without-password']))
    ).astype(int)
    df['feature_weak_auth'] = (
        ((df['parameter'] == 'PasswordAuthentication') & (df['actual_value'] == 'yes')) |
        ((df['parameter'] == 'PermitEmptyPasswords')   & (df['actual_value'] == 'yes')) |
        ((df['parameter'] == 'complexity')             & (df['actual_value'] == 'no'))  |
        ((df['parameter'] == 'PASS_MIN_LEN') &
         (pd.to_numeric(df['actual_value'], errors='coerce').fillna(99) < 8))
    ).astype(int)
    df['feature_kernel_hardening'] = (
        (df['category'] == 'SYSCTL') & (~df['is_compliant'])
    ).astype(int)
    df['feature_network_stack']    = (
        (df['parameter'].isin(NETWORK_PARAMS)) & (~df['is_compliant'])
    ).astype(int)
    df['feature_firewall_weak']    = (
        (df['category'] == 'FIREWALL') & (~df['is_compliant'])
    ).astype(int)
    df['feature_world_writable']   = (
        (df['category'] == 'FILE_PERMISSIONS') &
        (df['actual_value'].isin(['777', '666']))
    ).astype(int)
    df['feature_weak_protocol']    = (
        (df['parameter'] == 'Protocol') & (df['actual_value'] == '1')
    ).astype(int)
    df['feature_is_vulnerable']    = df['is_vulnerable'].astype(int)
    df['feature_high_risk_param']  = df['parameter'].isin(HIGH_RISK_PARAMS).astype(int)

    # ── Numeric: category risk score (0–3) ───────────────────────────────
    df['feature_category_risk'] = df['category'].map(CATEGORY_RISK).fillna(1).astype(int)

    # ── Numeric: SSH param value risk score (0–4) ────────────────────────
    def ssh_value_risk(row):
        if row['category'] != 'SSH':
            return 0
        param = row['parameter']
        val   = str(row['actual_value']).lower()
        if param == 'MaxAuthTries':
            try:
                n = int(val)
                if n <= 3:   return 0
                elif n <= 5: return 1
                elif n <= 8: return 2
                else:        return 3
            except ValueError:
                return 0
        return SSH_RISK.get(param, {}).get(val, 1)

    df['feature_ssh_risk_score'] = df.apply(ssh_value_risk, axis=1)

    # ── Numeric: file permission risk score (0–4) ────────────────────────
    def perm_risk_score(row):
        if row['category'] != 'FILE_PERMISSIONS':
            return 0
        return PERM_RISK.get(str(row['actual_value']), 1)

    df['feature_perm_risk_score'] = df.apply(perm_risk_score, axis=1)

    # ── Numeric: password weakness score (0–4) ───────────────────────────
    def pwd_weakness(row):
        if row['category'] != 'PASSWORD_POLICY':
            return 0
        param = row['parameter']
        if param == 'complexity':
            return 3 if str(row['actual_value']) == 'no' else 0
        try:
            val = int(row['actual_value'])
        except (ValueError, TypeError):
            return 0
        if param == 'PASS_MIN_LEN':
            if val < 6:  return 4
            if val < 8:  return 3
            if val < 12: return 1
            return 0
        if param == 'PASS_MAX_DAYS':
            if val == 99999: return 3
            if val > 180:    return 2
            if val > 90:     return 1
            return 0
        if param == 'PASS_WARN_AGE':
            return 1 if val == 0 else 0
        return 0

    df['feature_pwd_weakness_score'] = df.apply(pwd_weakness, axis=1)

    # ── Numeric: combined risk score (0–10) ───────────────────────────────
    df['feature_combined_risk'] = (
        df['feature_ssh_risk_score'] +
        df['feature_perm_risk_score'] +
        df['feature_pwd_weakness_score'] +
        df['feature_root_access']      * 4 +
        df['feature_weak_protocol']    * 4 +
        df['feature_world_writable']   * 4 +
        df['feature_weak_auth']        * 3 +
        df['feature_firewall_weak']    * 3 +
        df['feature_kernel_hardening'] * 2 +
        df['feature_high_risk_param']
    ).clip(upper=10)

    return df


def save_feature_dataset(df: pd.DataFrame) -> pd.DataFrame:
    output_path = 'dataset/processed/features/dataset_with_features.csv'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    feature_cols = [c for c in df.columns if c.startswith('feature_')]
    print(f'✓ Saved feature dataset : {output_path}')
    print(f'  Total rows             : {len(df)}')
    print(f'  Features created       : {len(feature_cols)}')
    print(f'\nSeverity distribution:')
    print(df['severity'].value_counts().to_string())
    print(f'\nAvg combined_risk by severity (should increase NONE→CRITICAL):')
    print(df.groupby('severity')['feature_combined_risk'].mean().round(2).to_string())
    return df


def main():
    print('Creating ML features...\n')
    labeled_path = 'dataset/processed/labeled/master_labeled_dataset.csv'
    if not os.path.exists(labeled_path):
        print(f'Error: File not found → {labeled_path}')
        return
    df = pd.read_csv(labeled_path)
    print(f'Loaded {len(df)} labeled samples')
    df = create_ml_features(df)
    save_feature_dataset(df)
    print('\n✓ Feature engineering completed successfully')


if __name__ == '__main__':
    main()
