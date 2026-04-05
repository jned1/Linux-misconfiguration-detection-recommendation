"""
main.py  –  Linux Security Misconfiguration Detection System
-------------------------------------------------------------
Hybrid detection engine combining:
  • Rule-based CIS Benchmark checks
  • ML-based severity prediction (Random Forest)

Usage:
    # Scan current machine and generate HTML + JSON report
    sudo python3 src/main.py --scan --report

    # Scan from an existing JSON config snapshot
    python3 src/main.py --config path/to/scan.json --report

    # Scan and print console summary only (no file output)
    python3 src/main.py --scan --console

    # Use a specific output directory
    python3 src/main.py --scan --report --output reports/my_scan
"""

import argparse
import json
import os
import pickle
import subprocess
import sys
import datetime
import numpy as np

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR  = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SCANNER     = os.path.join(BASE_DIR, "scripts", "collection", "linux_config_scanner.py")

MODEL_PATH   = os.path.join(MODELS_DIR, "random_forest_severity.pkl")
ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# Feature column order MUST match training
FEATURE_COLS = [
    "feature_network_exposed",
    "feature_affects_auth",
    "feature_critical_file",
    "feature_root_access",
    "feature_weak_auth",
]

# ── CIS Benchmark Rules ────────────────────────────────────────────────────
CIS_RULES = [
    {
        "id": "CIS-5.2.1",
        "category": "SSH",
        "parameter": "sshd_config_permissions",
        "description": "SSH config file should not be world-writable",
        "check_type": "file_permission",
        "target": "/etc/ssh/sshd_config",
        "expected_max_octal": 600,
        "severity": "HIGH",
        "recommendation": "Run: chmod 600 /etc/ssh/sshd_config",
    },
    {
        "id": "CIS-5.2.8",
        "category": "SSH",
        "parameter": "PermitRootLogin",
        "description": "SSH root login must be disabled",
        "check_type": "ssh_param",
        "expected_value": "no",
        "severity": "CRITICAL",
        "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: systemctl restart sshd",
    },
    {
        "id": "CIS-5.2.9",
        "category": "SSH",
        "parameter": "PermitEmptyPasswords",
        "description": "SSH empty passwords must be disabled",
        "check_type": "ssh_param",
        "expected_value": "no",
        "severity": "CRITICAL",
        "recommendation": "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config, then: systemctl restart sshd",
    },
    {
        "id": "CIS-5.2.10",
        "category": "SSH",
        "parameter": "PasswordAuthentication",
        "description": "SSH password authentication should be disabled (use keys)",
        "check_type": "ssh_param",
        "expected_value": "no",
        "severity": "HIGH",
        "recommendation": "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config. Ensure you have key-based access first.",
    },
    {
        "id": "CIS-5.2.4",
        "category": "SSH",
        "parameter": "Protocol",
        "description": "SSH must use Protocol 2 only",
        "check_type": "ssh_param",
        "expected_value": "2",
        "severity": "CRITICAL",
        "recommendation": "Set 'Protocol 2' in /etc/ssh/sshd_config, then: systemctl restart sshd",
    },
    {
        "id": "CIS-6.1.2",
        "category": "FILE_PERMISSIONS",
        "parameter": "/etc/passwd permissions",
        "description": "/etc/passwd must be 644",
        "check_type": "file_permission",
        "target": "/etc/passwd",
        "expected_max_octal": 644,
        "severity": "HIGH",
        "recommendation": "Run: chmod 644 /etc/passwd",
    },
    {
        "id": "CIS-6.1.3",
        "category": "FILE_PERMISSIONS",
        "parameter": "/etc/shadow permissions",
        "description": "/etc/shadow must be 640 or stricter",
        "check_type": "file_permission",
        "target": "/etc/shadow",
        "expected_max_octal": 640,
        "severity": "CRITICAL",
        "recommendation": "Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
    },
    {
        "id": "CIS-6.1.4",
        "category": "FILE_PERMISSIONS",
        "parameter": "/etc/group permissions",
        "description": "/etc/group must be 644",
        "check_type": "file_permission",
        "target": "/etc/group",
        "expected_max_octal": 644,
        "severity": "MEDIUM",
        "recommendation": "Run: chmod 644 /etc/group",
    },
]


# ── Feature derivation from a single finding ──────────────────────────────

def derive_features(rule: dict, actual_value: str) -> list:
    """Return a feature vector [5 ints] for the ML model."""
    cat  = rule.get("category", "")
    param = rule.get("parameter", "").lower()

    network_exposed  = 1 if cat == "SSH" else 0
    affects_auth     = 1 if any(k in param for k in
                                ["password", "permit", "auth", "root"]) else 0
    critical_file    = 1 if any(k in param for k in
                                ["/etc/shadow", "/etc/passwd", "/etc/sudoers"]) else 0
    root_access      = 1 if "permitrootlogin" in param and actual_value.lower() != "no" else 0
    weak_auth        = 1 if any(k in param for k in
                                ["password", "emptypassword"]) and actual_value.lower() != "no" else 0
    return [network_exposed, affects_auth, critical_file, root_access, weak_auth]


# ── ML model loader ────────────────────────────────────────────────────────

class MLPredictor:
    def __init__(self):
        self.model   = None
        self.encoder = None
        self._loaded = False

    def load(self):
        if not os.path.exists(MODEL_PATH):
            print("  [ML] Model not found – run train_ml_model.py first. Using rule-based only.")
            return False
        with open(MODEL_PATH,   "rb") as f: self.model   = pickle.load(f)
        with open(ENCODER_PATH, "rb") as f: self.encoder = pickle.load(f)
        self._loaded = True
        print("  [ML] Model loaded successfully.")
        return True

    def predict(self, feature_vector: list) -> str:
        if not self._loaded:
            return None
        X = np.array(feature_vector, dtype=float).reshape(1, -1)
        label_int = self.model.predict(X)[0]
        return self.encoder.inverse_transform([label_int])[0]

    def predict_proba(self, feature_vector: list) -> dict:
        if not self._loaded:
            return {}
        X = np.array(feature_vector, dtype=float).reshape(1, -1)
        probs = self.model.predict_proba(X)[0]
        classes = self.encoder.inverse_transform(self.model.classes_)
        return {cls: round(float(p), 4) for cls, p in zip(classes, probs)}


# ── Configuration collector ────────────────────────────────────────────────

def collect_live_config() -> dict:
    """Run the scanner and return its JSON output."""
    if not os.path.exists(SCANNER):
        print(f"  [SCANNER] Scanner not found at {SCANNER}. Using minimal inline scan.")
        return _minimal_inline_scan()

    print("  [SCANNER] Running linux_config_scanner.py ...")
    result = subprocess.run(
        [sys.executable, SCANNER],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  [SCANNER] Scanner exited with error:\n{result.stderr[:500]}")
        return _minimal_inline_scan()

    # The scanner writes a JSON file; also try to parse stdout
    scan_dir = os.path.join(BASE_DIR, "dataset", "generated", "real_scans")
    json_files = sorted(
        [f for f in os.listdir(scan_dir) if f.endswith(".json")]
        if os.path.isdir(scan_dir) else [],
        reverse=True,
    )
    if json_files:
        path = os.path.join(scan_dir, json_files[0])
        with open(path) as f:
            return json.load(f)

    return _minimal_inline_scan()


def _minimal_inline_scan() -> dict:
    """Fallback: read SSH config and critical file perms directly."""
    import stat

    config = {"ssh": {}, "file_permissions": {}, "scan_time": str(datetime.datetime.now())}

    # SSH config
    try:
        with open("/etc/ssh/sshd_config") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        config["ssh"][parts[0]] = parts[1]
    except Exception:
        pass

    # File permissions
    for filepath in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/ssh/sshd_config"]:
        try:
            mode = oct(stat.S_IMODE(os.stat(filepath).st_mode))[2:]
            config["file_permissions"][filepath] = mode
        except Exception:
            pass

    return config


# ── Rule checker ──────────────────────────────────────────────────────────

def run_rule_checks(system_config: dict, ml: MLPredictor) -> list:
    """Apply all CIS rules against the collected config. Returns list of findings."""
    findings = []
    ssh_config   = system_config.get("ssh", {})
    file_perms   = system_config.get("file_permissions", {})

    for rule in CIS_RULES:
        finding = {
            "rule_id"        : rule["id"],
            "category"       : rule["category"],
            "parameter"      : rule["parameter"],
            "description"    : rule["description"],
            "expected_value" : "",
            "actual_value"   : "N/A",
            "is_compliant"   : True,
            "is_vulnerable"  : False,
            "rule_severity"  : rule["severity"],
            "ml_severity"    : None,
            "final_severity" : "NONE",
            "recommendation" : rule.get("recommendation", ""),
            "confidence"     : {},
        }

        check = rule.get("check_type")

        # --- SSH parameter check ---
        if check == "ssh_param":
            param = rule["parameter"]
            expected = rule["expected_value"]
            actual   = ssh_config.get(param, "NOT_SET").strip()
            finding["expected_value"] = expected
            finding["actual_value"]   = actual

            if actual.lower() != expected.lower():
                finding["is_compliant"]  = False
                finding["is_vulnerable"] = True

        # --- File permission check ---
        elif check == "file_permission":
            target   = rule["target"]
            expected = str(rule["expected_max_octal"])
            actual   = file_perms.get(target, "NOT_FOUND")
            finding["expected_value"] = f"<= {expected}"
            finding["actual_value"]   = actual

            if actual == "NOT_FOUND":
                finding["is_compliant"]  = True   # can't check; skip
            else:
                try:
                    if int(actual, 8) > int(expected, 8):
                        finding["is_compliant"]  = False
                        finding["is_vulnerable"] = True
                except ValueError:
                    pass

        # --- ML severity prediction ---
        if finding["is_vulnerable"]:
            feat_vec = derive_features(rule, finding["actual_value"])
            ml_pred  = ml.predict(feat_vec)
            ml_proba = ml.predict_proba(feat_vec)

            finding["ml_severity"]  = ml_pred
            finding["confidence"]   = ml_proba

            # Hybrid: take the more severe of rule-based and ML prediction
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
            rule_rank = sev_order.get(rule["severity"], 4)
            ml_rank   = sev_order.get(ml_pred or "NONE", 4)
            finding["final_severity"] = rule["severity"] if rule_rank <= ml_rank else ml_pred
        else:
            finding["final_severity"] = "NONE"

        findings.append(finding)

    return findings


# ── Console report ────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH"    : "\033[93m",  # yellow
    "MEDIUM"  : "\033[94m",  # blue
    "LOW"     : "\033[96m",  # cyan
    "NONE"    : "\033[92m",  # green
}
RESET = "\033[0m"


def print_console_report(findings: list, hostname: str = "localhost"):
    vulnerable = [f for f in findings if f["is_vulnerable"]]
    compliant  = [f for f in findings if not f["is_vulnerable"]]

    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    for f in vulnerable:
        sev_count[f["final_severity"]] = sev_count.get(f["final_severity"], 0) + 1

    print("\n" + "="*65)
    print(f"  Linux Security Misconfiguration Report  |  {hostname}")
    print(f"  Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*65)
    print(f"\n  Checks Run : {len(findings)}")
    print(f"  Compliant  : {len(compliant)}")
    print(f"  Vulnerable : {len(vulnerable)}")
    print(f"\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_count[sev]
        bar = "█" * count
        color = SEV_COLORS.get(sev, "")
        print(f"    {color}{sev:10}{RESET}  {bar} ({count})")

    if vulnerable:
        print("\n" + "-"*65)
        print("  FINDINGS")
        print("-"*65)
        for f in sorted(vulnerable,
                        key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","NONE"]
                                       .index(x["final_severity"])):
            color = SEV_COLORS.get(f["final_severity"], "")
            print(f"\n  [{color}{f['final_severity']:8}{RESET}] {f['rule_id']}  –  {f['description']}")
            print(f"    Expected : {f['expected_value']}")
            print(f"    Actual   : {f['actual_value']}")
            if f["ml_severity"]:
                print(f"    ML pred  : {f['ml_severity']}")
            print(f"    Fix      : {f['recommendation']}")
    else:
        print("\n  \033[92m✓ No misconfigurations found!\033[0m")

    print("\n" + "="*65 + "\n")


# ── Entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Misconfiguration Detection System"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan",   action="store_true",
                      help="Scan the current live system")
    mode.add_argument("--config", metavar="FILE",
                      help="Load a saved JSON config snapshot")

    parser.add_argument("--report",  action="store_true",
                        help="Generate HTML and JSON reports")
    parser.add_argument("--console", action="store_true",
                        help="Print summary to console (default: on)")
    parser.add_argument("--output",  metavar="DIR", default=REPORTS_DIR,
                        help=f"Output directory for reports (default: {REPORTS_DIR})")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    # ── 1. Load ML model ──
    print("\n[1/3] Loading ML model...")
    ml = MLPredictor()
    ml.load()

    # ── 2. Collect configuration ──
    print("\n[2/3] Collecting system configuration...")
    if args.scan:
        system_config = collect_live_config()
    else:
        with open(args.config) as f:
            system_config = json.load(f)
        print(f"  Loaded config from: {args.config}")

    # Handle case where JSON is a list (e.g. ssh_configs.json from generator)
    if isinstance(system_config, list):
        wrapped = {"hostname": "localhost", "ssh": {}, "file_permissions": {}}
        # Merge ALL items in the list — take last value wins per key
        for item in system_config:
            if isinstance(item, dict):
                for key, val in item.items():
                    if key in ["PermitRootLogin", "PasswordAuthentication",
                               "PermitEmptyPasswords", "Protocol",
                               "PermitUserEnvironment", "X11Forwarding",
                               "MaxAuthTries", "LoginGraceTime"]:
                        wrapped["ssh"][key] = str(val)
                    elif key in ["hostname"]:
                        wrapped["hostname"] = str(val)
        system_config = wrapped

    hostname = system_config.get("hostname", "localhost")

    # ── 3. Run detection ──
    print("\n[3/3] Running hybrid detection engine...")
    findings = run_rule_checks(system_config, ml)
    vulnerable = [f for f in findings if f["is_vulnerable"]]
    print(f"  Checks: {len(findings)}  |  Vulnerable: {len(vulnerable)}")

    # ── 4. Output ──
    print_console_report(findings, hostname)

    if args.report:
        # Import here to avoid circular issues; generate_report.py must be on path
        report_module = os.path.join(BASE_DIR, "scripts", "reporting", "generate_report.py")
        if os.path.exists(report_module):
            import importlib.util
            spec = importlib.util.spec_from_file_location("generate_report", report_module)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            html_path, json_path = mod.generate(findings, hostname, args.output)
            print(f"  HTML report → {html_path}")
            print(f"  JSON report → {json_path}")
        else:
            # Fallback: save raw JSON
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = os.path.join(args.output, f"report_{ts}.json")
            with open(json_path, "w") as f:
                json.dump({"hostname": hostname,
                           "scan_time": str(datetime.datetime.now()),
                           "findings": findings}, f, indent=2)
            print(f"  JSON report → {json_path}")


if __name__ == "__main__":
    main()
