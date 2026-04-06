#!/usr/bin/env python3
"""
Master pipeline script
Linux Security Misconfiguration Detection System
-------------------------------------------------
Runs the full pipeline end-to-end:

  Phase 1 : Extract CIS rules
  Phase 2 : Generate synthetic data
  Phase 3 : Label data
  Phase 4 : Create features
  Phase 5 : Split dataset
  Phase 6 : Train ML model
  Phase 7 : Run detection + generate report

Usage:
    python3 scripts/run_pipeline.py                  # full pipeline
    python3 scripts/run_pipeline.py --skip-data      # skip phases 1-5 (dataset already built)
    python3 scripts/run_pipeline.py --skip-train     # skip phases 1-6 (model already trained)
    python3 scripts/run_pipeline.py --no-scan        # use sample config instead of live scan
"""

import argparse
import os
import subprocess
import sys
import datetime

# ── Colours ────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def banner(text):
    print("\n" + BOLD + CYAN + "=" * 62)
    print("  " + text)
    print("=" * 62 + RESET)


def step(num, total, description):
    print("\n" + BOLD + YELLOW +
          "[{}/{}] {}".format(num, total, description) +
          RESET)
    print("-" * 62)


def ok(description):
    print(GREEN + "  ✓  " + description + RESET)


def warn(description):
    print(YELLOW + "  ⚠  " + description + RESET)


def error(description):
    print(RED + "  ✗  " + description + RESET)


# ── Command runner ─────────────────────────────────────────────────────────

def run_command(description, command, allow_fail=False):
    """Run a shell command. Exit on failure unless allow_fail=True."""
    result = subprocess.run(command, shell=True, text=True)
    if result.returncode != 0:
        if allow_fail:
            warn("{} failed (non-fatal, continuing)".format(description))
            return False
        else:
            error("{} failed with exit code {}".format(description, result.returncode))
            print(RED + "  Pipeline aborted." + RESET)
            sys.exit(1)
    ok("{} completed".format(description))
    return True


def file_exists_and_nonempty(path):
    return os.path.exists(path) and os.path.getsize(path) > 0


# ── Summary helpers ────────────────────────────────────────────────────────

def print_dataset_summary(base):
    print("\n  Dataset summary:")
    total = 0
    for split in ["train", "validation", "test"]:
        path = os.path.join(base, "dataset", "final", split)
        if os.path.isdir(path):
            for f in os.listdir(path):
                if f.endswith(".csv"):
                    fpath = os.path.join(path, f)
                    lines = sum(1 for _ in open(fpath)) - 1  # subtract header
                    size  = os.path.getsize(fpath)
                    print("    {:12s}  {:>5d} rows  ({} bytes)".format(
                        split + "/", lines, size))
                    total += lines
    print("    {:12s}  {:>5d} rows  (total)".format("ALL", total))


def print_model_summary(base):
    meta_path = os.path.join(base, "models", "model_metadata.json")
    if not file_exists_and_nonempty(meta_path):
        return
    import json
    with open(meta_path) as f:
        meta = json.load(f)
    print("\n  Model summary:")
    print("    Algorithm  : {}".format(meta.get("model_type", "?")))
    print("    Train rows : {}".format(meta.get("train_samples", "?")))
    print("    Val  Acc   : {}".format(meta.get("val_accuracy", "?")))
    print("    Test Acc   : {}".format(meta.get("test_accuracy", "?")))
    print("    Test F1    : {}".format(meta.get("test_f1_weighted", "?")))


def print_report_summary(base):
    reports_dir = os.path.join(base, "reports")
    if not os.path.isdir(reports_dir):
        return
    html_files = sorted(
        [f for f in os.listdir(reports_dir) if f.endswith(".html")],
        reverse=True,
    )
    json_files = sorted(
        [f for f in os.listdir(reports_dir) if f.startswith("report_") and f.endswith(".json")],
        reverse=True,
    )
    if html_files:
        print("\n  Latest report:")
        print("    HTML → reports/{}".format(html_files[0]))
    if json_files:
        print("    JSON → reports/{}".format(json_files[0]))


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Linux Security Misconfiguration Detection – Master Pipeline"
    )
    parser.add_argument("--skip-data",  action="store_true",
                        help="Skip phases 1-5 (dataset already built)")
    parser.add_argument("--skip-train", action="store_true",
                        help="Skip phases 1-6 (model already trained)")
    parser.add_argument("--no-scan",    action="store_true",
                        help="Use sample JSON config instead of live scan (no sudo needed)")
    args = parser.parse_args()

    # Change to repo root (script lives in scripts/)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(base)

    start_time = datetime.datetime.now()

    banner("Linux Security Misconfiguration Detection System")
    print("  Start time : {}".format(start_time.strftime("%Y-%m-%d %H:%M:%S")))
    print("  Working dir: {}".format(base))

    # ── Determine total steps ──────────────────────────────────────────────
    if args.skip_train:
        total_steps = 1
    elif args.skip_data:
        total_steps = 2
    else:
        total_steps = 7

    current = 0

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1-5: Dataset creation
    # ══════════════════════════════════════════════════════════════════════
    if not args.skip_data and not args.skip_train:

        banner("PHASE 1-5: Dataset Creation")

        current += 1
        step(current, total_steps, "Extracting CIS Benchmark rules")
        run_command("CIS rules extraction",
                    "python3 scripts/collection/extract_cis_rules.py")

        current += 1
        step(current, total_steps, "Generating synthetic configurations")
        run_command("Synthetic data generation",
                    "python3 scripts/generation/generate_synthetic_configs.py")

        current += 1
        step(current, total_steps, "Labeling all data")
        run_command("Data labeling",
                    "python3 scripts/labeling/label_all_data.py")

        current += 1
        step(current, total_steps, "Engineering features")
        run_command("Feature engineering",
                    "python3 scripts/labeling/create_features.py")

        current += 1
        step(current, total_steps, "Splitting into train / validation / test")
        run_command("Dataset split",
                    "python3 scripts/labeling/split_dataset.py")

        print_dataset_summary(base)

    else:
        warn("Skipping dataset creation phases (--skip-data or --skip-train)")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: ML model training
    # ══════════════════════════════════════════════════════════════════════
    if not args.skip_train:

        banner("PHASE 6: ML Model Training")
        current += 1
        step(current, total_steps, "Training Random Forest classifier")

        train_csv = os.path.join(base, "dataset", "final", "train", "train_data.csv")
        if not file_exists_and_nonempty(train_csv):
            error("Training data not found at {}".format(train_csv))
            error("Run without --skip-data first to build the dataset.")
            sys.exit(1)

        run_command("ML model training",
                    "python3 scripts/training/train_ml_model.py")

        print_model_summary(base)

    else:
        warn("Skipping ML training (--skip-train)")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7: Detection + Report
    # ══════════════════════════════════════════════════════════════════════
    banner("PHASE 7: Detection & Report Generation")
    current += 1
    step(current, total_steps, "Running hybrid detection engine")

    model_path = os.path.join(base, "models", "random_forest_severity.pkl")
    if not file_exists_and_nonempty(model_path):
        warn("Trained model not found – detection will use rule-based only")

    if args.no_scan:
        # Use the generated ssh_configs.json as sample input
        sample_config = os.path.join(base, "dataset", "generated", "ssh_configs.json")
        if not os.path.exists(sample_config):
            error("Sample config not found: {}".format(sample_config))
            sys.exit(1)
        run_command(
            "Detection (sample config)",
            "python3 src/main.py --config {} --report --output reports".format(sample_config),
        )
    else:
        print("  Running live scan (requires sudo)...")
        run_command(
            "Detection (live scan)",
            "sudo python3 src/main.py --scan --report --output reports",
            allow_fail=True,  # non-fatal if sudo not available
        )

    print_report_summary(base)

    # ══════════════════════════════════════════════════════════════════════
    # Done
    # ══════════════════════════════════════════════════════════════════════
    elapsed = datetime.datetime.now() - start_time

    banner("PIPELINE COMPLETE")
    print("  Elapsed    : {}".format(str(elapsed).split(".")[0]))
    print("  Reports    : {}/reports/".format(base))
    print("  Models     : {}/models/".format(base))
    print("  Dataset    : {}/dataset/final/".format(base))
    print("\n" + GREEN + BOLD +
          "  All phases completed successfully!" + RESET + "\n")


if __name__ == "__main__":
    main()
