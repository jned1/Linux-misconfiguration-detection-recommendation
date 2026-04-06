#!/usr/bin/env python3
"""
cli_ui.py  –  Interactive Terminal UI
Linux Security Misconfiguration Detection System
------------------------------------------------
Usage:
    python3 src/cli_ui.py
"""

import os
import sys
import json
import time
import subprocess
import datetime
import importlib.util

# ── Try to import rich; fall back to plain ANSI if missing ────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
    RICH = True
except ImportError:
    RICH = False

# ── Base dir (src/cli_ui.py  →  go up one level) ─────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── ANSI fallback colours ──────────────────────────────────────────────────
C = {
    "red":    "\033[91m", "yellow": "\033[93m", "green":  "\033[92m",
    "cyan":   "\033[96m", "blue":   "\033[94m", "bold":   "\033[1m",
    "dim":    "\033[2m",  "reset":  "\033[0m",
}

SEV_COLOR_RICH = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold blue",
    "LOW":      "cyan",
    "NONE":     "bold green",
}
SEV_COLOR_ANSI = {
    "CRITICAL": C["red"], "HIGH": C["yellow"],
    "MEDIUM":   C["blue"], "LOW": C["cyan"], "NONE": C["green"],
}

# ─────────────────────────────────────────────────────────────────────────
# Helper wrappers (work with or without rich)
# ─────────────────────────────────────────────────────────────────────────

if RICH:
    console = Console()

    def clear():
        console.clear()

    def print_header():
        console.print(Panel.fit(
            "[bold cyan]🛡  Linux Security Misconfiguration Detection System[/]\n"
            "[dim]Hybrid Rule-Based + ML Detection  |  CIS Benchmark Compliant[/]",
            border_style="cyan", padding=(1, 4)
        ))

    def print_menu(options):
        t = Table(show_header=False, box=box.ROUNDED, border_style="cyan",
                  padding=(0, 2), min_width=48)
        t.add_column("key",  style="bold yellow", width=4)
        t.add_column("desc", style="white")
        for key, desc in options:
            t.add_row(key, desc)
        console.print(t)

    def info(msg):   console.print("  [cyan]ℹ[/]  " + msg)
    def ok(msg):     console.print("  [green]✓[/]  " + msg)
    def warn(msg):   console.print("  [yellow]⚠[/]  " + msg)
    def error(msg):  console.print("  [red]✗[/]  " + msg)
    def rule(title=""): console.print(Rule(title, style="cyan"))

    def ask(prompt, default=None):
        return Prompt.ask("  [bold yellow]→[/] " + prompt, default=default)

    def confirm(prompt):
        return Confirm.ask("  [bold yellow]?[/] " + prompt)

    def spinner(msg):
        return Progress(
            SpinnerColumn(), TextColumn("[cyan]{task.description}"),
            TimeElapsedColumn(), console=console, transient=True
        )

    def sev_text(s):
        return "[{}]{}[/]".format(SEV_COLOR_RICH.get(s, "white"), s)

else:
    def clear():
        os.system("clear")

    def print_header():
        w = 62
        print(C["cyan"] + C["bold"] + "=" * w)
        print("  🛡  Linux Security Misconfiguration Detection System")
        print("  Hybrid Rule-Based + ML  |  CIS Benchmark Compliant")
        print("=" * w + C["reset"])

    def print_menu(options):
        print()
        for key, desc in options:
            print("  {}[{}]{} {}".format(C["yellow"], key, C["reset"], desc))
        print()

    def info(msg):   print("  " + C["cyan"]   + "ℹ" + C["reset"] + "  " + msg)
    def ok(msg):     print("  " + C["green"]  + "✓" + C["reset"] + "  " + msg)
    def warn(msg):   print("  " + C["yellow"] + "⚠" + C["reset"] + "  " + msg)
    def error(msg):  print("  " + C["red"]    + "✗" + C["reset"] + "  " + msg)
    def rule(title=""): print(C["cyan"] + "─" * 62 + C["reset"] + (" " + title if title else ""))

    def ask(prompt, default=None):
        suffix = " [{}]".format(default) if default else ""
        val = input("  → " + prompt + suffix + ": ").strip()
        return val if val else default

    def confirm(prompt):
        return input("  ? " + prompt + " [y/N]: ").strip().lower() == "y"

    def spinner(msg):
        class _Dummy:
            def __enter__(self): info(msg + " ..."); return self
            def __exit__(self, *a): pass
            def add_task(self, *a, **kw): return 0
            def update(self, *a, **kw): pass
        return _Dummy()

    def sev_text(s):
        return SEV_COLOR_ANSI.get(s, "") + s + C["reset"]


# ─────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────

def path(relative):
    return os.path.join(BASE_DIR, relative)


def file_ok(p):
    return os.path.exists(p) and os.path.getsize(p) > 0


def run_script(cmd, label):
    """Run a subprocess command, stream output, return success bool."""
    rule(label)
    result = subprocess.run(cmd, shell=True)
    if result.returncode == 0:
        ok(label + " — done")
        return True
    else:
        error(label + " — failed (exit {})".format(result.returncode))
        return False


def load_ml_model():
    model_path   = path("models/random_forest_severity.pkl")
    encoder_path = path("models/label_encoder.pkl")
    if not file_ok(model_path):
        return None, None
    import pickle
    with open(model_path,   "rb") as f: model   = pickle.load(f)
    with open(encoder_path, "rb") as f: encoder = pickle.load(f)
    return model, encoder


def load_report_module():
    rmod = path("scripts/reporting/generate_report.py")
    if not os.path.exists(rmod):
        return None
    spec = importlib.util.spec_from_file_location("generate_report", rmod)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_main_module():
    mmod = path("src/main.py")
    if not os.path.exists(mmod):
        return None
    spec = importlib.util.spec_from_file_location("main_detection", mmod)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def status_badge(ok_flag):
    return ("[green]● READY[/]"    if ok_flag else "[red]○ MISSING[/]") if RICH \
      else (C["green"] + "● READY" + C["reset"] if ok_flag else C["red"] + "○ MISSING" + C["reset"])


# ─────────────────────────────────────────────────────────────────────────
# Screens
# ─────────────────────────────────────────────────────────────────────────

def show_status():
    """Show current system status."""
    train_ok  = file_ok(path("dataset/final/train/train_data.csv"))
    model_ok  = file_ok(path("models/random_forest_severity.pkl"))
    report_ok = os.path.isdir(path("reports")) and any(
        f.endswith(".html") for f in os.listdir(path("reports"))
        if os.path.isdir(path("reports"))
    )

    if RICH:
        t = Table(title="System Status", box=box.ROUNDED, border_style="cyan",
                  min_width=50)
        t.add_column("Component",  style="bold white", width=28)
        t.add_column("Status",     justify="center")
        t.add_row("Dataset (train/val/test)", status_badge(train_ok))
        t.add_row("ML Model (Random Forest)", status_badge(model_ok))
        t.add_row("Reports generated",        status_badge(report_ok))
        console.print(t)
    else:
        rule("System Status")
        print("  Dataset       : " + status_badge(train_ok))
        print("  ML Model      : " + status_badge(model_ok))
        print("  Reports       : " + status_badge(report_ok))
    print()


# ─────────────────────────────────────────────────────────────────────────

def menu_train():
    clear()
    print_header()
    if RICH:
        console.print(Panel("[bold]Phase: ML Model Training[/]", border_style="yellow"))
    else:
        rule("ML Model Training")

    train_csv = path("dataset/final/train/train_data.csv")
    if not file_ok(train_csv):
        error("Training data not found. Run dataset pipeline first (option 1).")
        input("\n  Press Enter to return...")
        return

    info("Training Random Forest classifier on your dataset...")
    info("This will also generate confusion matrix + feature importance charts.\n")

    if not confirm("Start training now?"):
        return

    success = run_script(
        "python3 {}".format(path("scripts/training/train_ml_model.py")),
        "ML Model Training"
    )

    if success:
        # Show model metadata
        meta_path = path("models/model_metadata.json")
        if file_ok(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            if RICH:
                t = Table(title="Training Results", box=box.SIMPLE_HEAVY,
                          border_style="green", min_width=44)
                t.add_column("Metric",  style="bold white")
                t.add_column("Value",   style="bold green", justify="right")
                t.add_row("Algorithm",       meta.get("model_type", "?"))
                t.add_row("Training samples",str(meta.get("train_samples", "?")))
                t.add_row("Val Accuracy",    str(meta.get("val_accuracy", "?")))
                t.add_row("Test Accuracy",   str(meta.get("test_accuracy", "?")))
                t.add_row("Test F1 (weighted)", str(meta.get("test_f1_weighted", "?")))
                console.print(t)
            else:
                rule("Training Results")
                print("  Algorithm     : " + str(meta.get("model_type", "?")))
                print("  Train samples : " + str(meta.get("train_samples", "?")))
                print("  Val  Accuracy : " + str(meta.get("val_accuracy", "?")))
                print("  Test Accuracy : " + str(meta.get("test_accuracy", "?")))
                print("  Test F1       : " + str(meta.get("test_f1_weighted", "?")))

        ok("Model saved to models/random_forest_severity.pkl")
        ok("Charts saved to reports/")

    input("\n  Press Enter to return to menu...")


# ─────────────────────────────────────────────────────────────────────────

def menu_dataset():
    clear()
    print_header()
    if RICH:
        console.print(Panel("[bold]Phase: Dataset Pipeline[/]", border_style="yellow"))
    else:
        rule("Dataset Pipeline")

    info("This runs all 5 dataset creation phases:")
    info("  1 → Extract CIS rules")
    info("  2 → Generate synthetic configs")
    info("  3 → Label all data")
    info("  4 → Engineer features")
    info("  5 → Split train / validation / test\n")

    if not confirm("Run full dataset pipeline?"):
        return

    phases = [
        ("scripts/collection/extract_cis_rules.py",            "CIS Rule Extraction"),
        ("scripts/generation/generate_synthetic_configs.py",   "Synthetic Data Generation"),
        ("scripts/labeling/label_all_data.py",                 "Data Labeling"),
        ("scripts/labeling/create_features.py",                "Feature Engineering"),
        ("scripts/labeling/split_dataset.py",                  "Dataset Split"),
    ]

    failed = False
    for rel, label in phases:
        success = run_script("python3 {}".format(path(rel)), label)
        if not success:
            failed = True
            break

    if not failed:
        ok("\nDataset pipeline complete!")
        for split in ["train", "validation", "test"]:
            p = path("dataset/final/{}/".format(split))
            if os.path.isdir(p):
                for f in os.listdir(p):
                    if f.endswith(".csv"):
                        lines = sum(1 for _ in open(os.path.join(p, f))) - 1
                        ok("  {:12s} → {:>4d} rows".format(split, lines))

    input("\n  Press Enter to return to menu...")


# ─────────────────────────────────────────────────────────────────────────

def menu_scan():
    clear()
    print_header()
    if RICH:
        console.print(Panel("[bold]Phase: Detection & Report[/]", border_style="yellow"))
    else:
        rule("Detection & Report")

    model_ok = file_ok(path("models/random_forest_severity.pkl"))
    if not model_ok:
        warn("ML model not trained yet — detection will use rule-based only.")

    if RICH:
        console.print("\n  [bold]Choose scan mode:[/]")
    else:
        print("\n  Choose scan mode:")

    print_menu([
        ("1", "Live scan     — scan THIS machine (requires sudo)"),
        ("2", "Config file   — load a saved JSON config snapshot"),
        ("3", "Sample scan   — use built-in demo config (no sudo needed)"),
        ("b", "Back to menu"),
    ])

    choice = ask("Select option", "3")

    if choice == "b":
        return

    os.makedirs(path("reports"), exist_ok=True)

    if choice == "1":
        info("Running live scan (sudo required)...")
        cmd = "sudo python3 {} --scan --report --output {}".format(
            path("src/main.py"), path("reports"))

    elif choice == "2":
        config_path = ask("Path to JSON config file",
                          path("dataset/generated/ssh_configs.json"))
        if not os.path.exists(config_path):
            error("File not found: " + config_path)
            input("\n  Press Enter to return...")
            return
        cmd = "python3 {} --config {} --report --output {}".format(
            path("src/main.py"), config_path, path("reports"))

    else:  # sample
        # Build a demo config inline
        demo_config = {
            "hostname": "demo-server",
            "ssh": {
                "PermitRootLogin":      "yes",
                "PasswordAuthentication": "yes",
                "PermitEmptyPasswords": "no",
                "Protocol":             "2",
            },
            "file_permissions": {
                "/etc/passwd":          "644",
                "/etc/shadow":          "777",
                "/etc/group":           "644",
                "/etc/ssh/sshd_config": "644",
            }
        }
        demo_path = path("dataset/generated/demo_scan.json")
        os.makedirs(os.path.dirname(demo_path), exist_ok=True)
        with open(demo_path, "w") as f:
            json.dump(demo_config, f, indent=2)
        info("Using built-in demo config (2 CRITICAL, 1 HIGH finding)...")
        cmd = "python3 {} --config {} --report --output {}".format(
            path("src/main.py"), demo_path, path("reports"))

    rule("Running Detection Engine")
    result = subprocess.run(cmd, shell=True)

    if result.returncode == 0:
        # Show latest report path
        rdir = path("reports")
        html_files = sorted(
            [f for f in os.listdir(rdir) if f.endswith(".html")], reverse=True
        ) if os.path.isdir(rdir) else []
        if html_files:
            ok("\nHTML report → reports/{}".format(html_files[0]))
            if confirm("Open report in browser?"):
                subprocess.run("xdg-open {}".format(
                    os.path.join(rdir, html_files[0])), shell=True)

    input("\n  Press Enter to return to menu...")


# ─────────────────────────────────────────────────────────────────────────

def menu_view_reports():
    clear()
    print_header()
    if RICH:
        console.print(Panel("[bold]Saved Reports[/]", border_style="yellow"))
    else:
        rule("Saved Reports")

    rdir = path("reports")
    if not os.path.isdir(rdir):
        warn("No reports directory found.")
        input("\n  Press Enter to return...")
        return

    html_files = sorted(
        [f for f in os.listdir(rdir) if f.endswith(".html")], reverse=True
    )
    json_files = sorted(
        [f for f in os.listdir(rdir) if f.startswith("report_") and f.endswith(".json")],
        reverse=True,
    )

    if not html_files:
        warn("No reports found. Run a scan first (option 3).")
        input("\n  Press Enter to return...")
        return

    if RICH:
        t = Table(title="Available Reports", box=box.ROUNDED,
                  border_style="cyan", min_width=56)
        t.add_column("#",    style="bold yellow", width=4, justify="right")
        t.add_column("File", style="white")
        t.add_column("Size", style="dim",  justify="right")
        for i, f in enumerate(html_files[:10], 1):
            sz = os.path.getsize(os.path.join(rdir, f))
            t.add_row(str(i), f, "{:.1f} KB".format(sz / 1024))
        console.print(t)
    else:
        rule("Available Reports")
        for i, f in enumerate(html_files[:10], 1):
            sz = os.path.getsize(os.path.join(rdir, f))
            print("  [{:2d}]  {}  ({:.1f} KB)".format(i, f, sz / 1024))

    print()
    choice = ask("Enter # to open in browser, or press Enter to skip", "")
    if choice and choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(html_files):
            subprocess.run(
                "xdg-open {}".format(os.path.join(rdir, html_files[idx])),
                shell=True
            )
            ok("Opening " + html_files[idx])

    # Also show latest JSON summary
    if json_files:
        rule("Latest JSON Summary")
        try:
            with open(os.path.join(rdir, json_files[0])) as f:
                data = json.load(f)
            meta = data.get("metadata", {})
            sev  = meta.get("severity_summary", {})
            if RICH:
                t2 = Table(box=box.SIMPLE, border_style="dim")
                t2.add_column("Field",  style="bold white")
                t2.add_column("Value",  style="cyan")
                t2.add_row("Host",       meta.get("hostname", "?"))
                t2.add_row("Scan time",  meta.get("scan_time", "?"))
                t2.add_row("Total checks", str(meta.get("total_checks", "?")))
                t2.add_row("Vulnerable",   str(meta.get("vulnerable", "?")))
                t2.add_row("Compliant",    str(meta.get("compliant", "?")))
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    t2.add_row(s, sev_text(s) + "  " + str(sev.get(s, 0)))
                console.print(t2)
            else:
                print("  Host          : " + meta.get("hostname", "?"))
                print("  Scan time     : " + meta.get("scan_time", "?"))
                print("  Total checks  : " + str(meta.get("total_checks", "?")))
                print("  Vulnerable    : " + str(meta.get("vulnerable", "?")))
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    print("  {:10s}    : {}".format(s, str(sev.get(s, 0))))
        except Exception:
            pass

    input("\n  Press Enter to return to menu...")


# ─────────────────────────────────────────────────────────────────────────

def menu_full_pipeline():
    clear()
    print_header()
    if RICH:
        console.print(Panel("[bold]Full Pipeline  (All Phases)[/]", border_style="yellow"))
    else:
        rule("Full Pipeline")

    info("This will run:")
    info("  1-5 → Dataset creation")
    info("  6   → ML model training")
    info("  7   → Detection + HTML/JSON report\n")

    mode = ask("Use live scan [l] or sample config [s]?", "s").lower()
    no_scan = "--no-scan" if mode != "l" else ""

    if not confirm("Start full pipeline now?"):
        return

    cmd = "python3 {} {}".format(path("scripts/run_pipeline.py"), no_scan)
    run_script(cmd, "Full Pipeline")

    input("\n  Press Enter to return to menu...")


# ─────────────────────────────────────────────────────────────────────────
# Main menu loop
# ─────────────────────────────────────────────────────────────────────────

def main():
    while True:
        clear()
        print_header()
        show_status()

        if RICH:
            console.print("  [bold white]Main Menu[/]\n")
        else:
            print("  Main Menu\n")

        print_menu([
            ("1", "Dataset Pipeline     — extract, generate, label, split"),
            ("2", "Train ML Model       — Random Forest severity classifier"),
            ("3", "Run Scan & Report    — detect misconfigurations"),
            ("4", "View Reports         — browse saved HTML/JSON reports"),
            ("5", "Full Pipeline        — run everything end-to-end"),
            ("q", "Quit"),
        ])

        choice = ask("Select option").strip().lower()

        if   choice == "1": menu_dataset()
        elif choice == "2": menu_train()
        elif choice == "3": menu_scan()
        elif choice == "4": menu_view_reports()
        elif choice == "5": menu_full_pipeline()
        elif choice == "q":
            if RICH:
                console.print("\n  [cyan]Goodbye![/]\n")
            else:
                print("\n  Goodbye!\n")
            sys.exit(0)
        else:
            warn("Invalid option. Please choose 1-5 or q.")
            time.sleep(1)


if __name__ == "__main__":
    main()
