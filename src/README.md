# Source Code

This directory contains the core implementation of the Linux misconfiguration detection framework.

## Architecture Overview

The system follows a modular design:

main.py
  → scanner (orchestrates checks)
  → checks (detect misconfigurations)
  → cis_mapping (benchmark alignment)
  → remediation_engine (recommendations)
  → result_formatter (report generation)

## Subdirectories

- checks/ → Individual security checks
- core/ → Orchestration and shared utilities
- recommendations/ → Benchmark mapping and remediation logic

The modular approach ensures scalability and maintainability.
