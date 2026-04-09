"""
paths.py — Single source of truth for all bug-bounty output paths.

All scanner/brain/agent output is written under OUTPUT_ROOT/{target}/ so that
the cloned repository stays clean and results live outside version control.

Configure the root via:
    export BBH_OUTPUT_DIR=/path/to/your/outputs   (default: ~/bug-bounty-outputs)
"""

import os
from pathlib import Path

OUTPUT_ROOT: str = os.environ.get(
    "BBH_OUTPUT_DIR",
    str(Path.home() / "bug-bounty-outputs"),
)


def target_dir(target: str) -> str:
    """Root directory for a specific target: OUTPUT_ROOT/{target}/"""
    return os.path.join(OUTPUT_ROOT, target)


def recon_dir(target: str) -> str:
    """Recon output directory: OUTPUT_ROOT/{target}/recon/"""
    return os.path.join(OUTPUT_ROOT, target, "recon")


def findings_dir(target: str) -> str:
    """Findings directory: OUTPUT_ROOT/{target}/findings/"""
    return os.path.join(OUTPUT_ROOT, target, "findings")


def brain_dir(target: str) -> str:
    """Brain analysis directory: OUTPUT_ROOT/{target}/brain/"""
    return os.path.join(OUTPUT_ROOT, target, "brain")


def reports_dir(target: str) -> str:
    """Reports directory: OUTPUT_ROOT/{target}/reports/"""
    return os.path.join(OUTPUT_ROOT, target, "reports")


def session_file(target: str) -> str:
    """Agent session state file: OUTPUT_ROOT/{target}/session.json"""
    return os.path.join(OUTPUT_ROOT, target, "session.json")


def session_trace(target: str) -> str:
    """Agent trace log: OUTPUT_ROOT/{target}/session.jsonl"""
    return os.path.join(OUTPUT_ROOT, target, "session.jsonl")


def ensure(path: str) -> str:
    """Create directory (and parents) if it does not exist. Return path."""
    os.makedirs(path, exist_ok=True)
    return path
