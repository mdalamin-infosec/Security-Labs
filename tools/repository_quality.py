#!/usr/bin/env python3
"""Repository hygiene checks that are safe to run in CI without lab access."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PARTS = {"outputs", "target", "__pycache__"}
FORBIDDEN_SUFFIXES = {".pcap", ".pcapng", ".sqlite", ".db", ".pem", ".key"}
REQUIRED = [
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/ARCHITECTURE.md",
    "docs/RESULTS-LATEST.md",
    "docs/VALIDATION.md",
    "docs/TESTING_STRATEGY.md",
    "docs/THREAT_MODEL.md",
    "docs/LIMITATIONS.md",
    "docs/ROADMAP.md",
]


def tracked_files():
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [Path(p.decode()) for p in out.split(b"\0") if p]


def main():
    errors = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            errors.append(f"missing required documentation: {rel}")

    for rel in tracked_files():
        parts = set(rel.parts)
        if parts & FORBIDDEN_PARTS:
            errors.append(f"tracked runtime/build path: {rel}")
        if rel.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"tracked sensitive/runtime file type: {rel}")
        if any(part.endswith(".egg-info") for part in rel.parts):
            errors.append(f"tracked generated package metadata: {rel}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("Repository hygiene: PASS")
    print(f"Tracked files checked: {len(tracked_files())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
