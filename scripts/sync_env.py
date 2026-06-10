#!/usr/bin/env python
"""
Append missing keys from .env.example into .env without overwriting live values.

Usage:
    python scripts/sync_env.py
    python scripts/sync_env.py --dry-run
    python scripts/sync_env.py --env-file .env --example-file .env.example
"""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_env_keys(path: Path) -> set[str]:
    keys: set[str] = set()
    if not path.exists():
        return keys

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key:
            keys.add(key)
    return keys


def example_entries(path: Path) -> list[tuple[str | None, str]]:
    entries: list[tuple[str | None, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            entries.append((None, raw_line))
            continue
        key = raw_line.split("=", 1)[0].strip()
        entries.append((key, raw_line))
    return entries


def sync_env(env_file: Path, example_file: Path, dry_run: bool) -> list[str]:
    if not example_file.exists():
        raise FileNotFoundError(f"Example file not found: {example_file}")

    existing_keys = parse_env_keys(env_file)
    missing_lines: list[str] = []
    pending_context: list[str] = []

    for key, line in example_entries(example_file):
        if key is None:
            if line.strip().startswith("#"):
                pending_context.append(line)
            elif not line.strip():
                pending_context.clear()
            continue
        if key not in existing_keys:
            if pending_context:
                missing_lines.extend(pending_context)
            missing_lines.append(line)
            existing_keys.add(key)
        pending_context.clear()

    missing_lines = [line for line in missing_lines if line.strip()]
    if not missing_lines or dry_run:
        return missing_lines

    current = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    separator = "" if not current else ("\n" if current.endswith("\n") else "\n\n")
    env_file.write_text(current + separator + "\n".join(missing_lines) + "\n", encoding="utf-8")
    return missing_lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Append missing .env.example keys to .env.")
    parser.add_argument("--env-file", default=".env", help="Live env file path. Default: .env")
    parser.add_argument("--example-file", default=".env.example", help="Example env file path. Default: .env.example")
    parser.add_argument("--dry-run", action="store_true", help="Report missing entries without writing.")
    args = parser.parse_args()

    env_file = Path(args.env_file)
    example_file = Path(args.example_file)
    missing = sync_env(env_file, example_file, args.dry_run)

    if missing:
        action = "Would append" if args.dry_run else "Appended"
        print(f"{action} {len(missing)} line(s) to {env_file}:")
        for line in missing:
            print(f"  {line}")
    else:
        print(f"{env_file} already contains all keys from {example_file}.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
