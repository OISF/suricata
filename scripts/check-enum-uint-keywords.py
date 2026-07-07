#!/usr/bin/env python3
"""
Check that each Suricata keyword with the feature "enum uint" has an
"enum_values" object in --list-keywords=json output.

Usage:
    python3 scripts/check-enum-uint-keywords.py [--suricata-bin PATH]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


def resolve_suricata_bin(repo_root: Path, configured: Optional[str]) -> Path:
    if configured:
        return Path(configured)

    in_path = shutil.which("suricata")
    if in_path:
        return Path(in_path)

    candidates = [repo_root / "src" / "suricata", repo_root / "suricata"]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise SystemExit(
        "Unable to find Suricata binary. Use --suricata-bin to provide it."
    )


def list_keywords_json(suricata_bin: Path) -> list[dict[str, Any]]:
    """Return keyword objects from --list-keywords=json output."""
    proc = subprocess.run(
        [str(suricata_bin), "--list-keywords=json"],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = proc.stdout.strip()
    if not payload:
        payload = proc.stderr.strip()

    if not payload:
        raise SystemExit("No output from suricata --list-keywords=json")

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse JSON output: {exc}") from exc

    r = []
    for keyword in data:
        obj = data[keyword]
        obj["name"] = keyword
        r.append(obj)

    return r


def has_enum_uint_feature(keyword_obj: dict[str, Any]) -> bool:
    feature_fields = []
    if "features" in keyword_obj:
        for feature in keyword_obj["features"]:
            if feature == "enum uint":
                return True

    return False


def keyword_name(keyword_obj: dict[str, Any]) -> str:
    for key in ("name", "keyword"):
        value = keyword_obj.get(key)
        if isinstance(value, str) and value:
            return value
    return "<unknown>"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check enum-uint keywords expose enum_values object in "
            "--list-keywords=json output."
        )
    )
    parser.add_argument(
        "--suricata-bin",
        default=None,
        help="Path to Suricata binary (default: auto-detect)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    suricata_bin = resolve_suricata_bin(repo_root, args.suricata_bin)
    keyword_objects = list_keywords_json(suricata_bin)

    candidates = [obj for obj in keyword_objects if has_enum_uint_feature(obj)]

    if not candidates:
        print('No keywords found with feature "enum uint".')
        return 0

    failures: list[str] = []
    print(f"Checking {len(candidates)} keyword(s) with feature 'enum uint'...\n")

    for obj in candidates:
        name = keyword_name(obj)
        enum_values = obj.get("enum_values")
        ok = isinstance(enum_values, dict)
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
        if not ok:
            failures.append(name)

    if failures:
        print(f"\n{len(failures)} keyword(s) missing enum_values object:\n")
        for name in failures:
            print(f"  - {name}")
        return 1

    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
