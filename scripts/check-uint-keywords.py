#!/usr/bin/env python3
"""
Check that each Suricata keyword with "multi .*uint" features can be used
in a rule with the syntax:  keyword: >1, all;

Usage:
    python3 scripts/check-multi-uint-keywords.py [--suricata-bin PATH] [--suricata-yaml PATH]
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


MULTI_UINT_RE = re.compile(r"multi .*uint\d+")

# Per-integer-width checks: feature word -> rule option to test
UINT_CHECKS: dict[str, tuple[re.Pattern[str], str]] = {
    "uint8":  (re.compile(r"\buint8\b"),  ">1"),
    "uint16": (re.compile(r"\buint16\b"), ">0x101"),
    "uint32": (re.compile(r"\buint32\b"), ">0x10001"),
    "uint64": (re.compile(r"\buint64\b"), ">0x100000001"),
}


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


def list_keywords(suricata_bin: Path) -> list[tuple[str, str]]:
    """Return (name, features) pairs for all keywords from --list-keywords=csv."""
    proc = subprocess.run(
        [str(suricata_bin), "--list-keywords=csv"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = proc.stdout or proc.stderr
    reader = csv.reader(io.StringIO(output), delimiter=";")
    result = []
    for i, row in enumerate(reader):
        if i == 0:
            continue
        if len(row) < 4:
            continue
        result.append((row[0].strip(), row[3].strip()))
    return result


SID_RE = re.compile(r"sid:(?P<sid>\d+)")


def check_keywords(
    entries: list[tuple[str, str]],
    suricata_bin: Path,
    suricata_yaml: Path,
) -> dict[int, list[str]]:
    """Write one rule per (keyword, option) entry, run suricata -T once.

    Returns a mapping of entry index (0-based) -> error lines for failed rules.
    """
    rules = []
    for sid, (keyword, option) in enumerate(entries, start=1):
        if keyword == "bsize":
            # bsize is a special case: it requires a sticky buffer first.
            rules.append(
                f'alert ip any any -> any any '
                f'(msg:"check {keyword} {option}"; http.uri; {keyword}: {option}; sid:{sid};)\n'
            )
        else:
            rules.append(
                f'alert ip any any -> any any '
                f'(msg:"check {keyword} {option}"; {keyword}: {option}; sid:{sid};)\n'
            )

    with tempfile.TemporaryDirectory(prefix="uint-check-") as tmpdir:
        rule_file = Path(tmpdir) / "test.rules"
        rule_file.write_text("".join(rules))
        cmd = [
            str(suricata_bin),
            "-T",
            "-c", str(suricata_yaml),
            "-S", str(rule_file),
            "-l", tmpdir,
        ]
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )

        # Attribute each error line to its entry via the sid embedded in the message.
        errors_by_idx: dict[int, list[str]] = {}
        current_idx: Optional[int] = None
        for line in proc.stderr.splitlines():
            m = SID_RE.search(line)
            if m:
                current_idx = int(m.group("sid")) - 1  # convert to 0-based
            if current_idx is not None and 0 <= current_idx < len(entries):
                errors_by_idx.setdefault(current_idx, []).append(line)
        return errors_by_idx


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check multi-uint keywords can be used with '>1, all' syntax."
    )
    parser.add_argument(
        "--suricata-bin",
        default=None,
        help="Path to Suricata binary (default: auto-detect)",
    )
    parser.add_argument(
        "--suricata-yaml",
        default=None,
        help="Path to suricata.yaml (default: <repo>/scripts/docrules/docrules.yaml)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    suricata_bin = resolve_suricata_bin(repo_root, args.suricata_bin)
    suricata_yaml = (
        Path(args.suricata_yaml)
        if args.suricata_yaml
        else (repo_root / "scripts" / "docrules" / "docrules.yaml")
    )
    if not suricata_yaml.exists():
        raise SystemExit(
            f"suricata.yaml not found: {suricata_yaml}. Use --suricata-yaml."
        )

    all_kw = list_keywords(suricata_bin)

    # Build the flat list of (keyword, option) entries for a single suricata run,
    # alongside metadata needed for reporting.
    # Each entry: (group_label, keyword, option)
    groups: list[tuple[str, str, str]] = []

    for name, features in all_kw:
        if MULTI_UINT_RE.search(features):
            groups.append(("multi-uint", name, ">1,all"))

    for type_name, (pattern, option) in UINT_CHECKS.items():
        for name, features in all_kw:
            if pattern.search(features):
                groups.append((type_name, name, option))

    if not groups:
        print("No matching keywords found.")
        return 0

    entries = [(kw, opt) for _, kw, opt in groups]
    print(f"Running {len(entries)} check(s) across {len(set(kw for _, kw, _ in groups))} keyword(s)...\n")

    errors_by_idx = check_keywords(entries, suricata_bin, suricata_yaml)

    # Report grouped by label
    seen_labels: list[str] = []
    for label in [g[0] for g in groups]:
        if label not in seen_labels:
            seen_labels.append(label)

    any_failure = False
    failures: list[tuple[str, str, str, str]] = []  # (label, keyword, option, output)

    for label in seen_labels:
        label_entries = [(i, kw, opt) for i, (lbl, kw, opt) in enumerate(groups) if lbl == label]
        print(f"--- {label} ---")
        for idx, keyword, option in label_entries:
            failed = idx in errors_by_idx
            status = "FAIL" if failed else "OK"
            print(f"  [{status}] {keyword}: {option}")
            if failed:
                any_failure = True
                failures.append((label, keyword, option, "\n".join(errors_by_idx[idx])))
        print()

    if any_failure:
        print(f"{len(failures)} check(s) failed:\n")
        for label, keyword, option, output in failures:
            print(f"  [{label}] {keyword}: {option}")
            print(f"  suricata output:\n    " + output.replace("\n", "\n    "))
            print()
        return 1

    print("All checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
