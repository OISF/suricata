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


def list_multi_uint_keywords(suricata_bin: Path) -> list[str]:
    """Return keyword names whose features column matches 'multi .*uint<N>'."""
    proc = subprocess.run(
        [str(suricata_bin), "--list-keywords=csv"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = proc.stdout or proc.stderr
    reader = csv.reader(io.StringIO(output), delimiter=";")
    keywords = []
    for i, row in enumerate(reader):
        if i == 0:
            # header row
            continue
        if len(row) < 4:
            continue
        name = row[0].strip()
        features = row[3].strip()
        if MULTI_UINT_RE.search(features):
            keywords.append(name)
    return keywords


SID_RE = re.compile(r"sid:(?P<sid>\d+)")


def check_keywords(
    keywords: list[str],
    suricata_bin: Path,
    suricata_yaml: Path,
) -> dict[str, list[str]]:
    """Write all rules to one file, run suricata -T once, return keyword->errors map."""
    sid_to_keyword: dict[int, str] = {}
    rules = []
    for sid, keyword in enumerate(keywords, start=1):
        sid_to_keyword[sid] = keyword
        rules.append(
            f'alert ip any any -> any any '
            f'(msg:"check {keyword} multi uint"; {keyword}: >1,all; sid:{sid};)\n'
        )

    with tempfile.TemporaryDirectory(prefix="multi-uint-check-") as tmpdir:
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

        # Attribute each error line to the keyword via the sid embedded in the message.
        keyword_errors: dict[str, list[str]] = {}
        current_sid: Optional[int] = None
        for line in proc.stderr.splitlines():
            m = SID_RE.search(line)
            if m:
                current_sid = int(m.group("sid"))
            if current_sid is not None and current_sid in sid_to_keyword:
                kw = sid_to_keyword[current_sid]
                keyword_errors.setdefault(kw, []).append(line)
        return keyword_errors


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

    keywords = list_multi_uint_keywords(suricata_bin)
    if not keywords:
        print("No multi-uint keywords found.")
        return 0

    print(f"Testing {len(keywords)} multi-uint keyword(s): {', '.join(keywords)}\n")

    keyword_errors = check_keywords(keywords, suricata_bin, suricata_yaml)

    for keyword in keywords:
        status = "FAIL" if keyword in keyword_errors else "OK"
        print(f"  [{status}] {keyword}")

    if keyword_errors:
        print(f"\n{len(keyword_errors)} keyword(s) failed:\n")
        for keyword in keywords:
            if keyword not in keyword_errors:
                continue
            errors = "\n".join(keyword_errors[keyword])
            print(f"  keyword: {keyword}")
            print(f"  suricata output:\n    " + errors.replace("\n", "\n    "))
            print()
        return 1

    print("\nAll keywords passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
