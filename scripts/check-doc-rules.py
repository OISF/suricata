#!/usr/bin/env python3
"""Extract Suricata rule examples from documentation RST files.

This script scans a documentation tree for ``.. container:: example-rule`` blocks,
converts role markup such as ``:example-rule-emphasis:`any``` back to plain text,
and try to load them with Suricata, outputing invalid rules
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

ROLE_RE = re.compile(
    r"`?:example-rule-(?:action|header|options|emphasis):`([^`]*)`"
)
RULE_START_RE = re.compile(
    r"^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\b", re.IGNORECASE
)


RuleWithOrigin = Tuple[str, Path, int]


def indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def clean_rule_text(text: str) -> str:
    # Unescape custom role markup used by docs around rule fragments.
    cleaned = ROLE_RE.sub(r"\1", text)
    # In docs, trailing '\\' is often used to wrap long rules across lines.
    cleaned = re.sub(r"\\\s*\n\s*", " ", cleaned)
    # RST often escapes pipe characters in examples.
    cleaned = cleaned.replace("\\|", "|")
    cleaned = cleaned.replace("\\*", "*")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def collect_container_body(lines: List[str], start_idx: int) -> Tuple[str, int]:
    container_indent = indent_width(lines[start_idx])
    body_lines: List[str] = []
    i = start_idx + 1

    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            body_lines.append("")
            i += 1
            continue

        if indent_width(line) <= container_indent:
            break

        body_lines.append(line)
        i += 1

    non_empty = [line for line in body_lines if line.strip()]
    if non_empty:
        min_indent = min(indent_width(line) for line in non_empty)
        dedented = [line[min_indent:] if line.strip() else "" for line in body_lines]
    else:
        dedented = []

    return "\n".join(dedented).strip(), i


def extract_rules_from_rst(path: Path) -> Iterator[Tuple[str, int]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0

    while i < len(lines):
        if lines[i].strip() == ".. container:: example-rule":
            block_text, i = collect_container_body(lines, i)
            if block_text:
                cleaned = clean_rule_text(block_text)
                yield cleaned, i
            continue
        i += 1


def iter_rst_files(path: Path) -> Iterable[Path]:
    if path.is_file() and path.suffix == ".rst":
        return [path]
    if path.is_dir():
        return sorted(path.rglob("*.rst"))
    return []


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


def check_rule_with_suricata(
    rule: str,
    suricata_bin: Path,
    suricata_yaml: Path,
) -> Tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="doc-rule-check-") as tmpdir:
        rule_file = Path(tmpdir) / "rule.rules"
        rule_file.write_text(rule + "\n", encoding="utf-8")

        cmd = [
            str(suricata_bin),
            "-T",
            "-c", str(suricata_yaml),
            "--set", "app-layer.protocols.pgsql.enabled=true",
            "--data-dir="+tmpdir,
            "-S", str(rule_file),
            "-l", tmpdir,
        ]
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )

        combined = proc.stderr.strip()
        return proc.returncode == 0, combined


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Suricata rules from doc RST example-rule containers."
    )
    parser.add_argument(
        "doc_path",
        nargs="?",
        default="doc",
        help="Path to doc directory or .rst file (default: doc)",
    )
    parser.add_argument(
        "--suricata-bin",
        default=None,
        help="Path to Suricata binary (default: auto-detect)",
    )
    parser.add_argument(
        "--suricata-yaml",
        default=None,
        help="Path to suricata.yaml (default: <repo>/suricata.yaml)",
    )
    args = parser.parse_args()

    doc_path = Path(args.doc_path)
    if not doc_path.exists():
        raise SystemExit(f"Invalid doc path: {doc_path}")

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

    rules_with_origin: List[RuleWithOrigin] = []
    for rst_file in iter_rst_files(doc_path):
        for rule, line_number in extract_rules_from_rst(rst_file):
            rules_with_origin.append((rule, rst_file, line_number))

    invalid_rules = 0
    for index, (rule, source_file, line_number) in enumerate(rules_with_origin, start=1):
        is_valid, output_text = check_rule_with_suricata(
            rule,
            suricata_bin,
            suricata_yaml,
        )
        if not is_valid:
            print(
                (
                    f"Invalid rule at #{index} ({source_file}:{line_number})\n"
                    f"Rule: {rule}\n"
                    f"Suricata stderr:\n{output_text}\n"
                ),
                end="\n",
            )
            invalid_rules = invalid_rules + 1

    if invalid_rules:
        print(
            f"Found {invalid_rules} invalid rule(s) out of {len(rules_with_origin)} checked.",
            end="\n\n",
        )
        return 1

    print(
        f"Found no invalid rule out of {len(rules_with_origin)} checked.",
        end="\n\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
