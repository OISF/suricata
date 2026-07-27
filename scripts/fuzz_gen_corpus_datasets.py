#!/usr/bin/env python3

import argparse
import re
import sys
from pathlib import Path


KEYWORD_RE = re.compile(r"\b(datarep|dataset)\s*:\s*(.*?);", re.IGNORECASE | re.DOTALL)
DATASET_FILE_RE = re.compile(r"\b(load|state|save)\s+([^,;\s]+)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate corpus elements for fuzz_dataset from suricata-verify tests "
            "using datarep/dataset keywords."
        )
    )
    parser.add_argument(
        "output",
        type=Path,
        help="Output directory where generated corpus files are written.",
    )
    parser.add_argument(
        "--sv-root",
        type=Path,
        default=(Path(__file__).resolve().parent.parent / "suricata-verify"),
        help="Path to suricata-verify root (default: ../suricata-verify).",
    )
    return parser.parse_args()


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return sanitized or "unnamed_test"


def normalize_argument(raw: str) -> str:
    return re.sub(r"\s+", " ", raw).strip() + ";"


def maybe_load_dataset_bytes(rules_file: Path, argument: str) -> bytes:
    match = DATASET_FILE_RE.search(argument)
    if not match:
        return b""

    dataset_name = match.group(2)
    dataset_path = (rules_file.parent / dataset_name).resolve()
    try:
        return dataset_path.read_bytes()
    except OSError:
        # Some tests use paths that are not intended to exist. Keep corpus valid.
        return b""


def replace_dataset_filename(argument: str) -> str:
    def _repl(match: re.Match) -> str:
        return f"{match.group(1)} /tmp/dataset.fuzz"

    return DATASET_FILE_RE.sub(_repl, argument)


def iter_test_rule_files(sv_root: Path):
    tests_root = sv_root / "tests"
    if not tests_root.is_dir():
        raise FileNotFoundError(f"suricata-verify tests directory not found: {tests_root}")

    by_test_dir = {}
    for rules_file in sorted(tests_root.rglob("*.rules")):
        by_test_dir.setdefault(rules_file.parent, []).append(rules_file)

    for test_dir in sorted(by_test_dir):
        yield test_dir, sorted(by_test_dir[test_dir])


def main() -> int:
    args = parse_args()

    output_dir = args.output
    sv_root = args.sv_root.resolve()

    output_dir.mkdir(parents=True, exist_ok=True)

    generated = 0
    for test_dir, rule_files in iter_test_rule_files(sv_root):
        entries = []
        for rules_file in rule_files:
            try:
                rules_text = rules_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for keyword, raw_argument in KEYWORD_RE.findall(rules_text):
                argument = normalize_argument(raw_argument)
                argument = replace_dataset_filename(argument)
                prefix = "A" if keyword.lower() == "datarep" else "B"
                dataset_bytes = maybe_load_dataset_bytes(rules_file, raw_argument)

                payload = prefix.encode("ascii") + argument.encode("utf-8") + dataset_bytes
                entries.append(payload)

        if not entries:
            continue

        base_name = sanitize_name(test_dir.name)
        if len(entries) == 1:
            out_path = output_dir / base_name
            out_path.write_bytes(entries[0])
            generated += 1
            continue

        for idx, payload in enumerate(entries, start=1):
            out_path = output_dir / f"{base_name}.{idx}"
            out_path.write_bytes(payload)
            generated += 1

    print(f"Generated {generated} corpus files in {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())