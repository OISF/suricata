#!/usr/bin/env python3
"""
Test Suricata rules in rules subdirectory
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path


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
    rule_file: str,
    suricata_bin: Path,
    suricata_yaml: Path,
) -> Tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="dist-rule-check-") as tmpdir:
        cmd = [
            str(suricata_bin),
            "-T",
            "-c", str(suricata_yaml),
            "-S", str(rule_file),
            '--strict-rule-keywords=all',
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

    for rule_file in sorted(Path(repo_root / "rules").rglob("*.rules")):
        is_valid, output_text = check_rule_with_suricata(
            rule_file,
            suricata_bin,
            suricata_yaml,
        )
        if not is_valid:
            print(
                (
                    f"Invalid rule in  #{rule_file}\n"
                    f"Suricata stderr:\n{output_text}\n"
                ),
                end="\n",
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
