#!/usr/bin/env python3

import argparse
import csv
import os
import re
import subprocess
import sys
from urllib.parse import urlparse


def run_suricata_csv(command):
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as err:
        raise RuntimeError(f"Command not found: {command[0]}") from err
    except subprocess.CalledProcessError as err:
        stderr = err.stderr.strip() if err.stderr else ""
        raise RuntimeError(
            f"Failed to run {' '.join(command)}{': ' + stderr if stderr else ''}"
        ) from err

    output = result.stdout
    if not output.strip():
        raise RuntimeError("suricata --list-keywords=csv returned empty output")
    return output


def find_docs_column(header):
    lowered = [h.strip().lower() for h in header]
    for i, name in enumerate(lowered):
        if name == "documentation":
            return i
    return None


def extract_rows(csv_text):
    reader = csv.reader(csv_text.splitlines(), delimiter=';')

    try:
        header = next(reader)
    except StopIteration:
        return []

    docs_col = find_docs_column(header)
    rows = []

    for lineno, row in enumerate(reader, start=2):
        if not row:
            continue
        row = [col.strip() for col in row]
        keyword = row[0] if row else ""

        if docs_col is not None and docs_col < len(row):
            link = row[docs_col]
        else:
            nonempty = [col for col in row if col]
            link = nonempty[-1] if nonempty else ""

        if not link:
            continue

        rows.append((lineno, keyword, link.rstrip(';')))

    return rows


def url_to_local_path(link):
    parsed = urlparse(link)

    if parsed.scheme not in ("http", "https", ""):
        return None, None

    path = parsed.path or ""
    fragment = parsed.fragment or ""

    if not path:
        return None, fragment

    normalized = path.lstrip('/')
    if normalized.startswith("en/latest/"):
        normalized = normalized[len("en/latest/"):]
    else:
        return None, fragment

    return normalized, fragment


def read_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def anchor_exists(content, fragment):
    # Sphinx targets are exposed as id=... (and sometimes name=... for legacy anchors).
    pattern = re.compile(r"(?:id|name)=[\"']%s[\"']" % re.escape(fragment))
    return pattern.search(content) is not None


def validate_links(rows, html_dir, check_anchors):
    missing_files = []
    missing_anchors = []
    ok = 0

    cache = {}

    for lineno, keyword, link in rows:
        rel_path, fragment = url_to_local_path(link)
        if rel_path is None:
            missing_files.append((lineno, keyword, link, "unsupported or empty path"))
            continue

        abs_path = os.path.join(html_dir, rel_path)
        if not os.path.isfile(abs_path):
            missing_files.append((lineno, keyword, link, rel_path))
            continue

        if check_anchors and fragment:
            if abs_path not in cache:
                cache[abs_path] = read_file(abs_path)
            if not anchor_exists(cache[abs_path], fragment):
                missing_anchors.append((lineno, keyword, link, rel_path, fragment))
                continue

        ok += 1

    return ok, missing_files, missing_anchors


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Run suricata --list-keywords=csv and validate documentation links "
            "against generated HTML files."
        )
    )
    parser.add_argument(
        "--suricata-bin",
        default="./src/suricata",
        help="Path to suricata binary (default: suricata in PATH)",
    )
    parser.add_argument(
        "--html-dir",
        default="doc/userguide/_build/html",
        help="Path to generated HTML docs directory (default: doc/userguide/_build/html)",
    )
    parser.add_argument(
        "--no-anchor-check",
        action="store_true",
        help="Only check that target HTML files exist, do not validate #anchors",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    html_dir = os.path.abspath(args.html_dir)
    if not os.path.isdir(html_dir):
        print(f"error: HTML directory not found: {html_dir}", file=sys.stderr)
        return 2

    command = [args.suricata_bin, "--list-keywords=csv"]

    try:
        csv_output = run_suricata_csv(command)
    except RuntimeError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    rows = extract_rows(csv_output)
    if not rows:
        print("error: no keyword documentation rows found in CSV output", file=sys.stderr)
        return 2

    ok, missing_files, missing_anchors = validate_links(
        rows, html_dir, check_anchors=not args.no_anchor_check
    )

    total = len(rows)

    if missing_files:
        print("Missing HTML files:")
        for lineno, keyword, link, detail in missing_files:
            print(f"  keyword '{keyword}': {link} (expected: {detail})")

    if missing_anchors:
        print("Missing anchors:")
        for lineno, keyword, link, rel_path, fragment in missing_anchors:
            print(
                f"  keyword '{keyword}': {link} "
                f"(file: {rel_path}, anchor: #{fragment})"
            )

    print(
        f"Checked {total} documentation links: "
        f"{ok} OK, {len(missing_files)} missing files, {len(missing_anchors)} missing anchors"
    )

    return 1 if (missing_files or missing_anchors) else 0


if __name__ == "__main__":
    sys.exit(main())
