#!/usr/bin/env python3
"""Check both slot layouts produce one byte-exact capture and alert."""
import pathlib
import struct
import sys

MARKER = b"NETMAP_8777_TAIL_MARKER"


def packets(directory):
    captures = list(directory.glob("output.pcap*"))
    if len(captures) > 1:
        raise ValueError(f"{directory}: expected at most one PCAP, got {len(captures)}")
    if not captures:
        return []
    data = captures[0].read_bytes()
    if len(data) < 24:
        raise ValueError(f"{directory}: truncated PCAP header")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError(f"{directory}: unsupported PCAP magic {magic!r}")
    result = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError(f"{directory}: truncated PCAP record header")
        _, _, caplen, origlen = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + caplen > len(data):
            raise ValueError(f"{directory}: truncated PCAP record")
        result.append((origlen, data[offset:offset + caplen]))
        offset += caplen
    return result


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: verify.py control|zero-fragment RESULTS_DIR")
    mode = sys.argv[1]
    if mode not in ("control", "zero-fragment"):
        raise ValueError(f"unknown case {mode}")
    directory = pathlib.Path(sys.argv[2])
    expected = (directory / "expected.bin").read_bytes()
    frames = packets(directory)
    log = directory / "fast.log"
    alerts = log.read_bytes().count(MARKER) if log.exists() else 0
    if frames != [(len(expected), expected)] or alerts != 1:
        raise ValueError(f"{mode}: expected one byte-exact capture and alert; "
                         f"got {len(frames)} frames and {alerts} alerts")
    print(f"{mode}: one exact packet and alert")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
