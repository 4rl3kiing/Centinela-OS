#!/usr/bin/env python3
"""Packs files into a CPKG installer payload (see disk/src/payload.rs).

Usage: pack-payload.py OUTPUT DEST=SOURCE...
"""
import struct
import sys
from pathlib import Path

ENTRY = 96
PATH_LEN = 80


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    files = []
    for spec in sys.argv[2:]:
        dest, source = spec.split("=", 1)
        if len(dest) > PATH_LEN or dest.startswith("/") or ".." in dest.split("/"):
            sys.exit(f"bad payload path: {dest}")
        files.append((dest.encode(), Path(source).read_bytes()))
    header = b"CPKG0001" + struct.pack("<II", len(files), 0)
    offset = len(header) + ENTRY * len(files)
    table = b""
    for dest, data in files:
        table += dest.ljust(PATH_LEN, b"\0") + struct.pack("<QQ", offset, len(data))
        offset += len(data)
    Path(sys.argv[1]).write_bytes(header + table + b"".join(data for _, data in files))


if __name__ == "__main__":
    main()
