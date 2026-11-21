#!/usr/bin/env python3
"""Verifies a QEMU screendump of the Centinela-OS framebuffer console.

Decodes every 8x16 text cell back into a character by exact pixel match
against the kernel's own glyph table (hal/src/font.rs, rows doubled
vertically, foreground 0xd0d0d0 on black), then checks that the expected
log lines are on screen. A wrong pixel anywhere in a cell makes it '?'.

Usage: check-screen.py SCREEN.ppm EXPECTED_TEXT...
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FOREGROUND = 0xD0D0D0
BACKGROUND = 0x000000


def load_font():
    source = (ROOT / "hal/src/font.rs").read_text()
    table = source[source.index("pub const BASIC"):]
    rows = re.findall(r"\[(0x[0-9A-Fa-f]{2}(?:, 0x[0-9A-Fa-f]{2}){7})\]", table)[:128]
    if len(rows) != 128:
        sys.exit(f"font parse failed: {len(rows)} glyphs")
    return [[int(v, 16) for v in row.split(", ")] for row in rows]


def load_ppm(path):
    data = Path(path).read_bytes()
    header = re.match(rb"P6\s+(\d+)\s+(\d+)\s+(\d+)\s", data)
    if not header:
        sys.exit("not a binary PPM")
    width, height = int(header.group(1)), int(header.group(2))
    pixels = data[header.end():]
    if len(pixels) < width * height * 3:
        sys.exit("truncated PPM")
    return width, height, pixels


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    font = load_font()
    width, height, pixels = load_ppm(sys.argv[1])
    glyphs = {}
    for code in range(0x20, 0x7F):
        glyphs.setdefault(tuple(font[code][y // 2] for y in range(16)), chr(code))

    def cell(column, row):
        bits = []
        for y in range(16):
            value = 0
            base = ((row * 16 + y) * width + column * 8) * 3
            for x in range(8):
                i = base + x * 3
                color = pixels[i] << 16 | pixels[i + 1] << 8 | pixels[i + 2]
                if color == FOREGROUND:
                    value |= 1 << x
                elif color != BACKGROUND:
                    return "?"
            bits.append(value)
        return glyphs.get(tuple(bits), "?")

    lines = [
        "".join(cell(column, row) for column in range(width // 8)).rstrip()
        for row in range(height // 16)
    ]
    screen = "\n".join(lines)
    print(f"screen: {width}x{height}, {sum(1 for line in lines if line)} text rows decoded")
    missing = [needle for needle in sys.argv[2:] if needle not in screen]
    if missing:
        print(screen)
        sys.exit(f"missing on screen: {missing}")
    print("PASS: framebuffer console shows the expected log lines")


if __name__ == "__main__":
    main()
