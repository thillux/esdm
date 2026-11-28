#!/usr/bin/env python3
"""The grayscale rendering of a figure, for black and white printing.

    gray_svg.py IN.svg OUT.svg

Every light color of the SVG - #rrggbb, #rgb and rgb(r, g, b), in
attributes and styles - becomes the gray of the same relative luminance,
i.e. the same CIE lightness, as Typst's luma() converts the colors of
palette.typ, so the fills keep the distinctions they make. Every dark color
(L* below 50) - text, outlines, arrows - becomes black for the most
contrast, as the dark colors of palette.typ do in the grayscale variant of
the design document.
"""

import re
import sys


def lin(c):
    c /= 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def enc(y):
    v = 12.92 * y if y <= 0.0031308 else 1.055 * y ** (1 / 2.4) - 0.055
    return max(0, min(255, round(v * 255)))


# CIE L* 50 in relative luminance: darker colors become black
DARK = ((50 + 16) / 116) ** 3


def gray(r, g, b):
    y = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    if y < DARK:
        return "#000000"
    return "#%02x%02x%02x" % ((enc(y),) * 3)


def hex_color(m):
    h = m.group(1)
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return gray(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def rgb_color(m):
    vals = []
    for v in m.group(1).split(","):
        v = v.strip()
        vals.append(float(v[:-1]) * 2.55 if v.endswith("%") else float(v))
    return gray(*vals[:3])


def main(argv):
    with open(argv[1], encoding="utf-8") as f:
        s = f.read()
    # Not inside entities (&#183;) or URL fragments (url(#id)).
    s = re.sub(r"(?<![&\w(])#([0-9A-Fa-f]{6}|[0-9A-Fa-f]{3})\b", hex_color, s)
    s = re.sub(r"\brgba?\(([^)]*)\)", rgb_color, s)
    with open(argv[2], "w", encoding="utf-8") as f:
        f.write(s)


if __name__ == "__main__":
    main(sys.argv)
