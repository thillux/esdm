#!/usr/bin/env python3
"""Reject colors that are not in the palette of the documentation.

    check_palette.py [DIR]

DIR (default: the doc/typst directory next to this script) holds
palette.typ, the only definition of the colors (VIS-1 of the documentation
requirements). Every other color written as a hex value - in the draw.io,
PlantUML and Graphviz figures, the R plots and the Typst sources - must be
one of its values; Typst sources must not use rgb(), luma() or named colors
at all outside palette.typ, but import the palette. Prints each offense
and exits 1 if there is one.
"""

import os
import re
import sys

HEX = re.compile(r"(?<!&)#([0-9A-Fa-f]{6}|[0-9A-Fa-f]{3})\b")
# Colors of Typst written in place of a palette name.
TYPST_COLOR = re.compile(r"\b(rgb|luma|cmyk|oklab|oklch)\(|"
                         r"(?<![\w.-])(black|white|gray|silver|red|green|"
                         r"blue|teal|aqua|eastern|purple|fuchsia|"
                         r"maroon|orange|yellow|olive|lime)(?![\w-])\s*[,)+]")


def norm(h):
    h = h.upper()
    return "".join(c * 2 for c in h) if len(h) == 3 else h


def main(argv):
    root = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "typst")
    palette = os.path.join(root, "palette.typ")
    with open(palette, encoding="utf-8") as f:
        allowed = {norm(m.group(1)) for m in HEX.finditer(f.read())}
    bad = []
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("build", "data")]
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            if path == palette or not name.endswith(
                    (".drawio", ".puml", ".dot", ".R", ".typ")):
                continue
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    code = line.split("//")[0] if name.endswith(".typ") \
                        else line
                    for m in HEX.finditer(code):
                        # #fig:..., #let and friends are no colors
                        if name.endswith(".typ") and not re.search(
                                r'["<]#' + m.group(1), code):
                            continue
                        if norm(m.group(1)) not in allowed:
                            bad.append("%s:%d: #%s is not in palette.typ"
                                       % (os.path.relpath(path, root), n,
                                          m.group(1)))
                    if name.endswith(".typ"):
                        m = TYPST_COLOR.search(code)
                        if m:
                            bad.append("%s:%d: %s: use a color of "
                                       "palette.typ" % (os.path.relpath(
                                           path, root), n, m.group(0)))
    for b in bad:
        print(b, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
