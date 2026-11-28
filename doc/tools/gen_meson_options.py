#!/usr/bin/env python3
"""Generate the reference of the meson options from meson_options.txt.

    gen_meson_options.py [--check] [TOP]

TOP is the top directory of the ESDM tree (default: two levels above this
script). Writes doc/typst/chapters/build-options-list.typ: one section per
banner of meson_options.txt, one entry per option with its type, default,
range or choices and description. With --check, writes nothing and exits 1
if the file is not what meson_options.txt gives, so that the reference
cannot fall behind the options.
"""

import os
import re
import sys

OUT = os.path.join("doc", "typst", "chapters", "build-options-list.typ")

# The headings of the banners of meson_options.txt; a banner not listed
# keeps its own words, less "configuration (options)".
HEADINGS = {
    "Jitter RNG entropy source configuration": "Jitter RNG",
    "CPU-based Entropy Source configuration options": "CPU Entropy Source",
    "Kernel RNG entropy source configuration (/dev/random)":
        "Kernel RNG Entropy Source",
    "Interrupt-based entropy source configuration":
        "Interrupt Entropy Source",
    "Scheduler-based entropy source configuration":
        "Scheduler Entropy Source",
    "eBPF-based entropy source configuration": "eBPF Entropy Sources",
    "/dev/hwrand-based Entropy Source configuration options":
        "Hardware RNG Entropy Source",
    "TPM 2.0 Entropy Source configuration options": "TPM 2.0 Entropy Source",
    "PKCS#11 and PC/SC Entropy Source configuration options":
        "PKCS#11 and PC/SC Entropy Sources",
    "Linux-kernel jitterentropy Entropy Source":
        "Kernel Jitter RNG Entropy Source",
    "External Entropy Source configuration options":
        "External Entropy Sources",
    "Common Options": "Seeding, Compliance and Threads",
    "Cryptographic backends configuration": "Cryptographic Backends",
    "Linux Interface Configuration": "Linux Interfaces and the Server",
    "Client-related Configuration": "Clients",
    "Server-related Configuration": "Server",
    "Auxiliary Options": "Auxiliary Programs",
    "Enable Test configuration": "Testing",
    "Fuzz testing": "Fuzzing",
}


class Parser:
    """The subset of the meson language meson_options.txt uses."""

    def __init__(self, text):
        self.s = text
        self.i = 0

    def ws(self):
        while self.i < len(self.s):
            if self.s[self.i].isspace():
                self.i += 1
            elif self.s[self.i] == "#":
                self.i = self.s.index("\n", self.i)
            else:
                break

    def value(self):
        self.ws()
        s, i = self.s, self.i
        if s.startswith("'''", i):
            end = s.index("'''", i + 3)
            self.i = end + 3
            return s[i + 3:end]
        if s[i] == "'":
            end = s.index("'", i + 1)
            self.i = end + 1
            return s[i + 1:end]
        if s[i] == "[":
            self.i += 1
            items = []
            while True:
                self.ws()
                if self.s[self.i] == "]":
                    self.i += 1
                    return items
                items.append(self.value())
                self.ws()
                if self.s[self.i] == ",":
                    self.i += 1
        m = re.compile(r"-?0x[0-9a-fA-F]+|-?\d+|true|false").match(s, i)
        if not m:
            raise ValueError("unexpected input at %r" % s[i:i + 40])
        self.i = m.end()
        tok = m.group(0)
        return {"true": True, "false": False}.get(tok, tok)

    def option(self):
        """Parses the arguments of option( up to its closing parenthesis."""
        name = self.value()
        kw = {}
        while True:
            self.ws()
            if self.s[self.i] == ")":
                self.i += 1
                return name, kw
            if self.s[self.i] == ",":
                self.i += 1
                continue
            m = re.compile(r"([a-z_]+)\s*:").match(self.s, self.i)
            self.i = m.end()
            kw[m.group(1)] = self.value()


def parse(text):
    """Returns [(banner, [(name, kwargs)])] in the order of the file."""
    sections = []
    pos = 0
    # A banner: a title line between two rules, comment lines may follow it
    token = re.compile(r"^#{10,}\n# (.+)\n(?:#(?!#{9}).*\n)*#{10,}$|"
                       r"^\s*option\(", re.M)
    while True:
        m = token.search(text, pos)
        if not m:
            return sections
        if m.group(1):
            sections.append((m.group(1).strip(), []))
            pos = m.end()
            continue
        p = Parser(text)
        p.i = m.end()
        sections[-1][1].append(p.option())
        pos = p.i


def heading(banner):
    return HEADINGS.get(banner, re.sub(r"\s+configuration( options)?$", "",
                                       banner, flags=re.I))


def tstr(s):
    """A Typst string literal: its text is set as is, never as markup."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def blocks(desc):
    """The paragraphs and list items of a description, after its summary.

    meson shows the first line as the summary of an option; the rest are
    paragraphs separated by blank lines, items starting with "-" or "*", or
    indented lines that continue the item above.
    """
    lines = desc.strip("\n").split("\n")
    summary = lines[0].strip().rstrip(".")
    out, cur = [], None
    for line in lines[1:]:
        text = line.strip()
        if not text:
            cur = None
            continue
        item = re.match(r"^[-*]\s+(.*)", text)
        if item:
            cur = ["item", item.group(1)]
            out.append(cur)
        elif cur is None:
            cur = ["par", text]
            out.append(cur)
        else:
            cur[1] += " " + text
    return summary, out


def kind(kw):
    t = kw["type"]
    v = kw.get("value")
    if t == "boolean":
        return "boolean", "true" if v is True else "false"
    if t == "integer":
        rng = ""
        if "min" in kw or "max" in kw:
            rng = "%s to %s" % (kw.get("min", "…"), kw.get("max", "…"))
        return "integer" + (", " + rng if rng else ""), str(v)
    if t == "combo":
        return "one of " + ", ".join(kw["choices"]), v
    if t == "string":
        return "string", v if v else "(empty)"
    return t, v


def render(sections):
    out = [
        "// Generated by doc/tools/gen_meson_options.py from"
        " meson_options.txt -",
        "// do not edit: change meson_options.txt and run the script.",
        "#import \"../template.typ\": *",
        "",
        "#let option-entry(name, kind, default, summary, body) = block(",
        "  breakable: true, above: 1.2em, below: 0.6em, {",
        "    block(sticky: true, below: 0.45em, {",
        "      text(weight: \"semibold\", raw(name))",
        "      h(0.8em)",
        "      text(size: 0.9em, fill: muted, [#kind · default #raw(default)])",
        "    })",
        "    pad(left: 1.4em, {",
        "      par(summary + \".\")",
        "      for (k, t) in body {",
        "        if k == \"item\" { list(t) } else { par(t) }",
        "      }",
        "    })",
        "  })",
        "",
    ]
    for banner, options in sections:
        title = heading(banner)
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        out.append("== %s <sec:options-%s>" % (title, slug))
        out.append("")
        for name, kw in options:
            k, default = kind(kw)
            summary, body = blocks(kw.get("description", ""))
            items = ", ".join("(%s, %s)" % (tstr(a), tstr(b))
                              for a, b in body)
            out.append("#option-entry(%s, %s, %s, %s, (%s))" % (
                tstr(name), tstr(k), tstr(str(default)), tstr(summary),
                items + ("," if len(body) == 1 else "")))
            out.append("")
    return "\n".join(out)


def main(argv):
    check = "--check" in argv
    args = [a for a in argv[1:] if a != "--check"]
    top = os.path.abspath(args[0] if args else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    with open(os.path.join(top, "meson_options.txt"), encoding="utf-8") as f:
        text = render(parse(f.read()))
    path = os.path.join(top, OUT)
    if check:
        try:
            with open(path, encoding="utf-8") as f:
                current = f.read()
        except FileNotFoundError:
            current = None
        if current != text:
            print("%s is not current: run doc/tools/gen_meson_options.py"
                  % OUT, file=sys.stderr)
            return 1
        return 0
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
