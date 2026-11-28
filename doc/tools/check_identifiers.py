#!/usr/bin/env python3
"""Check that the documentation names only options and functions that exist.

    check_identifiers.py [TOP]

TOP is the top directory of the ESDM tree (default: two levels above this
script). Every inline raw text of the Typst sources under doc/typst that is
an ESDM function or macro (esdm_..., ESDM_...) must occur in the C sources,
and every meson option - a name set with name=value or -Dname=..., or a
name of meson_options.txt's naming scheme - must be one of
meson_options.txt (CON-1 of the documentation requirements). Prints each
offense and exits 1 if there is one.
"""

import os
import re
import sys

RAW = re.compile(r"`([^`\n]+)`")
OPTION_SET = re.compile(r"(?:^|\s|-D)([a-z][a-z0-9_-]*)=")
# Names that look like options of meson_options.txt: the prefixes in use.
# A bare name counts only in the underscore style; the hyphenated options
# share their prefixes with programs and count only when set (name=...).
BARE_OPTION = re.compile(r"^(es_[a-z0-9_]+|ais2031_[a-z0-9]+|drng_[a-z0-9_]+|"
                         r"sp80090c|fips140|hash_[a-z0-9_]+|"
                         r"threading_[a-z_]+)$")
SET_OPTION = re.compile(BARE_OPTION.pattern[:-2] + r"|client-[a-z-]+|"
                        r"esdm-server-[a-z-]+|linux-[a-z-]+)$")
SYMBOL = re.compile(r"\b((?:esdm|ESDM)_[A-Za-z0-9_]+)")
# Prefixes of names that are not C symbols: paths, units, status flags.
NOT_SYMBOL = ("esdm_type", "esdm_es", "esdm_cdev", "esdm_random",
              "esdm_urandom", "esdm_rpc_client.h", "esdm_egd_client.h")
# Names other projects define: Botan's Botan::ESDM_RNG, its esdm_rng module.
FOREIGN = {"ESDM_RNG", "esdm_rng"}


def main(argv):
    top = os.path.abspath(argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    with open(os.path.join(top, "meson_options.txt"), encoding="utf-8") as f:
        options = set(re.findall(r"option\(\s*'([^']+)'", f.read()))
    symbols = set()
    for dirpath, dirnames, files in os.walk(top):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")
                       and d not in ("build", "result", "doc", "subprojects")]
        for name in files:
            if name.endswith((".c", ".h", ".in", ".build", ".py")):
                with open(os.path.join(dirpath, name), encoding="utf-8",
                          errors="replace") as f:
                    symbols.update(SYMBOL.findall(f.read()))
    bad = []
    docdir = os.path.join(top, "doc", "typst")
    for dirpath, dirnames, files in os.walk(docdir):
        dirnames[:] = [d for d in dirnames if d != "build"]
        for name in sorted(files):
            if not name.endswith(".typ"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for m in RAW.finditer(text):
                raw = m.group(1)
                line = text.count("\n", 0, m.start()) + 1
                where = "%s:%d" % (os.path.relpath(path, top), line)
                names = {n for n in OPTION_SET.findall(raw)
                         if SET_OPTION.match(n)}
                if BARE_OPTION.match(raw):
                    names.add(raw)
                for opt in names:
                    if opt not in options:
                        bad.append("%s: meson option %s does not exist"
                                   % (where, opt))
                for sm in SYMBOL.finditer(raw):
                    sym = sm.group(1)
                    # esdm_builtin_*.c, esdm_rpc_<call>: patterns, no symbols
                    if raw[sm.end():sm.end() + 1] in ("*", "<"):
                        continue
                    if (sym.startswith(NOT_SYMBOL) or sym in FOREIGN
                            or sym in symbols):
                        continue
                    bad.append("%s: %s is not in the C sources"
                               % (where, sym))
    for b in bad:
        print(b, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
