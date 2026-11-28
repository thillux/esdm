# AGENTS.md

Instructions for coding agents that work on the ESDM, the Entropy Source and
DRNG Manager: a random number generator for Linux in user space.

## Repository Overview

| Directory | Content |
|---|---|
| `esdm` | `libesdm`, the generator: entropy source manager, DRNG manager, entropy sources, auxiliary pool, status in shared memory |
| `crypto` | Built-in primitives (SHA-2, SHA-3, ChaCha20, Hash and HMAC DRBG); the other crypto backends are selected at build time |
| `common` | Support code shared by all parts: logging, privileges and namespaces, threading, helpers |
| `service-rpc` | RPC interface: protobuf-c service, server and client library |
| `service-egd` | EGD interface: server and client library |
| `es-ext` | External entropy source: protocol, provider library `libesdm_es_ext`, the PKCS#11 and PC/SC providers, an example |
| `frontends` | Programs: `server`, `cuse`, `getrandom`, `openssl-provider`, `tool`, `kernel-seeder`, `aux-client`, `server-signal-helper` |
| `kernel` | Kernel modules `esdm_es` (interrupt and scheduler entropy sources, with kernel patches) and `esdm_cdev` (character devices) |
| `tests` | One directory per test suite; `tests/tla` holds the TLA+ models, `tests/fuzz` the fuzzers |
| `doc/typst` | Design document, slides and poster in Typst, with figures, plots and checks |
| `doc/tools` | Checks and generators of the documentation |
| `man` | Manual pages |
| `addon` | `clang-format-helper.sh`, `sanity_checks.sh`, SELinux policy |

`meson.build` and `meson_options.txt` define the build; `flake.nix` defines
the development shell, the packages, the kernel module builds and the checks.

The ESDM is a toolkit. Only `libesdm` is mandatory; every frontend, entropy
source, interface, kernel module and tool can be left out by a build option.
A change must keep the reduced builds working, among them a server with the
RPC interface only (`-Desdm-server-egd=disabled`) and with the EGD interface
only (`-Desdm-server-rpc=disabled -Dlinux-devfiles=disabled
-Dlinux-getrandom=disabled`).

## Before Making Changes

- Read the relevant source code, its tests and its section of the design
  document before proposing a change.
- Do not make unrelated refactors. Prefer existing abstractions over new
  ones.
- Establish the facts first. Reproduce a reported defect with a test that
  fails on the unchanged code before fixing it.
- Do not remove a component because it looks redundant. The
  `server-signal-helper`, for example, stays.
- Ask before a decision that belongs to the authors: a compliance claim, an
  interface change, the removal of a feature.

## Coding Rules

- Linux kernel coding style: tabs of eight columns, lines of 80 columns.
  `.clang-format` and `.editorconfig` are at the top of the tree;
  `addon/clang-format-helper.sh` formats the tree. The generated protobuf
  code is not formatted.
- Externally visible symbols are prefixed with `esdm_`, macros with `ESDM_`.
- Conditional compilation is decided by the build system. Keep `#ifdef` in
  C files to a minimum.
- The build has no compiler warnings. A new warning is a defect.
- Secrets are wiped with the helpers of `common` before their memory is
  released.

## Building and Testing

Build inside the development shell. Nix builds run locally:

```sh
nix develop --builders '' -c meson setup build -Dtestmode=enabled
nix develop --builders '' -c meson compile -C build
nix develop --builders '' -c meson test -C build
```

- A new meson option needs `meson setup --wipe`.
- Nix does not see untracked files: `git add` a new file before a nix build.
- Several test runs at once collide on their sockets. Run one suite at a
  time per machine.
- Many tests need root and are skipped without it. Run them as mapped root
  in a user namespace (`unshare --map-root-user ... --mount --pid --fork
  --mount-proc`). The test "Kernel entropy feeder" fails there; the `cuse`
  suite does not run there.
- Test daemons start with an empty environment on purpose. Pass a variable
  through with `tests/test_env.h`.
- Known-answer tests use published vectors. A generated vector names its
  source in the test.
- The kernel modules are built with `nix build .#esdm_cdev_latest` and
  `nix build .#esdm_cdev_6_1`.
- `nix flake check` runs the checks of the flake, the TLA+ models among them.

A change is complete when:

1. the build has no warnings,
2. the meson suites pass as user and as mapped root,
3. the reduced builds it can affect still build,
4. the tests for the changed behavior exist and failed before the change.

Report the result as it is: the numbers of passed, failed and skipped tests,
and what was not run.

## TLA+ Models

`tests/tla/<Model>.tla` with its configurations `tests/tla/<Model>/*.cfg`
model the concurrent parts in PlusCal. `tests/tla/check.sh` checks them:

```sh
cd tests/tla && nix shell --builders '' nixpkgs#tlaplus18 -c ./check.sh
```

- A configuration passes when TLC finds no error, or the error its line
  `\* Expect:` names. `\* Witness:` pins the counterexample. `\* Slow` keeps
  a configuration out of the default run; naming a configuration runs it in
  any case.
- A change of modelled code changes the model in the same commit. A fixed
  defect keeps a configuration that shows the defect in the code before the
  fix.
- Deadlock and liveness checks are on. A configuration that turns one off
  states why.
- A changed model updates its section, the overview table and the table of
  findings in `doc/typst/chapters/formal-verification.typ`. State counts
  come from a run, not from memory.

## Documentation

The design document is built with:

```sh
nix build --builders '' --no-link --print-out-paths .#esdm-doc
```

It produces the document in A4 and US Letter, the slide deck, its short
version and the poster. A warning of Typst fails the build, and so do the
checks: `check-palette` (only colors of `palette.typ`), `check-identifiers`
(the options and functions named exist), `check-options` (the option
reference matches `meson_options.txt`).

The documentation is methodical and rational. It is written for a reader
who checks it: an evaluator, an integrator, a reviewer.

Method:

- Proceed in a fixed order: the requirement or the goal, the design that
  meets it, the reason for the design, the evidence. A section that states
  a property also states how the property is verified: a test, a model, an
  assessment or an argument.
- Give the reason for a decision, and name the alternatives that were
  rejected and why. A statement without a reason is a claim; mark it as
  one or support it.
- Define a term before it is used, and use one term for one thing
  throughout. Acronyms go through `acronyms.typ`.
- Separate what the ESDM does from what the operator must do, and what is
  claimed from what is not. Limits, assumptions and non-goals are written
  down in the place where the claim is made.
- State conditions precisely: the build option, the default, the unit, the
  bound. "Usually" and "should" need a stated exception or are replaced by
  the rule.
- Treat like things alike. Sections on entropy sources, interfaces, models
  and configurations follow one structure each, so that they can be
  compared and a missing item is visible.

Standards:

- FIPS 140-3 with its implementation guidance, SP 800-90A, SP 800-90B and
  SP 800-90C, and AIS 20/31 are the frame of reference. Use their terms
  where they have one: entropy source, noise source, conditioning
  component, health test, security strength, prediction resistance,
  functionality class.
- Relate a design decision that touches randomness to the requirement it
  serves, by standard, section and identifier: the construction of
  SP 800-90C, the section of the implementation guidance, the requirement
  of the functionality class of AIS 20/31.
- State for which standard a statement holds when the standards differ, for
  example in the entropy of the seed or in the reseeding.
- A compliance claim names the standard and its version, the build options
  that establish it, and the conditions under which it holds. Do not claim
  what is not shown, and do not weaken a claim silently.

Citations:

- Cite a statement that is not established by the ESDM itself: a
  requirement of a standard, a result of the literature, a property of
  another component. Cite with the keys of `references.bib` and add the
  section or the identifier of the requirement.
- Cite the version of the standard that was used. A new source gets an
  entry in `references.bib` with the data to find it.
- Refer to the code for a statement about the ESDM: the function, the build
  option or the file. Refer to sections by their labels, not by numbers.
- Do not cite from memory. Verify a quotation, a section number and an
  identifier against the source; if the source is not at hand, say so
  rather than guess.

Duplication:

- Prevent duplication, and reduce it where it exists. A fact has one place
  where it is stated in full; every other place refers to it by its label.
- Before writing a statement, search for it. Extend the existing place
  rather than add a second one. A reader who finds two versions of a fact
  must not have to decide which one holds.
- Generate what can be derived instead of copying it: the option reference
  comes from `meson_options.txt`, the excerpts of the slides are the files
  themselves, the version comes from the build.
- A summary may repeat a result in one sentence and then refers to its
  section. Tables that overlap are merged or split along one criterion.
- The slides and the poster take their statements from the design document.
  They shorten it and do not add facts of their own.
- When a fact changes, change every place that carries it in the same
  commit; search the chapters, the slides, the poster, the manual pages and
  `CHANGES.md`.

Appearance:

- The documents are visually appealing and are not marketing material.
  Appearance serves the reading: a clear hierarchy, quiet pages, figures
  that carry technical content. No slogans, no superlatives, no decoration
  without information, no claim that the text does not support.
- A figure is preferred to a paragraph where it shows structure, a flow or
  states. Every figure has a source in the repository, a caption and a
  reference in the text. Its labels are readable at the size it is printed.
- The color scheme is the one of `palette.typ` and nothing else;
  `check-palette` enforces it. Colors have fixed roles in every document
  and figure: warm tones for the entropy sources of the ESDM itself, blue
  for the processing and the interfaces of the ESDM, slate and gray for
  external parts, containers and secondary text, red for failure paths,
  always dashed. A color is never the only carrier of a meaning; the
  grayscale variant of the document must remain readable.
- The design document, the slides and the poster have one aligned look: the
  same palette and color roles, the same symbols of `icons.typ`, the same
  shapes for the same things in figures, the same names for the same
  parts. A reader who knows one of them recognizes the others.
- Keep the typography uniform within a document: one scale of sizes, one
  style of tables, captions and code. Change a style in the template, not
  at the place of use.

Rules for the text:

- Formal technical English, no first person, no informal headings.
- The document is not Common Criteria documentation, but it must be easy to
  reference from such documentation: stable section labels, defined terms,
  one statement per place.
- Every statement is one of the code. Verify a number, a default or a return
  value against the source before writing it.
- A list has at least two items. One item is a sentence.
- A table has proportional column widths; the first column is not wider
  than its content needs.
- A change that users notice adds an entry to `CHANGES.md` and updates the
  manual pages. A change of a compliance claim updates the chapter on the
  configurations in the same commit.

Rules for the slides and the poster:

- Slide titles are short and formal.
- The short deck is the full deck with the slides marked `short: true`.
  There is one source.
- The poster has a stated purpose in the header comment of its source.
  Measure a change against it. Its figures are drawn for the poster, no
  label is smaller than 34 pt, and it has two columns at most.
- Neither the slides nor the poster state counts or findings of the model
  checking.
- Look at the rendered result before reporting a visual change.

## Commits

- One topic per commit. The message starts with the component and a
  lowercase summary: `server: no core dumps after the privilege drop`.
- Every commit carries the `Signed-off-by` line of the committer
  (`git commit -s`).
- Commit and push only when asked. Rewrite published history only with
  explicit permission.
- Do not commit build directories, rendered documents or secrets.

## Code Review

When reviewing a change:

1. Inspect the complete diff, not just the changed lines.
2. Track changed behavior into its callers and consumers: the RPC and EGD
   servers, the frontends, the kernel modules.
3. Check the tests, the model and the documentation for the changed
   behavior.
4. Look for security, correctness, compatibility and data-integrity issues.
5. Report only actionable findings supported by evidence.

Do not report stylistic preferences that tooling enforces, hypothetical
problems without a plausible execution path, or issues unrelated to the
change.

### Review Output

Per finding, ordered by severity:

- **Severity**: Critical / High / Medium / Low
- **Confidence**: High / Medium / Low
- **Location**: file and line
- **Problem**: concise description
- **Impact**: what can happen
- **Evidence**: a concrete failure scenario
- **Recommendation**: a suggested fix, when appropriate

Report one finding per underlying defect.

### Summary

After the findings, state what was reviewed, what validation was performed
and what uncertainty remains. If there are no actionable findings, state:
"No actionable findings."
