// ESDM presentation v1.0.0 - Typst translation of
// doc/esdm_presentation_v1.0.0.pdf (LibreOffice Impress), slide by slide.
// Build from doc/typst: typst compile --root . presentations/<this file>

#import "template.typ": *
#import "screens.typ": *
#import "irq-cycles-plot.typ": irq-cycles-plot

#show: setup
#set document(title: "Entropy Source and DRNG Manager")

#let figdir = "../figures/"

// ---------------------------------------------------------------- slide 1
#title-slide(
  title: [Entropy Source and \ DRNG Manager \ #"...or /dev/random in User Space"],
  author: [Stephan Müller \ \<smueller\@chronox.de\>],
)

// ---------------------------------------------------------------- slide 2
#slide(2, title: [Agenda], scale: 1, items: (
  [ESDM Goals],
  [ESDM Design],
  [Initial Seeding Strategies],
  [Entropy Sources],
))

// ---------------------------------------------------------------- slide 3
#slide(3, title: [ESDM Goals], scale: 0.466, items: (
  [Full user space implementation], (
    [No kernel changes needed – only if scheduler ES is requested],
    [Independent of political games of developers],
  ),
  [API and ABI compliant drop-in replacement of Linux /dev/random, /dev/urandom and getrandom(2)],
  [Minimal dependencies on environment], (
    [Protobuf-c],
    [FUSE / CUSE support],
  ),
  [Runs fully unprivileged],
  [Sole use of cryptography for data processing],
  [Flexible configuration supporting wide range of use cases],
  [Standards compliance: SP800-90A/B/C, AIS 20/31, FIPS IG 7.19 / D.K (use of DRBG as conditioner)],
), extra: screen(99.9pt, 365.3pt, 583.3pt, 55.4pt, 583.3pt / 1430,
  ps-output, left-px: 7, rules: (
    (regex("^\$"), it => text(fill: zenburn.green, it)),
    (regex("esdm(-server|-cuse|-proc)"), it => {
      show regex("^esdm"): set text(fill: zenburn.match, weight: "bold")
      it
    }),
  )))

// ---------------------------------------------------------------- slide 4
#slide(4, title: [ESDM Design], scale: 0.6, items: (
  [7 Entropy Sources], (
    [5 external],
    [2 internal],
    [All ES treated equally],
    [No domination by any ES – seeding \ triggered by initialization process or DRNG],
  ),
  [All ES can be selectively disabled at \ compile time],
  [ES data fed into DRNG],
  [DRNG accessible with APIs],
), extra: fig(image(figdir + "big-picture.svg", width: 389.7pt,
  height: 344.9pt, fit: "contain"), 400.5pt, 68.3pt, 389.7pt, 344.9pt))

// ---------------------------------------------------------------- slide 5
#slide(5, title: [ESDM Components], scale: 0.54, items: (
  [ESDM Server], (
    [Using ESDM library],
    [Offering RPC Interface],
    [Protobuf-C RPC],
    [Sensitive operations require \ privilege],
  ),
  [ESDM RPC library], (
    [API for other clients],
  ),
  [/dev/random CUSE],
  [/dev/urandom CUSE],
  [/proc/sys/kernel/random FUSE],
  [libesdm-getrandom.so],
), extra: fig(image(figdir + "deck-components.svg", width: 470pt,
  height: 217pt, fit: "contain"), 315pt, 149pt, 470pt, 217pt))

// ---------------------------------------------------------------- slide 6
#slide(6, title: [DRNG Output APIs], scale: 0.4625, items: (
  [Blocking APIs – deliver data only after fully initialized and fully seeded], (
    [When Linux compliant interfaces enabled:], (
      [/dev/random],
      [getrandom() system call],
    ),
  ),
  [Prediction Resistance API – deliver data only after fully initialized and successful reseed returning at most \ data equal to the amount of entropy], (
    [ESDM RPC client API],
    [Using /dev/random with O_SYNC],
    [Using getrandom(2) with flag GRND_RANDOM],
    [Compliant with:], (
      [FIPS IG 7.19 / D.K to use DRBG as conditioning component for seeding other DRBGs],
      [German AIS 20/31 (2011 and draft 2022) NTG.1 requirements],
    ),
  ),
  [Get seed: getrandom(2) with flag GRND_SEED to obtain data from entropy sources directly],
  [All other APIs deliver data without blocking until complete initialization], (
    [No guarantee of ESDM being fully initialized / seeded],
  ),
))

// ---------------------------------------------------------------- slide 7
#let log-rules = (
  (regex("^ESDM .*? Warning .*?\]:"), it => text(fill: zenburn.orange, it)),
  (regex("^ESDM .*? Debug .*?\]:"), it => text(fill: zenburn.blue, it)),
  (regex("^ESDM .*? Verbose .*?\]:"), it => text(fill: zenburn.green, it)),
)
#slide(7, title: [DRNG Seeding], scale: 0.39, items: (
  [Temporary seed buffer: \ concatenation of output from all ES],
  [Seeding during initialization: when \ 256 bits of entropy are available],
  [Seeding at runtime], (
    [After 2#super[20] generate requests or 10 minutes],
    [After forced reseed by user space],
    [After new DRNG is loaded],
    [At least 128 bits (SP800-90C mode: ESDM security strength) of total entropy must be available],
    [256 bits of entropy requested from each ES – ES may deliver less],
    [Seed operation occurs when DRNG is requested to produce random bits],
    [DRNG returns to not fully seeded when last seed with full entropy was > 2#super[30] generate operations ago],
  ),
), extra: {
  screen(279.5pt, 122.8pt, 508.8pt, 89.3pt, 508.8pt / 1977, seed-log-top,
    left-px: 3, rules: log-rules)
  screen(5.5pt, 338.7pt, 784pt, 67.7pt, 784pt / 2108, seed-log-bottom,
    left-px: 3, rules: log-rules)
})

// ---------------------------------------------------------------- slide 8
#slide(8, title: [Initial Seeding Strategy I \ Default Operation], scale: 0.84,
  items: (
  [DRNG is fully seeded with 256 bits of entropy],
  [Blocking interfaces released after DRNG is fully seeded], (
    [After 5 requests received, forced seeding with available \ entropy to achieve fully seeded level],
  ),
  [Default applied], (
    [Either no specific seeding strategy compiled],
    [Or specific seeding strategy is not enabled at start time],
  ),
))

// ---------------------------------------------------------------- slide 9
// meson_options.txt as shown in the editor screenshots: a line is an array
// of segments, a segment a string (default colour) or (style, string) with
// style "c" comment, "k" keyword, "s" string, "h" search match.
#let ed-line(segs) = {
  for seg in segs {
    if type(seg) == str {
      raw(seg)
    } else {
      let (st, s) = seg
      if st == "c" { text(fill: zenburn.cyan, raw(s)) }
      else if st == "k" { text(fill: zenburn.cyan, weight: "bold", raw(s)) }
      else if st == "s" { text(fill: zenburn.pink, raw(s)) }
      else if st == "h" { ed-hl(raw(s)) }
    }
  }
}
#let opt(name, typ, rest: (), value: none, hl-value: false) = (
  ("k", "option"), "(", ("s", "'" + name + "'"), ", type: ",
  ("s", "'" + typ + "'"), ..rest, ", value: ",
  if hl-value { ("h", value) } else { ("s", "'" + value + "'") }, ",",
)
#let desc(s) = ("       description:", ("s", s))
#let str-line(s) = (("s", s),)

#slide(9, title: [Initial Seeding Strategy II \ Entropy Source Oversampling],
  scale: 0.406, items: (
  [Fully seeded step changed],
  [Compile time option], (
    [Function only enabled in FIPS mode],
    [Function only enabled if message digest of conditioner >= 384 bits],
  ),
  [Initial conditioning: s + 64 bit],
  [Initial DRNG seeding: every entropy source requested for s + \ 128 bits], (
    [Every ES alone could provide all required entropy],
  ),
  [All ES data concatenated into seed buffer],
  [Runtime debug mode: display of all processing steps],
  [SP800-90C compliance:], (
    [SP800-90A DRBG with 256-bit strength / SHA-512 vetted \ conditioning component],
    [Complies with RBG2(NP) per default],
    [Can be configured to provide RBG2(P)],
  ),
  [Can be used in parallel with seeding strategy III],
), extra: screen(427.6pt, 195.4pt, 356.3pt, 116.6pt, 356.3pt / 865, (
  ed-line((("c", "# Option for: ESDM_OVERSAMPLE_ENTROPY_SOURCES"),)),
  ed-line((("k", "option"), "(", ("s", "'"), ("h", "oversam"),
    ("s", "ple_es'"), ", type: ", ("s", "'boolean'"), ", value: ",
    ("s", "'true'"), ",")),
  ed-line(desc("'''Oversampling of Entropy Sources.")),
  [],
  ed-line((("s", "If enabled, the ESDM "), ("h", "oversam"),
    ("s", "ples the entropy sources compliant to SP800-90C."))),
  ed-line((("s", "The "), ("h", "oversam"),
    ("s", "pling is applied in FIPS-enabled mode only."))),
  [],
  ed-line((("s", "The following "), ("h", "oversam"),
    ("s", "pling is applied:"))),
  ed-line(str-line("* Seed the DRNG with 128 more bits of entropy from the conditioning component.")),
  ed-line(str-line("* Inject 64 more bits of entropy from the noise source into the conditioning")),
  ed-line(str-line("  component.")),
  ed-line((("s", "'''"), ")")),
), left-px: 4))

// ---------------------------------------------------------------- slide 10
#slide(10, title: [Initial Seeding Strategy III \ Two Entropy Sources],
  scale: 0.456, items: (
  [Initial / minimal seeding steps apply unaltered – fully \ seeded step changed],
  [Compile time option], (
    [Function only enabled with compile option “ais2031”],
  ),
  [Initial DRNG seeding: two entropy sources \ must deliver 220 bits of entropy each],
  [All ES data concatenated into seed buffer],
  [Runtime debug mode: display of all \ processing steps],
  [German AIS 20/31 compliance], (
    [Caveat: Applies to draft version of AIS20/31 as of September 2022],
    [NTG.1: LRNG configuration ensures two entropy sources can reach at least 220 bits each],
    [PTG.3 / DRG.4: LRNG can be configured to provide a PTG.3 or DRG.4],
  ),
  [Can be used in parallel with seeding strategy II],
), extra: screen(495.2pt, 125.3pt, 288.7pt, 208.7pt, 288.7pt / 650, (
  ed-line((("c", "# Option for: ESDM_AIS2031_NTG1_SEEDING_STRATEGY"),)),
  ed-line(opt("ais2031", "boolean", value: "false")),
  ed-line(desc("'''German AIS 20/31 (2022) compliance.")),
  [],
  ..(
    "When enabling this option, two entropy sources must",
    "deliver 220 bits of entropy each to consider a DRNG",
    "as fully seeded. Any two entropy sources can be used",
    "to fulfill this requirement. If specific entropy sources",
    "shall not be capable of contributing to this seeding",
    "strategy, the respective entropy source must be configured",
    "to provide less than 220 bits of entropy.",
  ).map(s => ed-line(str-line(s))),
  [],
  ..(
    "The strategy is consistent with the requirements for",
    "NTG.1 compliance in German AIS 20/31 draft from 2022",
    "and is only enforced with lrng_es_mgr.ntg1=1.",
  ).map(s => ed-line(str-line(s))),
  [],
  ..(
    "Compliance with German AIS 20/31 from 2011 is always",
    "present when using /dev/random with the flag O_SYNC or",
    "getrandom(2) with GRND_RANDOM.",
  ).map(s => ed-line(str-line(s))),
  ed-line((("s", "'''"), ")")),
), left-px: 4))

// ---------------------------------------------------------------- slide 11
#slide(11, title: [DRNG Management], scale: 0.5, items: (
  [One DRNG per CPU up to maximum of 64],
  [Hash contexts on stack only],
  [Each DRNG initializes from entropy sources],
  [Sequential initialization of DRNG – first is CPU 0],
  [If one DRNG node is not yet fully seeded → use of \ DRNG(Node 0)],
  [Each DRNG instance managed independently],
  [To prevent reseed storm – reseed threshold different \ for each node], (
    [Node 0: 600 seconds],
    [Node 1: 700 seconds],
    […],
  ),
  [Maximum node number is compile time option],
), extra: {
  fig(image(figdir + "numa-drng.svg", width: 341pt, height: 96.3pt,
    fit: "contain"), 445.7pt, 57.9pt, 341pt, 96.3pt)
  screen(428.5pt, 210.5pt, 361.5pt, 173.8pt, 361.5pt / 880, (
    ed-line((("c", "# Option for: THREADING_MAX_THREADS"),)),
    ed-line(opt("threading_max_threads", "integer", rest: (", min: 1",),
      value: "64", hl-value: true)),
    ed-line(desc("'''Maximum number of concurrent threads supported.")),
    [],
    ed-line(str-line("This value can be set to any arbitrary number. Depending on the number")),
    ed-line(str-line("of threads, the required numbers of thread contexts are statically allocated.")),
    [],
    ed-line(str-line("The number of threads define:")),
    [],
    ed-line(str-line("* the number of concurrent DRNG instances that are maintained independent of")),
    ed-line(str-line("  each other - this value is limited by the number of found CPUs as it makes no")),
    ed-line(str-line("  sense to have more DRNG instances than CPUs that can execute them.")),
    [],
    ed-line(str-line("There is no other value that needs changing if the number of threads")),
    ed-line(str-line("shall be adjusted.")),
    [],
    ed-line(str-line("The value must not be lower than 1.")),
    ed-line((("s", "'''"), ")")),
  ), left-px: 4)
})

// ---------------------------------------------------------------- slide 12
#let hashes = "#" * 90
#slide(12, title: [Data Processing Primitives], scale: 0.481, items: (
  [Sole use of cryptographic mechanisms for data \ compression],
  [Cryptographic primitives compile-time switchable], (
    [DRNG, Conditioning hash],
    [Built-in: SP800-90A Hash DRBG SHA2-512 / SHA2-512],
    [Available Crypto-providers: OpenSSL, Botan, leancrypto],
  ),
  [Complete built-in cryptographic primitive testing available], (
    [Full ACVP test harness available: #text(fill: link-blue)[https://github.com/smuellerDD/acvpparser]],
    [ChaCha20 DRNG userspace implementation: #text(fill: link-blue)[https://github.com/smuellerDD/leancrypto]],
  ),
  [Other data processing primitives], (
    [Concatenation of data],
    [Truncation of message digest to heuristic entropy value],
  ),
  [Entropy behavior of all data processing primitives based on fully understood and uncontended \ operations],
), extra: screen(483.4pt, 122.1pt, 271.7pt, 147.5pt, 271.7pt / 849, (
  ed-line((("c", hashes),)),
  ed-line((("c", "# Cryptographic backends configuration"),)),
  ed-line((("c", hashes),)),
  [],
  ed-line((("c", "# Option for: ESDM_DRNG_HASH_DRBG"),)),
  ed-line(opt("drng_hash_drbg", "feature", value: "enabled")),
  ed-line(desc("'''SP800-90A Hash Deterministic Random Number Generator.")),
  [],
  ed-line(str-line("This configuration enables an SP800-90A Hash DRBG with SHA-512 core")),
  ed-line(str-line("without prediction resistance.")),
  ed-line((("s", "'''"), ")")),
  [],
  ed-line(opt("drng_chacha20", "feature", value: "disabled")),
  ed-line(("       description: ",
    ("s", "'ChaCha20-based Deterministic Random Number Generator.'"), ")")),
  [],
  ed-line(opt("hash_sha512", "feature", value: "enabled")),
  ed-line(("       description: ",
    ("s", "'Enable SHA2-512 conditioning hash'"), ")")),
  [],
  ed-line(opt("hash_sha3_512", "feature", value: "disabled")),
  ed-line(("       description: ",
    ("s", "'Enable SHA3-512 conditioning hash'"), ")")),
), left-px: 4))

// ---------------------------------------------------------------- slide 13
#slide(13, title: [External Entropy Sources], scale: 0.49, x: 34pt, items: (
  [Use without additional conditioning – fast source], (
    [Jitter RNG],
    [Kernel RNG],
    [CPU (e.g. Intel RDSEED, POWER DARN, RISC-V CSRRW, \ IBM Z PRNO)], (
      [Proper oversampling as defined by specification],
    ),
    [Data immediately available when ESDM requests it],
  ),
  [Additional conditioning – slow source], (
    [RNGDs],
    [Arbitrary writers to /dev/random],
    [All received data added to “auxiliary pool“ with hash update operation],
    [Data “trickles in” over time],
  ),
  [Every entropy source has individual entropy estimate], (
    [Taken at face value – each ES requires its own entropy assessment],
  ),
), extra: fig(image(figdir + "aux-pool-processing.svg", width: 297.6pt,
  height: 247.5pt, fit: "contain"), 491pt, 137.4pt, 297.6pt, 247.5pt))

// ---------------------------------------------------------------- slide 14
#slide(14, title: [Internal ES: \ Interrupts], scale: 0.522, items: (
  [Interrupt timing], (
    [All interrupts are treated as one entropy \ source],
  ),
  [Data collection executed in IRQ context],
  [Data compression executed partially in IRQ \ and process context],
  [Data compression is a hash update operation],
  [High performance: up to twice as fast as legacy /dev/random in IRQ context with continuous \ enabled], (
    [Even faster without continuous compression],
  ),
  [Kernel RNG lost acces to its primary IRQ ES#sym.arrow ESDM reseeds kernel RNG periodically],
  [Requires small kernel patch + kernel module], (
    [Code present in ESDM source tree],
  ),
), extra: irq-cycles-plot)

// ---------------------------------------------------------------- slide 15
#slide(15, title: [Internal ES: IRQ \ Data Processing], scale: 0.619, items: (
  [8 LSB of time stamp divided by \ GCD concatenated into per-CPU \ collection pool], (
    [Entropy estimate],
    [Health test],
  ),
  [32 bits of other event data concatenated into per-CPU \ collection pool],
  [When array full #sym.arrow conditioned into per-CPU entropy pool], (
    [When entropy is required #sym.arrow conditioning of all entropy pools into \ one message digest],
    [Addition of all per-CPU entropy estimates],
  ),
), extra: {
  fig(image(figdir + "irq-processing.svg", width: 415pt, height: 186pt,
    fit: "contain"), 373.2pt, 32.9pt, 415pt, 186pt)
  fig(image(figdir + "collection-pool-processing.svg", width: 219pt,
    height: 196pt, fit: "contain"), 569pt, 222pt, 219pt, 196pt)
})

// ---------------------------------------------------------------- slide 16
#slide(16, title: [Internal ES: \ Scheduler Events], scale: 0.653, items: (
  [Scheduler-based context switch timing], (
    [All context switches are treated as one entropy \ source],
  ),
  [Data collection executed in scheduler context], (
    [Collection: adding data into collection array #sym.arrow high-performance (couple of cycles)],
  ),
  [Data compression executed in process context during reseeding of DRNG],
  [Data compression is a hash operation],
  [Requires small kernel patch + kernel module], (
    [Code present in ESDM source tree],
  ),
))

// ---------------------------------------------------------------- slide 17
#slide(17, title: [Internal ES: Scheduler \ Data Processing], scale: 0.647,
  items: (
  [8 LSB of time stamp divided by \ GCD concatenated into per-CPU \ collection pool], (
    [Entropy estimate],
    [Health test],
  ),
  [When array full #sym.arrow overwriting of oldest value],
  [When entropy is required #sym.arrow conditioning of all \ entropy pools into \ one message digest], (
    [Addition of all per-CPU entropy estimates],
  ),
), extra: {
  fig(image(figdir + "sched-processing.svg", width: 350pt, height: 181pt,
    fit: "contain"), 439.6pt, 49.7pt, 350pt, 181pt)
  fig(image(figdir + "sched-pool-management.svg", width: 260pt,
    height: 175pt, fit: "contain"), 510pt, 240pt, 260pt, 175pt)
})

// ---------------------------------------------------------------- slide 18
// The entropy table of appendix C of the ESDM documentation (as rendered by
// LaTeX in the original slide, including the hyperref footnote marks).
#let fnmark(n) = box(stroke: 0.25pt + black, inset: (x: 0.2pt, y: 0.4pt),
  super(size: 0.7em, str(n)))
#let entropy-table = {
  set text(font: "New Computer Modern", size: 6.95pt, top-edge: "cap-height",
    bottom-edge: "baseline")
  set par(leading: 2.75pt)
  table(
    columns: (127pt, 69.6pt, 38.8pt),
    align: center + top,
    inset: (x: 2pt, top: 2.3pt, bottom: 2.3pt),
    stroke: 0.4pt,
    [Test System], [Entropy of \ 1,000,000 Traces], [Sufficient \ Entropy],
    table.hline(stroke: 0.4pt, y: 1),
    table.cell(colspan: 3, inset: 0pt, block(height: 1.2pt)),
    [ARMv7 rev 5], [1.9344], [Y],
    [ARMv7 rev 5 \ (Freescale i.MX53)#fnmark(22)], [7.07088], [Y],
    [ARMv7 rev 5 \ (Freescale i.MX6 Ultralite)#fnmark(23)], [6.638399], [Y],
    [ARM 64 bit AppliedMicro X-Gene \ Mustang Board], [5.599128], [Y],
    [Intel Atom Z530 – using GUI], [3.38584], [Y],
    [Intel i7 7500U Skylake - 64-bit KVM \ environment], [3.452064], [Y],
    [Intel i7 8565U Whiskey Lake – 64-bit \ KVM environment], [7.400136], [Y],
    [Intel i7 8565U Whiskey Lake – 32-bit \ KVM environment], [7.405704], [Y],
    [Intel i7 8565U Whiskey Lake], [6.871], [Y],
    [Intel Xeon Gold 6234], [4.434168], [Y],
    [IBM POWER 8 LE 8286-42A], [6.830712], [Y],
    [IBM POWER 7 BE 8202-E4C], [4.233912], [Y],
    [IBM System Z z13 (machine 2964)], [4.366368], [Y],
    [IBM System Z z15 (machine 8561)], [5.691832], [Y],
    [MIPS Atheros AR7241 rev 1#fnmark(24)], [7.157064], [Y],
    [MIPS Lantiq 34Kc V5.6#fnmark(25)], [7.032740], [Y],
    [Qualcomm IPQ4019 ARMv7#fnmark(26)], [6.638405], [Y],
    [SiFive HiFive Unmatched RISC-V U74], [2.387470], [Y],
  )
}
#slide(18, title: [Internal ES Testing \ Interfaces], scale: 0.581, items: (
  [Testing code is compile time option],
  [Access via DebugFS],
  [Testing supports data collection at boot time and runtime:], (
    [Raw unprocessed entropy time stamps for Scheduler / IRQ ES],
    [Performance data for ESDM’s Scheduler handler],
    [Performance data for ESDM’s IRQ handler],
  ),
  [Scheduler ES: Full SP800-90B assessment \ documentation yet pending],
  [IRQ ES: Full SP800-90B assessment available],
  [Raw entropy collection and analysis tools \ provided],
), extra: place(top + left, dx: 539.3pt, dy: 32.9pt, entropy-table))

// ---------------------------------------------------------------- slide 19
#slide(19, title: [Internal ES Health Test], scale: 0.581, items: (
  [Health test compile-time configurable],
  [Power-Up self tests], (
    [All cryptographic mechanisms],
    [Time stamp management],
  ),
  [APT / RCT],
  [Time-Stamp Pattern detection: 1st/2nd/3rd \ discrete derivative of time ≠ 0],
  [Blocking interface: Wait until APT power-up \ testing complete],
  [Provides SP800-90B compliance of internal ES],
))

// ---------------------------------------------------------------- slide 20
#slide(20, title: [General Testing], scale: 0.606, items: (
  [Automated regression test suite covering the different \ options of ESDM], (
    [Meson test harness],
  ),
  [Applied testing frameworks], (
    [ASAN: address, thread, undefined],
    [Valgrind memory leak detector],
    [clang-scan],
  ),
  [Performance tests of DRNG],
  [Interface validation testing],
  [Compile test testing all options],
), extra: screen(564.2pt, 39.1pt, 216.4pt, 373.2pt, 216.4pt / 868,
  meson-test-output, left-px: 1, rules: (
    (regex("\bOK\b"), it => text(fill: zenburn.ok, weight: "bold", it)),
    (regex("\bSKIP\b"), it => text(fill: zenburn.yellow, weight: "bold", it)),
  )))

// ---------------------------------------------------------------- slide 21
#slide(21, title: [ESDM - Resources], scale: 0.778, items: (
  [Code / Tests / Documentation: \ #text(fill: link-blue)[https://github.com/smuellerDD/esdm]],
  [Testing conducted with], (
    [FIPS mode],
    [Without FIPS mode],
    [With SELinux enabled],
    [Without SELinux],
    [Production use],
  ),
), extra: {
  screen(426.4pt, 195.3pt, 152.5pt, 225.2pt, 152.5pt / 546, status-left,
    left-px: 1)
  screen(594.5pt, 30.1pt, 178.1pt, 339.6pt, 178.1pt / 543, status-right,
    left-px: 1, rules: (
      (regex("^\$"), it => text(fill: zenburn.green, it)),
    ))
})
