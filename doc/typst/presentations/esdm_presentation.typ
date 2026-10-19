// ESDM presentation for release 1.2.4.
//
// Started as the Typst translation of doc/esdm_presentation_v1.0.0.pdf, which
// stays as the historical deck, and brought in line with the code of ESDM
// 1.2.4. The editor views show meson_options.txt verbatim (meson-excerpts.typ).
// Build from doc/typst: typst compile --root . presentations/<this file>

#import "template.typ": *
#import "meson-excerpts.typ": *

#show: setup
#set document(title: "Entropy Source and DRNG Manager 1.2.4")

#let figdir = "../figures/"

// An editor view of meson_options.txt (vim, Zenburn colours): comments
// cyan, the option keyword bold, strings - the ''' descriptions included -
// pink. `lines` are the verbatim lines of the file.
#let meson-view(x, y, w, h, px, lines) = {
  let pink(s) = text(fill: zenburn.pink, raw(s))
  // A line outside of a description: quoted strings pink, the rest plain.
  let plain(s) = {
    let parts = ()
    let pos = 0
    for m in s.matches(regex("'[^']*'")) {
      parts.push(raw(s.slice(pos, m.start)))
      parts.push(pink(m.text))
      pos = m.end
    }
    parts.push(raw(s.slice(pos)))
    parts.join()
  }
  let out = ()
  let in-str = false
  for l in lines {
    if in-str {
      let i = l.position("'''")
      if i == none {
        out.push(pink(l))
      } else {
        out.push([#pink(l.slice(0, i + 3))#raw(l.slice(i + 3))])
        in-str = false
      }
    } else if l.starts-with("#") {
      out.push(text(fill: zenburn.cyan, raw(l)))
    } else {
      let i = l.position("'''")
      let head = if i == none { l } else { l.slice(0, i) }
      let body = if head.starts-with("option") {
        [#text(fill: zenburn.cyan, weight: "bold", raw("option"))#plain(head.slice(6))]
      } else { plain(head) }
      if i != none {
        let rest = l.slice(i + 3)
        let j = rest.position("'''")
        if j == none {
          body = [#body#pink(l.slice(i))]
          in-str = true
        } else {
          body = [#body#pink(l.slice(i, i + 3 + j + 3))#raw(rest.slice(j + 3))]
        }
      }
      out.push(body)
    }
  }
  screen(x, y, w, h, px, out, left-px: 4)
}

// ---------------------------------------------------------------- slide 1
#title-slide(
  title: [Entropy Source and \ DRNG Manager 1.2.4 \ #"...or /dev/random in User Space"],
  author: [Stephan Müller \ \<smueller\@chronox.de\>],
)

// ---------------------------------------------------------------- slide 2
#slide(2, title: [Agenda], scale: 1, items: (
  [ESDM Goals],
  [ESDM Design],
  [Initial Seeding Strategies],
  [Entropy Sources],
  [Testing],
))

// ---------------------------------------------------------------- slide 3
#slide(3, title: [ESDM Goals], scale: 0.48, items: (
  [Full user space implementation], (
    [No kernel changes needed – only for the interrupt / scheduler ES of the kernel module],
    [eBPF-based interrupt / scheduler ES on a stock kernel],
    [Independent of political games of developers],
  ),
  [API and ABI compliant drop-in replacement of Linux /dev/random, /dev/urandom and getrandom(2)],
  [Minimal dependencies on environment], (
    [Protobuf-c, json-c],
    [FUSE / CUSE support],
  ),
  [Runs unprivileged – privileges dropped after initialization],
  [Sole use of cryptography for data processing],
  [Flexible configuration supporting wide range of use cases],
  [Standards compliance: SP800-90A/B/C, AIS 20/31 3.0 (NTG.1, DRG.3, DRG.4), FIPS 140, \ FIPS IG 7.19 / D.K (use of DRBG as conditioner)],
))

// ---------------------------------------------------------------- slide 4
#slide(4, title: [ESDM Design], scale: 0.6, items: (
  [14 Entropy Sources], (
    [4 internal: interrupt / scheduler timing – kernel module or eBPF],
    [10 external, among them the auxiliary pool],
    [All ES treated equally],
    [No domination by any ES – seeding triggered by initialization process or DRNG],
    [At most one timing ES credited with entropy],
  ),
  [All ES can be selectively disabled at compile time],
  [ES data fed into DRNG – uncredited ES as additional input],
  [DRNG accessible with APIs],
))

// ---------------------------------------------------------------- slide 5
#slide(5, title: [ESDM Big Picture], extra: fig(image(figdir +
  "big-picture.svg", width: 730pt, height: 305pt, fit: "contain"), 32pt,
  112pt, 730pt, 305pt))

// ---------------------------------------------------------------- slide 6
#slide(6, title: [ESDM Components], scale: 0.44, width: 270pt, items: (
  [ESDM Server], (
    [Using ESDM library],
    [RPC: Protobuf-C messages on Unix domain sockets],
    [Opportunistic DTLS 1.2 (option dtls)],
    [Sensitive operations require privilege],
    [Optional EGD interface with ESDM commands: prediction resistance, status, entropy accounting],
  ),
  [ESDM RPC library], (
    [API for other clients],
  ),
  [EGD client library],
  [Frontends on the RPC library – next slide],
), extra: fig(image(figdir + "deck-components.svg", width: 492pt,
  height: 280pt, fit: "contain"), 296pt, 132pt, 492pt, 280pt))

// ---------------------------------------------------------------- slide 7
#slide(7, title: [ESDM Frontends], scale: 0.5, items: (
  [/dev/random and /dev/urandom CUSE daemons], (
    [Fall back to the kernel device when the ESDM is unavailable],
  ),
  [/proc/sys/kernel/random FUSE daemon],
  [Kernel module esdm_cdev: /dev/esdm_random, /dev/esdm_urandom, /proc/esdm – over EGD],
  [libesdm-getrandom.so: getrandom(2) / getentropy(3)],
  [OpenSSL 3 providers], (
    [RNG, RNG with prediction resistance, SEED-SRC – over RPC],
    [EGD, EGD with prediction resistance – over the EGD socket],
  ),
  [esdm-kernel-seeder: reseeds the kernel RNG every 120 seconds],
  [esdm-tool: status (text / JSON), self test, wait until fully seeded],
  [Auxiliary client library: notification when the ESDM needs entropy],
  [esdm-es-ext-serve: serves an external entropy source to the ESDM],
))

// ---------------------------------------------------------------- slide 8
#slide(8, title: [DRNG Output APIs], scale: 0.375, items: (
  [Blocking APIs – deliver data only after fully initialized and fully seeded], (
    [When Linux compliant interfaces enabled:], (
      [/dev/random],
      [getrandom() system call],
    ),
    [/dev/esdm_random of the kernel module esdm_cdev],
  ),
  [Prediction Resistance API – deliver data only after fully initialized and successful reseed returning at most \ data equal to the amount of entropy], (
    [ESDM RPC client API (blocking and non-blocking)],
    [Using /dev/random, /dev/urandom, /dev/esdm_random or /dev/esdm_urandom with O_SYNC],
    [Using getrandom(2) with flag GRND_RANDOM],
    [EGD prediction resistance reads (ESDM commands 0xe0, 0xe1)],
    [Compliant with:], (
      [FIPS IG 7.19 / D.K to use DRBG as conditioning component for seeding other DRBGs],
      [SP800-90C RBG3(RS) when oversampling is in effect],
      [German AIS 20/31 (2011) NTG.1 requirements],
    ),
  ),
  [Get seed: getrandom(2) with flag GRND_SEED (and GRND_FULLY_SEEDED) to obtain data from entropy sources directly],
  [All other APIs deliver data without blocking], (
    [Error until the ESDM is fully operational – the Linux interfaces fall back to the kernel],
  ),
))

// ---------------------------------------------------------------- slide 9
#slide(9, title: [DRNG Seeding], scale: 0.48, items: (
  [Temporary seed buffer: concatenation of output from all ES],
  [Seeding during initialization: when 256 bits of entropy are available],
  [Seeding at runtime], (
    [After 2#super[20] generate requests or 10 minutes],
    [After forced reseed by user space],
    [At least 256 bits of total entropy must be available],
    [256 bits of entropy requested from each ES – ES may deliver less],
    [Asynchronous reseed worker – a DRNG serves requests meanwhile],
    [DRNG returns to not fully seeded when last seed with full entropy was > 2#super[30] generate operations ago],
    [SP800-90C / DRG.4: not fully seeded after 2#super[17] output bits without reseed],
  ),
))

// ---------------------------------------------------------------- slide 10
#slide(10, title: [Initial Seeding Strategy I \ Default Operation], scale: 0.7,
  items: (
  [DRNG is fully seeded with 256 bits of entropy],
  [Blocking interfaces released after DRNG is fully seeded], (
    [While not operational, a request triggers emergency seeding: \ repeated seeding with the available entropy up to the \ fully seeded level],
  ),
  [Default applied], (
    [Either no specific seeding strategy compiled],
    [Or specific seeding strategy is not enabled at start time],
  ),
))

// ---------------------------------------------------------------- slide 11
#slide(11, title: [Initial Seeding Strategy II \ Entropy Source Oversampling],
  scale: 0.406, width: 390pt, items: (
  [Fully seeded step changed],
  [Compile time option], (
    [sp80090c, fips140 or ais2031_drg3],
    [Applied whenever compiled in],
  ),
  [Initial conditioning: s + 64 bit],
  [Initial DRNG seeding: every entropy source requested for s + 128 bits], (
    [Every ES alone could provide all required entropy],
  ),
  [All ES data concatenated into seed buffer],
  [Runtime debug mode: display of all processing steps],
  [SP800-90C compliance:], (
    [SP800-90A DRBG with 256-bit strength, XDRBG-256 entropy pools],
    [Complies with RBG2(NP) per default],
    [Can be configured to provide RBG2(P)],
  ),
  [Can be used in parallel with seeding strategy III],
), extra: meson-view(427.6pt, 195.4pt, 356.3pt, 116.6pt, 356.3pt / 865,
  meson-sp80090c))

// ---------------------------------------------------------------- slide 12
#slide(12, title: [Initial Seeding Strategy III \ Two Entropy Sources],
  scale: 0.43, width: 450pt, items: (
  [Initial seeding step changed],
  [Compile time option], (
    [Function only enabled with compile option “ais2031_ntg1”],
  ),
  [Initial DRNG seeding: two entropy sources \ must deliver 240 bits of entropy each], (
    [Or a Jitter RNG in its own NTG.1 mode alone],
  ),
  [All ES data concatenated into seed buffer],
  [Runtime debug mode: display of all \ processing steps],
  [German AIS 20/31 3.0 (2024) compliance], (
    [NTG.1: ESDM configuration ensures two entropy sources can reach at least 240 bits each],
    [DRG.3 / DRG.4: options ais2031_drg3 / ais2031_drg4],
  ),
  [Can be used in parallel with seeding strategy II],
), extra: meson-view(495.2pt, 125.3pt, 288.7pt, 268pt, 288.7pt / 650,
  meson-ntg1))

// ---------------------------------------------------------------- slide 13
#slide(13, title: [AIS 20/31 DRG.3 / DRG.4], scale: 0.5, width: 380pt, items: (
  [ais2031_drg3], (
    [Entropy source oversampling of SP800-90C],
    [Without the request size based reseeding limits],
  ),
  [ais2031_drg4], (
    [DRNG not fully seeded after 2#super[17] output bits \ without successful reseed],
    [Reseed after three quarters of that at the latest],
    [Also applied by sp80090c and fips140],
  ),
  [Mutually exclusive],
  [Status reports the satisfied classes],
), extra: meson-view(427.6pt, 125.3pt, 356.3pt, 160pt, 356.3pt / 865,
  meson-drg4))

// ---------------------------------------------------------------- slide 14
#slide(14, title: [DRNG Management], scale: 0.48, width: 390pt, items: (
  [One DRNG per CPU up to maximum of 64],
  [Each DRNG initializes from entropy sources],
  [Sequential initialization of DRNG – first is the initial DRNG],
  [If one DRNG node is not yet fully seeded → use of \ another node or the initial DRNG],
  [Each DRNG instance managed independently],
  [To prevent reseed storm – seed times of the nodes \ staggered by up to 10% of the 600 seconds],
  [Separate DRNG for prediction resistance],
  [Maximum node number is compile time option – \ fewer at start time (esdm-server -M)],
), extra: {
  fig(image(figdir + "numa-drng.svg", width: 341pt, height: 96.3pt,
    fit: "contain"), 445.7pt, 57.9pt, 341pt, 96.3pt)
  meson-view(428.5pt, 210.5pt, 361.5pt, 173.8pt, 361.5pt / 880,
    meson-threads)
})

// ---------------------------------------------------------------- slide 15
#slide(15, title: [Data Processing Primitives], scale: 0.44, width: 425pt,
  items: (
  [Sole use of cryptographic mechanisms for data \ compression],
  [Cryptographic primitives compile-time switchable], (
    [DRNG, Conditioning hash, SHAKE256],
    [Built-in: SP800-90A Hash DRBG SHA2-512 / SHA2-512],
    [Crypto backends: OpenSSL, Botan, GnuTLS, leancrypto],
  ),
  [Entropy pools: XDRBG-256 over SHAKE256], (
    [Auxiliary pool, eBPF conditioning pool],
    [Insert: seed of the next reseed – extract: reseed and generate],
  ),
  [Complete built-in cryptographic primitive testing available], (
    [Full ACVP test harness available: #text(fill: link-blue)[https://github.com/smuellerDD/acvpparser]],
    [ChaCha20 DRNG userspace implementation: #text(fill: link-blue)[https://github.com/smuellerDD/leancrypto]],
  ),
  [Other data processing primitives: concatenation of data],
), extra: meson-view(483.4pt, 122.1pt, 271.7pt, 255pt, 271.7pt / 849,
  meson-backend))

// ---------------------------------------------------------------- slide 16
#slide(16, title: [External Entropy Sources], scale: 0.45, x: 34pt, width: 455pt,
  items: (
  [Use without additional conditioning – fast source], (
    [Jitter RNG (optionally in its own NTG.1 mode), kernel Jitter RNG],
    [Kernel RNG, Linux HWRand, TPM 2.0, PKCS\#11 token],
    [CPU (e.g. Intel RDSEED, POWER DARN, RISC-V seed CSR, \ IBM Z PRNO, ARM RNDRRS)], (
      [Proper oversampling as defined by specification],
    ),
    [Data immediately available when ESDM requests it],
  ),
  [Additional conditioning – slow source], (
    [RNGDs],
    [Arbitrary writers to /dev/random],
    [All received data added to “auxiliary pool“ – an XDRBG-256],
    [Data “trickles in” over time],
  ),
  [Every entropy source has individual entropy estimate], (
    [Taken at face value – each ES requires its own entropy assessment],
  ),
), extra: fig(image(figdir + "aux-pool-processing.svg", width: 297.6pt,
  height: 247.5pt, fit: "contain"), 491pt, 137.4pt, 297.6pt, 247.5pt))

// ---------------------------------------------------------------- slide 17
#slide(17, title: [External Entropy Sources II], scale: 0.48, items: (
  [TPM 2.0: TPM2_GetRandom on the resource manager /dev/tpmrm0],
  [PKCS\#11 token via libp11 – module path at start time],
  [Kernel Jitter RNG: kernel crypto API RNG, name configurable],
  [External entropy sources developed against libesdm_es_ext], (
    [ExternalLib: plugin library loaded into the esdm-server],
    [ExternalSocket: provider process on a Unix domain socket, \ e.g. esdm-es-ext-serve – opportunistic DTLS],
    [Credit capped by a configured rate – a provider is uncredited by default],
  ),
  [Slow sources: asynchronous buffer of entropy blocks, \ sources fetched in parallel during a reseed],
))

// ---------------------------------------------------------------- slide 18
#slide(18, title: [Internal ES: \ Interrupts], scale: 0.522, items: (
  [Interrupt timing], (
    [All interrupts are treated as one entropy source],
  ),
  [Data collection executed in IRQ context],
  [Collection: time stamp into a per-CPU ring – lock-free, a couple of cycles],
  [Conditioning: SP800-90A DRBG of the kernel when entropy is requested],
  [esdm-kernel-seeder reseeds the kernel RNG periodically],
  [Requires small kernel patch + kernel module], (
    [Code present in ESDM source tree: kernel/esdm_es],
  ),
  [Alternative without kernel patch: eBPF-based interrupt ES],
))

// ---------------------------------------------------------------- slide 19
#slide(19, title: [Internal ES: IRQ \ Data Processing], scale: 0.52,
  width: 300pt, items: (
  [64-bit time stamp divided by GCD added to per-CPU ring], (
    [Entropy estimate: by default 1 bit per 3 events],
    [Health test in FIPS mode],
  ),
  [When ring full #sym.arrow new events dropped],
  [When entropy is required #sym.arrow events of all rings seed the kernel DRBG], (
    [DRBG output is the seed data],
    [Addition of all per-CPU entropy estimates],
  ),
), extra: fig(image(figdir + "irq-processing.svg", width: 440pt,
  height: 250pt, fit: "contain"), 352pt, 150pt, 436pt, 250pt))

// ---------------------------------------------------------------- slide 20
#slide(20, title: [Internal ES: \ Scheduler Events], scale: 0.6, items: (
  [Scheduler-based context switch timing], (
    [All context switches are treated as one entropy source],
  ),
  [Data collection executed in scheduler context], (
    [Collection: adding data into per-CPU ring #sym.arrow high-performance (couple of cycles)],
  ),
  [Data compression executed in process context during reseeding of DRNG],
  [Data compression is the SP800-90A DRBG of the kernel],
  [Requires small kernel patch + kernel module], (
    [Code present in ESDM source tree: kernel/esdm_es],
  ),
  [Alternative without kernel patch: eBPF-based scheduler ES],
))

// ---------------------------------------------------------------- slide 21
#slide(21, title: [Internal ES: Scheduler \ Data Processing], scale: 0.52,
  width: 300pt, items: (
  [64-bit time stamp divided by GCD added to per-CPU ring], (
    [Entropy estimate],
    [Health test in FIPS mode],
  ),
  [When ring full #sym.arrow new events dropped],
  [When entropy is required #sym.arrow events of all rings seed the kernel DRBG], (
    [Addition of all per-CPU entropy estimates],
  ),
), extra: fig(image(figdir + "sched-processing.svg", width: 440pt,
  height: 250pt, fit: "contain"), 352pt, 150pt, 436pt, 250pt))

// ---------------------------------------------------------------- slide 22
#slide(22, title: [Internal ES: eBPF], scale: 0.42, width: 320pt, items: (
  [eBPF programs on the sched_switch and irq_handler_entry tracepoints], (
    [Stock kernel with BTF, libbpf ≥ 1.2 – no kernel patch],
    [Loaded during the privileged initialization of the esdm-server],
  ),
  [Time between successive events of a CPU collected in per-CPU batches], (
    [Handed to a BPF ring buffer when full or after an idle deadline],
    [Wiped when the sources are unloaded],
  ),
  [SP800-90B health tests in the eBPF program in FIPS 140, SP800-90C and NTG.1 mode],
  [Conditioning: per-source XDRBG-256 pool in the esdm-server],
  [Uncredited by default – measurement tools in addon/es_ebpf_testing],
), extra: fig(image(figdir + "ebpf-processing.svg", width: 420pt,
  height: 250pt, fit: "contain"), 382pt, 150pt, 404pt, 250pt))

// ---------------------------------------------------------------- slide 23
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
#slide(23, title: [Internal ES Testing \ Interfaces], scale: 0.5, width: 480pt,
  items: (
  [Kernel module: testing code is compile time option], (
    [Access via DebugFS (esdm_es), not in lockdown mode],
    [Data collection at boot time and runtime:], (
      [Raw time stamp differences for Scheduler / IRQ ES],
      [Performance data for ESDM’s Scheduler / IRQ handler],
    ),
  ),
  [eBPF ES: raw event collector esdm-ebpf-collect],
  [Scheduler ES: Full SP800-90B assessment \ documentation yet pending],
  [IRQ ES: Full SP800-90B assessment available],
  [Raw entropy collection and analysis tools \ provided],
), extra: place(top + left, dx: 539.3pt, dy: 32.9pt, entropy-table))

// ---------------------------------------------------------------- slide 24
#slide(24, title: [ESDM Health and Self Tests], scale: 0.52, items: (
  [Internal ES health tests in FIPS mode], (
    [APT / RCT],
    [Time-Stamp Pattern detection: 1st/2nd/3rd \ discrete derivative of time ≠ 0],
    [Blocking interface: Wait until APT power-up testing complete],
  ),
  [Self tests at startup, every 600 seconds and on request], (
    [Known-answer tests: hash, XDRBG-256 / SHAKE256, DRNG],
    [Self test of every entropy source],
    [No random numbers before the crypto self tests passed],
  ),
  [FIPS mode: integrity test of the ESDM components],
  [Provides SP800-90B compliance of internal ES],
))

// ---------------------------------------------------------------- slide 25
#slide(25, title: [General Testing], scale: 0.56, items: (
  [Automated regression test suite covering the different \ options of ESDM], (
    [Meson test harness, all crypto backends in CI],
  ),
  [Applied testing frameworks], (
    [ASAN, UBSAN, thread sanitizer],
    [Fuzzing of the RPC and EGD interfaces and the OpenSSL providers],
    [Coverage builds],
  ),
  [Kernel module and eBPF ES tested in VMs],
  [Performance tests of DRNG],
  [Interface validation testing],
))

// ---------------------------------------------------------------- slide 26
#slide(26, title: [ESDM - Resources], scale: 0.778, items: (
  [Code / Tests / Documentation: \ #text(fill: link-blue)[https://github.com/smuellerDD/esdm]],
  [Testing conducted with], (
    [FIPS mode],
    [Without FIPS mode],
    [With SELinux enabled],
    [Without SELinux],
    [Production use],
  ),
))
