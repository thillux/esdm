// ESDM presentation for release 1.2.4.
//
// A deck for developers in eight sections and a backup section: one
// message per slide, stated by its title; a few short points or a figure of
// the design document with callouts; reference material - build options,
// tables of commands and measurements - in the backup section at the end.
// Every statement is one of the design document (doc/typst/chapters), which
// each section names. The editor windows show meson_options.txt verbatim
// (meson-excerpts.typ), the terminal windows program output of this release
// (screens.typ).
// Build from doc/typst: typst compile --root . presentations/<this file>

#import "template.typ": *
#import "screens.typ": *
#import "meson-excerpts.typ": *

#show: setup.with(sections: ([Overview], [Interfaces], [DRNG Management],
  [Entropy Sources], [System Events], [Security], [Compliance],
  [Assurance]))
#set document(title: "Entropy Source and DRNG Manager 1.2.4")

// The definitions of the deck precede its first slide: make diff places a
// slide of an older version that uses one of them where it stood.

// A log line of the server without its time and its source location, so
// that the message fits the window: "ESDM (15:17:04) (ESDM fj_003) Debug -
// Entropy Source [../esdm/esdm_es_cpu.c:esdm_cpu_get:282]: obtained ..."
// becomes "(ESDM fj_003) Debug - Entropy Source: obtained ...".
#let short-log(lines) = lines.map(l => l.replace(
  regex("^ESDM \(\d\d:\d\d:\d\d\) "), "").replace(regex(" \[[^\]]*\]:"), ":"))

// Colours of the log lines in the terminal windows
#let log-rules = (
  (regex("^\(ESDM \w+\) Warning - [\w ]+:"), it => text(fill: code.warn, it)),
  (regex("^\(ESDM \w+\) Debug - [\w ]+:"), it => text(fill: code.debug, it)),
  (regex("^\(ESDM \w+\) Verbose - [\w ]+:"),
    it => text(fill: code.verbose, it)),
  (regex("fully seeded.*|ESDM fully operational"),
    it => text(fill: code.ok, it)),
)
#let prompt-rule = (regex("^\$ .*"), it => text(fill: code.prompt, it))
#let c-rules = (
  (regex("\b(static|const|struct|int|char|return)\b"),
    it => text(fill: code.keyword, it)),
  (regex("\"[^\"]*\""), it => text(fill: code.string, it)),
)

// An entropy source with the entropy the default build credits to 256 bits
// of its data.
#let rate-tile(name, rate, fill: surface) = block(width: 100%, height: 92pt,
  fill: fill, radius: 6pt, inset: (x: 11pt, y: 11pt), {
    set par(leading: 0.4em)
    text(size: t-caption, fill: ink, name)
    place(bottom + left, text(size: 30pt, weight: "semibold", fill: ink,
      top-edge: "cap-height", bottom-edge: "baseline", tracking: -0.5pt,
      rate))
  })

// A mark of the class table
#let ok = icon("check", fill: accent-text)
#let no = text(fill: faint, "–")

// The DRNG instances in the JSON form of the status
#let json-excerpt = {
  let start = status-json.position(l => l.contains("\"drngs\""))
  status-json.slice(start, start + 19)
}
// A provider of an external entropy source
#let es-ext-code = (
  "static const struct esdm_es_ext_plugin my_source = {",
  "\t.version = ESDM_ES_EXT_PLUGIN_VERSION,",
  "\t.name = \"my-noise-source\",",
  "\t.get_entropy = my_get_entropy,",
  "};",
  "",
  "int main(int argc, char *argv[])",
  "{",
  "\treturn esdm_es_ext_provider_main(&my_source, argc, argv);",
  "}",
)
// A build option as meson_options.txt states it, with what it means.
#let option-slide(title, excerpt, size: 9pt, body) = slide(title: title,
  grid(columns: (458pt, 1fr), column-gutter: 20pt,
    meson-view(excerpt, size: size),
    {
      set text(size: t-small)
      body
    }))

// =========================================================================
#title-slide(
  title: [Entropy Source and \ DRNG Manager],
  subtitle: [... or /dev/random in User Space],
  version: [ESDM #esdm-version],
  author: grid(columns: (auto, auto), column-gutter: 48pt,
    [Stephan Müller \ \<smueller\@chronox.de\>],
    [Markus Theil \ \<theil.markus\@gmail.com\>]),
)

#slide(title: [Agenda])[
  #set text(size: t-small)
  #let item(n, title, body) = grid(columns: (30pt, 1fr), column-gutter: 12pt,
    align: horizon,
    box(width: 30pt, height: 30pt, radius: 15pt, fill: accent,
      align(center + horizon, text(size: 17pt, weight: "semibold",
        fill: background, top-edge: "cap-height", bottom-edge: "baseline",
        str(n)))),
    [#text(size: t-body, weight: "semibold", title) \ #text(fill: muted, body)])
  #grid(columns: (1fr, 1fr), column-gutter: gap, row-gutter: 27pt,
    item(1)[Overview][Purpose, design goals, architecture],
    item(5)[System Events][Clones, suspend, fork, virtual machines],
    item(2)[Interfaces][Processes, output paths, first steps],
    item(6)[Security][Attacker model, security domains, hardening],
    item(3)[DRNG Management][Seeding, reseeding, state machines],
    item(7)[Compliance][SP 800-90C, FIPS 140-3, AIS 20/31, DRT.1],
    item(4)[Entropy Sources][Twelve sources, their rates and health tests],
    item(8)[Assurance][Testing, interface specification, model checking],
  )
]

// ================================================================ part 1
#section-slide(number: 1, title: [Overview],
  subtitle: [Purpose, design goals, comparison with the alternatives and
    architecture])

#slide(title: [Purpose of the ESDM])[
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: gap,
    stat[12][entropy sources, each with an entropy rate of its own],
    stat[4][output paths: full, plain, prediction resistance, seed],
    stat[5][crypto backends: builtin, OpenSSL, Botan, GnuTLS, leancrypto],
  )
  #v(22pt)
  - A drop-in replacement of `/dev/random`, `/dev/urandom`, `getrandom()` and
    `getentropy()`
  - The LRNG kernel patch series converted into user space: after its
    start-up, the ESDM runs without privileges
]

#slide(title: [Design Goals])[
  - An API- and ABI-compatible replacement of the Linux random number
    interfaces
  - User space: privileges serve the set-up only and are dropped before the
    first client
  - Entropy is conditioned with cryptographic operations only: a hash,
    XDRBG-256, a DRBG
  - Every entropy source is selected, credited and reported individually
  - Configurations for SP 800-90C, FIPS 140-3 and AIS 20/31
]

#slide(title: [Comparison with the Alternatives])[
  #let alt(name, adds, cost) = card(name, height: 250pt)[
    #adds
    #place(bottom + left)[#text(weight: "semibold")[Cost:] #cost]
  ]
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: 14pt,
    alt[The kernel RNG alone][Selectable entropy sources with a rate each, a
      status that names them, compliant configurations, a prediction
      resistance path.][a round trip to another process per request.],
    alt[An in-kernel replacement: the LRNG][No patched kernel for the core.
      Unprivileged after start-up, uses the crypto library of the system,
      updated like any daemon.][the drop-in interfaces need daemons and do
      not reach consumers that bypass them.],
    alt[Kernel RNG plus a Jitter RNG per application][One place where entropy
      is accounted, configured, health-tested and reported; sources an
      application cannot reach.][a dependency on a running service.],
  )
  #more[“Design Rationale and Alternatives”]
]

#slide(title: [Toolkit and Minimal Configurations])[
  #let cfg(name, parts, serves) = card(name, height: 196pt)[
    #parts
    #place(bottom + left)[#text(weight: "semibold")[Serves:] #serves]
  ]
  #grid(columns: (1fr, 1fr, 1fr, 1fr), column-gutter: 12pt,
    cfg[Server with RPC clients][`esdm-server`, `esdm-tool`, an OpenSSL
      provider. No kernel module.][applications through OpenSSL.],
    cfg[Server and `esdm_cdev`][`esdm-server` with the EGD interface
      alone and one kernel module.][readers of `/dev/esdm_random`, e.g. a
      hypervisor.],
    cfg[Linux interfaces][Server, CUSE daemons, `esdm-proc`, the
      `getrandom` library.][unmodified software.],
    cfg[Library only][`libesdm` linked into one program, no
      server.][that program.],
  )
  #v(12pt)
  #set text(size: t-small)
  Only the generator is mandatory. Every frontend, entropy source, kernel
  module, library and tool can be left out; an interface exists only where
  its component is built, installed and started.
  #more[“Interfaces of a Deployment”]
]

#slide(title: [Architecture])[
  #pic("big-picture.svg")
]

#slide(title: [Data Flow from Noise to Output])[
  #grid(columns: (1fr, 1fr), column-gutter: gap, row-gutter: 26pt,
    step(1)[Collect][Internal sources time interrupts and task wakeups, in a
      kernel module or in eBPF programs. External sources deliver on
      request.],
    step(2)[Credit][Each source fills a slot of the seed buffer with data and
      the entropy the configuration credits it. Data without credit becomes
      additional input.],
    step(3)[Seed][A DRNG instance is fully seeded with 256 bits of entropy,
      384 with the SP 800-90C oversampling. Until then, the blocking
      interfaces wait.],
    step(4)[Serve][One DRNG instance per CPU serves the requests and is
      reseeded ahead of them. The prediction resistance instance reseeds for
      every block.],
  )
]

// ================================================================ part 2
#section-slide(number: 2, title: [Interfaces],
  subtitle: [Processes, output paths and first steps])

#slide(title: [Processes])[
  #pic("processes.svg", height: 218pt)
  #v(10pt)
  #set text(size: t-small)
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: 20pt,
    [- `esdm-server` wraps `libesdm`: entropy source manager, DRNG manager,
       reseed worker],
    [- Clients use two RPC sockets – the privileged one for root only – or
       the EGD sockets],
    [- The frontends are clients as well: CUSE daemons, `esdm-proc`,
       `esdm-kernel-seeder`],
  )
]

#slide(title: [Server Builds with One Interface])[
  #cols(widths: (1fr, 1fr), valign: top,
    card([Without EGD: `-Desdm-server-egd=disabled`], height: 196pt)[
      - The server contains no EGD code and refuses `--egd_socket`
      - No EGD client library, socket units or EGD-based OpenSSL modules
      - Everything else as in the default build
    ],
    card([Without RPC: `-Desdm-server-rpc=disabled`], height: 196pt)[
      - The server opens no RPC socket and always serves the EGD socket
      - `esdm-tool` works over EGD: status, random numbers, seeding state,
        pool and reseed commands
      - What needs RPC is not built: CUSE daemons, `getrandom` library,
        kernel seeder
    ],
  )
  #v(12pt)
  #set text(size: t-small)
  A disabled interface is not part of the build: no code in the server, no
  client library, no units, no tests. The default build has both.
]

#slide(title: [Output Paths])[
  #cols(widths: (1.45fr, 1fr), valign: horizon,
    pic("paths.svg"),
    [
      #set text(size: 18pt)
      - *Full* and *plain* share the node DRNGs; they differ before the ESDM
        is operational
      - *Prediction resistance*: a block holds at most the entropy of its
        reseed, and at most 256 bits
      - *Seed*: conditioned data of the entropy sources, with the entropy it
        carries
    ])
]

#slide(title: [Drop-in Interfaces])[
  - `/dev/random`, `/dev/urandom`: CUSE daemons, bind-mounted over the
    devices of the kernel
  - `getrandom()`, `getentropy()`: `libesdm-getrandom.so`, preloaded or
    linked
  - `/proc/sys/kernel/random`: the FUSE file system `esdm-proc`
  #v(6pt)
  #note[While the server cannot be reached, the devices and `getrandom()`
    serve the kernel RNG. A statically linked program, or one that invokes
    the system call directly, never reaches the ESDM.]
]

#slide(title: [Interfaces without Fallback])[
  #grid(columns: (1fr, 1fr), column-gutter: 14pt, row-gutter: 14pt,
    card([RPC client library], height: 112pt)[The stable API: all four
      paths, the status, the configuration.],
    card([EGD sockets], height: 112pt)[One byte of command, one of length:
      for sandboxes, OpenSSL and libgcrypt. Enabled at runtime.],
    card([OpenSSL 3 providers], height: 112pt)[RAND and seed source, over
      the RPC or the EGD interface.],
    card([Kernel module `esdm_cdev`], height: 112pt)[`/dev/esdm_random`,
      `/dev/esdm_urandom`, `/dev/esdm_pr`; the devices of the kernel stay
      untouched.],
  )
  #more[“ESDM External Interfaces”; the commands of the EGD interface are in
    the backup section]
]

#slide(title: [Prediction Resistance])[
  - A DRNG instance of its own, reseeded from the entropy sources for every
    block
  - A block holds at most 256 bits, and at most the entropy its reseed
    injected
  - The caller may receive less than requested, or nothing
  - One request at a time: a concurrent one receives `-EAGAIN`
  - Reached with `O_SYNC`, `GRND_RANDOM`, `/dev/esdm_pr`, the RPC calls
    `_pr` and the second EGD socket
]

#slide(title: [Getting Started])[
  #cols(widths: (1fr, 1.05fr),
    stack(spacing: 20pt,
      step(1)[Build and install][`meson setup build`, `meson compile` and
        `meson install` – or `nix build .#esdm`],
      step(2)[Start][`systemctl enable --now esdm-server` and
        `esdm-linux-compat.target` for the Linux interfaces],
      step(3)[Check][`esdm-tool --status` reports “Fully seeded: true”;
        `/dev/random` and `getrandom()` work as before],
    ),
    window(status-left.slice(0, 19), size: 10pt, title: "esdm-tool --status",
      rules: ((regex("^Fully seeded: true"),
        it => text(fill: code.ok, weight: "bold", it)),)),
  )
]

#slide(title: [Status Report])[
  #cols(widths: (1fr, 1.05fr),
    [
      #set text(size: 18pt)
      - One status as JSON; the text report is rendered from it
      - Per entropy source: the entropy available and the rate credited
      - Per DRNG instance: seeding state, reseed counters, seed generation
      - `esdm-tool --status`, `--status-json`, `--drng-status`; also over
        the RPC and EGD interfaces and `/proc/esdm/status`
    ],
    window(json-excerpt, size: 10pt, title: "esdm-tool --status-json",
      rules: ((regex("\"[a-z_]+\":"), it => text(fill: code.keyword, it)),)),
  )
]

// ================================================================ part 3
#section-slide(number: 3, title: [DRNG Management],
  subtitle: [Seeding, reseeding and state machines])

#slide(title: [Seeding])[
  #cols(widths: (1fr, 1.3fr), valign: horizon,
    [
      #set text(size: 18pt)
      - Every source is asked for 256 bits and credits at most the entropy
        it holds
      - One thread per source: a seeding lasts as long as its slowest
        source
      - The credits are added up, the DRNG is credited with at most 256
        bits
      - Data without credit is additional input, not seed
    ],
    pic("es-manager.svg"),
  )
]

#slide(title: [Start-up Sequence])[
  #set text(size: 18pt)
  - Every entropy source is read on a thread of its own (`fj_002`, …);
    a source that is not available delivers nothing
  #v(4pt)
  #window(short-log(seed-log-top), size: 9pt, rules: log-rules,
    title: "esdm-server -f -vvvvv (time and source location omitted)")
]

#slide(title: [Fully Seeded State])[
  #cols(widths: (1fr, 1.15fr), valign: horizon,
    [
      #set text(size: 18pt)
      - Without enough entropy, a reseed carries the current time only and
        does not count as a full reseed
      - The default limit of 2#super[30] generate operations without a full
        reseed is chosen for availability
      - The options `sp80090c`, `fips140` and `ais2031_drg4` stop an
        instance after 2#super[17] bits without a full reseed
    ],
    pic("drng-states.svg"),
  )
]

#slide(title: [Reseed Worker])[
  #set text(size: 18pt)
  - It reseeds every instance whose reseed is due and brings up those not
    yet fully seeded
  - A reseed collects its entropy without holding the DRNG, which keeps
    serving
  - Seed times are spread by a random offset of up to a tenth of the
    interval
  #v(2pt)
  #window(short-log(seed-log-bottom), size: 9pt, rules: log-rules,
    title: "esdm-server -f -vvvvv (time and source location omitted)")
]

#slide(title: [DRNG Instances per CPU])[
  #pic("numa-drng.svg", height: 96pt)
  #v(10pt)
  #set text(size: 18pt)
  - One instance per CPU, up to the number of worker threads – 64 by
    default; #box[`esdm-server --small_memory`] uses one
  - Every instance is seeded from entropy collected for it: no entropy is
    used twice
  - A request starts with its own instance, skips busy and unseeded ones
    and falls back to the initial instance
]

#slide(title: [State Machines])[
  #cols(widths: (1fr, 1.1fr), valign: horizon,
    [
      #set text(size: 18pt)
      The document specifies five of them:
      - the ESDM as a whole (right)
      - a DRNG instance
      - the verdict of the self tests
      - the delivery of an entropy source
      - the health tests of the kernel module
      #v(4pt)
      #text(fill: muted, size: t-small)[The states are those of the code;
        the model checking covers their concurrent execution.]
    ],
    pic("fsm-esdm.svg"),
  )
]

#slide(title: [States of a DRNG Instance])[
  #pic("fsm-drng.svg", height: 208pt)
  #v(8pt)
  #set text(size: t-small)
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: 20pt,
    [- Stored: the flags `fully_seeded`, `initiated`, `force_reseed`,
       counters, the time of the last seeding],
    [- Budget spent: a node instance keeps its flag, but serves nothing
       until the worker has reseeded it],
    [- The prediction resistance instance has states of its own: not
       initiated, fresh, spent],
  )
]

#slide(title: [Self Tests])[
  #pic("fsm-selftest.svg", height: 112pt)
  #v(10pt)
  #set text(size: 18pt)
  - Known-answer tests of the hash, the XDRBG-256 and the DRNG, each with
    negative tests
  - At start-up, every 600 seconds and on request: `esdm-tool --selftest`
  - Every entropy source tests itself: a failing source is credited with
    nothing until a later test passes
]

#slide(title: [Unavailable Entropy Sources])[
  #cols(widths: (1fr, 1.6fr), gutter: 20pt, valign: horizon,
    [
      #set text(size: t-small)
      - `/dev/hwrng`, TPM 2.0: a read has 2 seconds; a failed source is
        probed every 10 seconds at most
      - External provider: credited only after its self test passed
      - Jitter RNG, CPU: read at every seeding, so they recover at once
      - A source without credit still delivers additional input
    ],
    pic("fsm-es-delivery.svg"),
  )
]

// ================================================================ part 4
#section-slide(number: 4, title: [Entropy Sources],
  subtitle: [Twelve sources, their entropy rates and health tests])

#slide(title: [Entropy Sources and Their Rates])[
  #grid(columns: (1fr,) * 6, column-gutter: 9pt, row-gutter: 9pt,
    rate-tile(fill: source)[Interrupts \ kernel module][256],
    rate-tile(fill: source)[Scheduler \ kernel module][0],
    rate-tile(fill: source-soft)[Interrupts \ eBPF][0],
    rate-tile(fill: source-soft)[Scheduler \ eBPF][0],
    rate-tile[Jitter RNG][256],
    rate-tile[Kernel Jitter RNG][256],
    rate-tile[CPU][8],
    rate-tile[Kernel RNG][128],
    rate-tile[`/dev/hwrng`][0],
    rate-tile[TPM 2.0][0],
    rate-tile[External provider][#text(size: 19pt, tracking: 0pt)[declared]],
    rate-tile(fill: accent-soft)[Auxiliary pool][#text(size: 19pt,
      tracking: 0pt)[by root]],
  )
  #v(12pt)
  #set text(size: t-small)
  Bits of entropy the default build credits to 256 bits of data. Of the four
  timing sources (warm tones), at most one is credited; the kernel Jitter RNG
  is not built by default.
  #more[“Entropy Sources: Rates, Health Tests and Independence”]
]

#slide(title: [Independence of the Entropy Sources])[
  #grid(columns: (1fr, 1fr), column-gutter: 14pt,
    card([Enforced], height: 196pt)[
      - Timing sources: the build refuses to credit two of them; a rate set
        at runtime sets the others to zero
      - Kernel RNG: zero while the scheduler source of the kernel module is
        credited, at most 4 bits beside its interrupt source
    ],
    card([Left to the integrator: credit one of each pair], height: 196pt)[
      - CPU and kernel RNG
      - Jitter RNG and kernel Jitter RNG
      - `/dev/hwrng` and TPM 2.0, when the same TPM backs both
      - eBPF scheduler source and kernel RNG
    ],
  )
  #v(10pt)
  #note[The default build is a pragmatic configuration for a general-purpose
    system, not an assessed one.]
]

#slide(title: [Interrupt and Scheduler Entropy Sources])[
  #set text(size: 18pt)
  - Interrupts and task wakeups: two entropy sources of the same
    architecture, in the module `esdm_es` with a small kernel patch
  - Per event: a timestamp, divided by its GCD and health-tested, into a
    per-CPU ring
  - On request: the timestamps of all rings seed the DRBG of the module,
    which generates the block
  #v(2pt)
  #pic("irq-processing.svg", height: 150pt)
]

#slide(title: [eBPF Entropy Sources])[
  #set text(size: 18pt)
  - Attached to the tracepoints `sched_switch` and `irq_handler_entry`;
    needs BTF and libbpf 1.2 or later
  - Time deltas in per-CPU batches of 64, handed over when full or after
    250 ms; conditioned in an XDRBG-256 pool per source
  - Credited with no entropy until the rate has been measured on the target
  #v(2pt)
  #pic("ebpf-processing.svg", height: 150pt)
]

#slide(title: [SP 800-90B Health Tests])[
  #cols(widths: (1fr, 1.2fr), valign: horizon,
    [
      #set text(size: 18pt)
      - The stuck test runs on every timestamp, in every mode
      - Repetition count, adaptive proportion and start-up test: only with
        `fips=1`
      - Start-up: two windows of 512 timestamps before entropy is delivered
      - A failure resets the rings and starts the start-up test again
      #v(2pt)
      #note[The default build credits the interrupt source without these
        three tests.]
    ],
    pic("fsm-health.svg"),
  )
]

#slide(title: [Entropy Sources Read on Request])[
  #grid(columns: (1fr, 1fr), column-gutter: 14pt, row-gutter: 14pt,
    card([Jitter RNG], height: 128pt)[The SP 800-90B source of the
      jitterentropy library. Several collectors, each with a lock of its
      own. From 3.7.0: an NTG.1 mode.],
    card([CPU], height: 128pt)[RDSEED, DARN, the seed CSR of RISC-V, PRNO,
      RNDRRS. Credited with 8 of 256 bits: the claim of the vendor cannot be
      verified.],
    card([Kernel RNG], height: 128pt)[`getrandom()` of the kernel. 128 bits
      by convention of the default build, 0 with the oversampling.],
    card([TPM 2.0 and `/dev/hwrng`], height: 128pt)[No credit by default.
      Read on a thread of its own with a deadline of 2 seconds.],
  )
]

#slide(title: [Auxiliary Pool])[
  #cols(widths: (1.25fr, 1fr), valign: horizon,
    [
      #set text(size: 18pt)
      - Collects data delivered at times the ESDM cannot control: an rngd,
        writes to `/dev/random`
      - Only root credits entropy; data of other users is mixed in without
        credit
      - Insert: seed data of the next reseed
      - Extract: reseed, then generate – the output never reveals the state
        of the pool
      - The eBPF sources condition in pools of the same kind
    ],
    pic("deck-xdrbg-pool.svg"),
  )
]

#slide(title: [External Entropy Sources])[
  #set text(size: 18pt)
  #cols(widths: (1fr, 1.25fr),
    [
      - A provider serves the noise source on a Unix domain socket
      - No foreign code in the address space of the server
      - Accepted as root or as the configured user only; its credit is
        capped
      - Shipped: `esdm-es-pkcs11`, `esdm-es-pcsc`
    ],
    [
      #window(es-ext-code, size: 9.5pt, rules: c-rules,
        title: "a provider written against libesdm_es_ext")
      #v(6pt)
      #text(size: t-small, fill: muted)[Callbacks for the entropy, the self
        test, the status and the entropy rate; the library speaks the
        protocol.]
    ])
]

#slide(title: [Crypto Backends])[
  #let be(name, drng) = card(name, height: 150pt, drng)
  #grid(columns: (1fr,) * 5, column-gutter: 9pt,
    be[builtin (default)][Hash DRBG with SHA-512, or ChaCha20 DRNG],
    be[OpenSSL][Hash DRBG, CTR DRBG or HMAC DRBG],
    be[Botan][HMAC DRBG, or ChaCha20 RNG with fast key erasure],
    be[GnuTLS][CTR DRBG with a derivation function],
    be[leancrypto][XDRBG-256 with SHAKE256],
  )
  #v(14pt)
  - The backend provides the DRNG, the conditioning hash and SHAKE256
  - Entropy accounting, thresholds and locking are the same code for every
    backend: `struct esdm_drng_cb`
]

// ================================================================ part 5
#section-slide(number: 5, title: [System Events],
  subtitle: [Clones and snapshots, suspend and resume, fork, entropy in
    virtual machines])

#slide(title: [System Events])[
  #pic("deck-system-events.svg", height: 222pt)
  #v(8pt)
  #set text(size: 18pt)
  A clone or a restored snapshot duplicates every DRNG state: two machines
  deliver the same random numbers until their states diverge.
  #more[“System Events: Clones, Suspend, Resume and Shutdown”]
]

#slide(title: [Reporting of System Events])[
  - Built without its entropy sources, `esdm_es` needs no kernel patch and
    only reports the events
  - Without the module, `esdm-server-signal-helper` reports suspend and
    resume; nothing reports a VM generation change
  - An undetected clone diverges with its next reseed only: the procedure
    that resumes the guest has to force one
  - The reaction is not instantaneous: a request served in the window still
    draws on the duplicated state
]

#slide(title: [Use of the Kernel Module `esdm_es`])[
  #cols(widths: (1fr, 1fr), valign: top,
    card([Its entropy sources], height: 210pt)[
      - Where the other sources do not suffice, or a second assessed
        non-physical source is required next to the Jitter RNG (NTG.1)
      - Where entropy is wanted before user space starts
      - Price: a patched kernel. On a stock kernel the eBPF sources
        observe the same events
    ],
    card([The system events], height: 210pt)[
      - On a virtual machine that may be cloned or restored: nothing else
        tells the server that its state exists twice
      - Suspend and resume alone: the units of the signal helper suffice
      - Built without its entropy sources, the module needs no kernel
        patch
    ],
  )
  #more[“When the Kernel Module esdm_es Is Needed”]
]

#slide(title: [Fork])[
  #stack(spacing: 15pt,
    step(1)[Fork][A process that embeds `libesdm.so` would hand a copy of
      every DRNG state to its child, which would repeat the output of the
      parent.],
    step(2)[Fork handler][It marks the child, takes every DRNG instance back
      to not fully seeded and clears the copied states of the built-in
      DRNGs.],
    step(3)[In the child][Every call for random data or for a seed fails
      with `-EOPNOTSUPP`. Initialize the ESDM after the fork, or use the RPC
      client library.],
  )
  #v(10pt)
  #note(sign: "info")[A `clone()` that bypasses the fork handlers is not
    detected. The ESDM server initializes the ESDM after its own forks.]
]

#slide(title: [Entropy in Virtual Machines])[
  - Timing sources and the Jitter RNG draw their entropy from the low bits
    of a high-resolution timestamp: check that the guest reads the cycle
    counter without a trap
  - Measure a timing source in the guest; the rate of the host or of
    another machine does not carry over
  - An idle guest has few events: keep a source credited that delivers on
    request
  - Boot with `fips=1` when a source of the kernel module is credited, or a
    degraded timer goes unnoticed
  #more[“Entropy in Virtual Machines”, following a study of the BSI]
]

#slide(title: [Operation of Guests])[
  #grid(columns: (1fr, 1fr), column-gutter: 14pt, row-gutter: 14pt,
    card([Entropy from the host], height: 122pt)[Feed virtio-rng from the
      ESDM of the host and credit `/dev/hwrng` in the guest – when host and
      guest have the same operator.],
    card([Services at boot], height: 122pt)[Order the services that need
      keys after `esdm-wait-until-fully-seeded.service`.],
    card([Snapshots, clones, templates], height: 122pt)[Take the image of a
      guest that is shut down. Otherwise load `esdm_es`, or force a reseed
      when the guest resumes.],
    card([Backups and migration], height: 122pt)[Protect the image of a
      running guest like the keys it will generate; after a migration, only
      one copy continues.],
  )
]

// ================================================================ part 6
#section-slide(number: 6, title: [Security],
  subtitle: [The attacker model, the security domains and the hardening of
    the server])

#slide(title: [Protected Assets])[
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: 14pt,
    card([State], height: 150pt)[The states of the DRNG instances, of the
      pools and of the entropy sources, the seed buffers: confidentiality
      and integrity.],
    card([Output], height: 150pt)[The random numbers delivered to a
      consumer: unpredictable to everybody but that consumer.],
    card([Availability], height: 150pt)[Random numbers for the consumers
      that wait for them, and no output before the ESDM is operational.],
  )
  #v(14pt)
  #set text(size: 18pt)
  Trusted: the kernel, the hardware, the hypervisor, root, the crypto
  backend, the systemd configuration and an accepted provider of an external
  entropy source.
  #more[“Attacker Model and Non-Goals”]
]

#slide(title: [Attacker Model])[
  #set text(size: t-small)
  #set par(leading: 0.42em)
  #let row(who, what) = (text(weight: "semibold", who), what)
  #grid(columns: (0.72fr, 1fr),
    inset: (y: 7.5pt, right: 18pt), stroke: (bottom: 0.5pt + rule),
    ..row[Unprivileged local user][Privileged operations for user ID 0 only;
      no internal state on any interface],
    ..row[Attacker who learned the state of a DRNG][Backtracking resistance;
      reseeds after 2#super[20] requests or 600 seconds; secrets wiped],
    ..row[Attacker who influences entropy sources][Health tests on the raw
      data; conservative rates; all sources conditioned together],
    ..row[Malicious client][Bounded, fuzzed parsers; a malformed request
      closes its connection],
    ..row[Stalling device][A deadline of 2 seconds per read; the source is
      skipped until a probe succeeds],
    ..row[Local user forcing the fallback][None in the drop-in interfaces;
      the other interfaces report an error],
  )
]

#slide(title: [Residual Risks and Non-Goals])[
  - Fallback: a local user who keeps enough connections busy moves the
    consumers of the drop-in interfaces to the kernel RNG
  - Entropy consumption: the seed call and the prediction resistance path
    have no quota per user
  - The default user `nobody` is shared with other software: run the daemons
    as a user that nothing else uses
  - Non-goals: attackers with the privileges of root, the kernel or the
    hypervisor; physical attacks; network attackers – all sockets are local
]

#slide(title: [Security Domains])[
  #pic("deck-security-domains.svg", height: 252pt)
  #v(8pt)
  #set text(size: t-small)
  Within D-SERVER there is one address space: a memory error in a parser
  reaches the DRNG states. The defence against it is the hardening, not a
  boundary.
]

#slide(title: [Privileges of the Server])[
  #grid(columns: (1fr, 1fr), column-gutter: gap, row-gutter: 20pt,
    step(1)[Start as root][Optionally fork into a PID namespace; a root
      supervisor stays outside, forwards signals, and the daemon ends
      with it.],
    step(4)[Initialize the ESDM][The entropy sources that need privileges –
      eBPF, `/dev/esdm_es` – and the status memory.],
    step(2)[Lock the memory][With `--memlock`: all memory locked, the
      process not dumpable.],
    step(5)[Bind the sockets][The privileged one with mode 0600, the
      unprivileged and EGD ones with 0666.],
    step(3)[Enter namespaces][Mount, cgroup and network namespaces of its
      own, before any thread exists.],
    step(6)[Drop the privileges for good][`setgroups`, `setgid`, `setuid`
      – then the RPC and EGD workers start to serve.],
  )
]

#slide(title: [Hardening])[
  #pic("hardening-layers.svg", height: 244pt)
  #v(10pt)
  #set text(size: 18pt)
  The input is bounded as well: an RPC message has at most 64 KiB, a worker
  serves at most 1024 connections.
]

// ================================================================ part 7
#section-slide(number: 7, title: [Compliance],
  subtitle: [Configurations for SP 800-90C, FIPS 140-3 and AIS 20/31, and
    the claims not made])

#slide(title: [Seeding Strategies])[
  #let strategy(n, name, body) = card(none, height: 236pt)[
    #text(size: 40pt, weight: "semibold", fill: accent-text, tracking: -1pt,
      top-edge: "cap-height", bottom-edge: "baseline", n)
    #v(14pt, weak: true)
    #text(weight: "semibold", name)
    #v(9pt, weak: true)
    #body
  ]
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: 14pt,
    strategy[256 bits][Default][The security strength, collected from all
      entropy sources together.],
    strategy[384 bits][Oversampling][`sp80090c`, `fips140`, `ais2031_drg3`
      or `ais2031_drg4`: 128 bits more for the initial seed, 64 bits more
      for a conditioning component.],
    strategy[2 × 240 bits][NTG.1][`ais2031_ntg1`: two entropy sources
      deliver 240 bits each. Or the Jitter RNG in its own NTG.1 mode alone:
      `es_jent_ntg1`.],
  )
  #more[the build options are shown verbatim in the backup section]
]

#slide(title: [Build Options and Classes])[
  #cols(widths: (1.5fr, 1fr), valign: horizon,
    pic("compliance-options.svg"),
    [
      #set text(size: 18pt)
      - The status line “Standards compliance” lists what the build
        provides
      - A flag reports the build and the mode, not the class: the entropy
        rates are part of the proof
      - `ais2031_drg3` and `ais2031_drg4` exclude each other
    ])
]

#slide(title: [NTG.1 Output])[
  #{
    set text(size: 18pt, top-edge: "cap-height", bottom-edge: "baseline")
    show table.cell.where(y: 0): set text(weight: "semibold",
      fill: accent-text)
    table(columns: (1.8fr, 1fr, 1fr, 1fr, 1.4fr, 1.6fr),
      align: (x, y) => (if x == 0 { left } else { center }) + horizon,
      inset: (x: 10pt, y: 9.5pt),
      table.header([Path], [DRG.3], [DRG.4], [NTG.1], [SP 800-90C],
        [Seeds a DRNG]),
      [Full], ok, ok, no, ok, no,
      [Plain], ok, ok, no, ok, no,
      [Prediction resistance], ok, ok, ok, ok, ok,
      [Seed], no, no, no, no, ok,
    )
  }
  #v(12pt)
  #set text(size: t-small)
  - Each class with its build option; DRG.4 only with physical entropy
    sources credited
  - Plain: only for output the ESDM served – before it is operational, the
    drop-in interfaces serve the kernel RNG
  #more[“Interfaces and Classes”; the path of every interface is in the
    backup section]
]

#slide(title: [SP 800-90C Constructions])[
  #cols(widths: (1.25fr, 1fr), valign: horizon,
    [
      #set text(size: 18pt)
      - `sp80090c`: 384 bits for the initial seed, 64 bits more for each
        conditioning component
      - No request after 2#super[17] output bits without a full reseed
      - The kernel RNG is credited with nothing: it does not comply with
        SP 800-90B
      - `fips140` adds the integrity test and the detection of the FIPS
        mode
    ],
    stack(spacing: 14pt,
      card([Full and plain paths], height: 120pt)[Node DRNGs and initial
        DRNG, reseeded with 256 bits: RBG2(P) or RBG2(NP).],
      card([Prediction resistance path], height: 120pt)[320 bits before at
        most 256 bits of output: RBG3(RS) with physical entropy sources
        only, else RBG2(NP).],
    ),
  )
]

#slide(title: [AIS 20/31 Classes])[
  - All DRNGs of the ESDM are DRG.3; `ais2031_drg3` adds the oversampling of
    the initial seed
  - `ais2031_drg4`: no request after 2#super[17] bits without a successful
    reseed, a reseed attempted after three quarters of that; DRG.4 is
    claimed with physical sources credited only
  - NTG.1: `ais2031_ntg1` with two sources of different principles, or
    `es_jent_ntg1` alone
  - An appendix of the document maps every requirement of NTG.1, DRG.3,
    DRG.4 and DRT.1 to its implementation
]

#slide(title: [DRT.1])[
  #pic("deck-drt1.svg", height: 196pt)
  #v(8pt)
  #set text(size: 18pt)
  - `/dev/esdm_pr` serves the prediction resistance path only and never the
    kernel RNG
  - In the guest, only `/dev/hwrng` is credited:
    `es_hwrand_entropy_rate=256`
  - No SP 800-90C or FIPS 140-3 claim of the host carries into the guest
]

#slide(title: [Claims Not Made])[
  - Output of the kernel RNG, which the drop-in interfaces serve while the
    server cannot be reached
  - Anything for the default build: its entropy rates are a pragmatic choice
  - DRG.4 with non-physical sources credited, although the status lists
    DRG.4
  - Independence of entropy sources beyond the rules it enforces
  - Distinct output of cloned virtual machines before their first reseed,
    without the kernel module or the VM generation device
  #more[“Limits” of chapter “Compliant Configurations”]
]

// ================================================================ part 8
#section-slide(number: 8, title: [Assurance],
  subtitle: [Testing, the interface specification and the formal
    verification of the concurrent parts])

#slide(title: [Verification Methods])[
  #set text(size: 18pt)
  #set par(leading: 0.42em)
  #let row(what, how) = (text(weight: "semibold", what), how)
  #grid(columns: (0.9fr, 1fr),
    inset: (y: 9.5pt, right: 18pt), stroke: (bottom: 0.5pt + rule),
    ..row[Threads, locks, state machines][Model checking with TLA+; thread
      sanitizer],
    ..row[Parsers and memory safety][Fuzzing, sanitizers, static analysis],
    ..row[Cryptographic primitives][Known-answer tests; self tests at
      start-up and every 600 seconds],
    ..row[Entropy sources][SP 800-90B assessment of the raw data; health
      tests],
    ..row[Kernel modules, integration with the system][Virtual machine
      tests; builds against every supported kernel],
  )
  #more[“Scope” of chapter “Formal Verification”]
]

#slide(title: [Test Execution])[
  #pic("testing.svg")
]

#slide(title: [Test Coverage])[
  #cols(widths: (1fr, 1.75fr), gutter: 20pt,
    [
      #set text(size: t-small)
      - `meson test`: one suite per directory of tests
      - libFuzzer harnesses of the RPC and EGD interfaces, the library API
        and the OpenSSL providers
      - Address, undefined behaviour and thread sanitizers; CodeQL
      - Virtual machines for the kernel modules, eBPF and EGD with GnuPG
        and OpenSSH
    ],
    window(meson-test-output.slice(0, 21), size: 9pt, rules: (
      prompt-rule,
      (regex("\bOK\b"), it => text(fill: code.ok, weight: "bold", it)),
      (regex("\bSKIP\b"), it => text(fill: code.skip, weight: "bold", it)),
    ), title: "meson test"),
  )
]

#slide(title: [Interface Specification])[
  #let group(name, ids) = card(name, height: 104pt, {
    set par(leading: 0.6em)
    ids.map(i => box(raw(i))).join(h(0.8em))
  })
  #grid(columns: (1fr, 1fr), column-gutter: 14pt, row-gutter: 12pt,
    group([Socket protocols], ("IF-RPC-U", "IF-RPC-P", "IF-EGD",
      "IF-EGD-PR", "IF-ESEXT")),
    group([Device and virtual files, shared memory], ("IF-CUSE-RANDOM",
      "IF-CUSE-URANDOM", "IF-PROC", "IF-KMOD-ES", "IF-KMOD-CDEV",
      "IF-SHM")),
    group([Library APIs, system call wrapper], ("IF-GETRANDOM",
      "IF-LIB-ESDM", "IF-LIB-RPCC",
      "IF-LIB-AUX", "IF-LIB-EGDC", "IF-LIB-ESEXT", "IF-OSSL")),
    group([Command lines, signals, environment], ("IF-CLI", "IF-SIG",
      "IF-ENV")),
  )
  #v(12pt)
  #set text(size: t-small)
  For each interface: purpose, use, parameters with types and ranges, effect
  and errors. `IF-RPC-P.4` is the fourth call of the privileged RPC service;
  the numbers are stable, later versions only append.
]

#slide(title: [Wire Format of an RPC Call])[
  - Two services on `SOCK_SEQPACKET` sockets: `UnprivAccess` for every local
    user, `PrivAccess` for user ID 0
  - A header of unsigned 32-bit fields in little-endian order:
    `method_index`, `message_length`, `request_id` – and `status_code` in
    the response
  - The payload is a protobuf message; every response carries `ret`: 0 or a
    count, or a negative `errno` value
  - A datagram has at most 65,536 bytes, its header included
  #more[chapter “Interface Specification”, “RPC Interfaces”]
]

#slide(title: [Model Checking])[
  #pic("deck-model-checking.svg", height: 230pt)
  #v(8pt)
  #set text(size: 18pt)
  The tests run some of the interleavings of the threads. The model checker
  runs all of them within its bounds and returns a trace for every property
  that does not hold.
]

#slide(title: [TLA+ Models])[
  #grid(columns: (1fr, 1.1fr), column-gutter: 14pt,
    card([What is modelled], height: 262pt, size: 18pt)[
      - Seeding and output of the DRNG instances
      - The self test gate, the auxiliary pool
      - The status in shared memory
      - CUSE frontends, EGD server, RPC server and client
      - The supervisor of the server
      - The kernel modules `esdm_es` and `esdm_cdev`
    ],
    card([Why TLA+ and a model checker], height: 262pt, size: 18pt)[
      - The defects of these parts are interleavings: a check and an action
        that another thread separates, a wakeup before its waiter
      - A violation comes as a trace of steps named after the C functions
      - PlusCal reads like the C code it models: developers can read and
        maintain it
    ],
  )
  #more[chapter “Formal Verification”]
]

#slide(title: [Validation and Limits of the Models])[
  #grid(columns: (1fr, 1fr), column-gutter: 14pt,
    card([Validation], height: 262pt, size: 18pt)[
      - Correspondence: every step is named after the C function it stems
        from
      - Sensitivity: every property is shown to be able to fail
      - Non-vacuity: the states a property refers to are shown to be
        reachable
      - Every violation was traced in the C code before it was reported
    ],
    card([Limits], height: 262pt, size: 18pt)[
      - Models, not code: written by hand, no refinement proof connects the
        two
      - Bounded instances: a few threads, DRNG instances and clients
      - Ideal primitives; the entropy a source credits is taken as present
      - Time is abstracted to events: no statement on latency
    ],
  )
]

#slide(title: [Further Reading])[
  #cols(widths: (1fr, 150pt), valign: horizon,
    [
      - *Design and assurance*: the design and the attacker model, the
        entropy assessments, the compliant configurations, the hardening,
        the formal verification
      - *Manual*: building, the build options, usage, the tools, the
        integrations, development, testing
      - Built from the repository: `nix build .#esdm-doc`
      #v(4pt)
      #link("https://github.com/smuellerDD/esdm")[https://github.com/smuellerDD/esdm]
    ],
    stack(spacing: 8pt,
      image(figdir + "qr-repo.svg", width: 150pt),
      align(center, text(size: t-caption, fill: muted)[Source code and
        documentation])),
  )
]

// ================================================================ backup
#section-slide(title: [Backup],
  subtitle: [Reference material: the path of every interface, the tables of
    commands and results, and the build options as meson_options.txt
    states them])

#slide(title: [Backup: Output Path of Each Interface])[
  #ref-table(columns: (1.7fr, 1fr, 1.1fr), size: 12pt,
    inset: (x: 7pt, y: 4.6pt),
    table.header([Interface], [Path], [ESDM server unreachable]),
    [CUSE `/dev/random`; `getrandom()` with flags 0, `getentropy()`], [Full],
      [the kernel RNG],
    [CUSE `/dev/urandom`; `getrandom()` with `GRND_INSECURE`], [Plain],
      [the kernel RNG, also before the ESDM is operational],
    [CUSE devices with `O_SYNC`; `getrandom()` with `GRND_RANDOM`],
      [Prediction resistance], [the kernel RNG],
    [`getrandom()` with `GRND_SEED`; `esdm_rpcc_get_seed`], [Seed], [fails],
    [`/dev/esdm_random` · `/dev/esdm_urandom`], [Full · plain],
      [waits · fails],
    [`esdm_cdev` devices with `O_SYNC`, `/dev/esdm_pr`],
      [Prediction resistance], [waits; with `O_NONBLOCK`: `EAGAIN`],
    [`esdm_rpcc_get_random_bytes_full` · `esdm_rpcc_get_random_bytes` ·
      `esdm_rpcc_get_random_bytes_pr`], [Full · plain · prediction
      resistance], [fails],
    [EGD 0x01, 0x02 · 0xe2 · 0xe0, 0xe1 and the second socket],
      [Full · plain · prediction resistance], [fails],
    [OpenSSL providers], [Full; prediction resistance with the `-pr`
      providers], [OpenSSL error],
  )
]

#slide(title: [Backup: Commands of the EGD Interface])[
  #cols(widths: (1fr, 1.25fr),
    [
      #set text(size: t-small)
      - The protocol of the Entropy Gathering Daemon on a Unix domain
        socket, enabled at runtime
      - It cannot ask for prediction resistance per request: a second socket
        serves the prediction resistance DRNG
      - Commands of the ESDM for what EGD cannot express
      - Clients: `libesdm_egd_client`, the OpenSSL EGD providers,
        `esdm_cdev`, libgcrypt
    ],
    ref-table(columns: (82pt, 1fr),
      table.header([Command], [Served]),
      [0x00 – 0x04], [EGD: entropy count, reads, write, PID],
      [0xe0, 0xe1], [Read from the prediction resistance DRNG],
      [0xe2], [Read with the semantics of `/dev/urandom`],
      [0xe3 – 0xe5], [State, status as text, status as JSON],
      [0xe6 – 0xea], [Entropy count, clear pool, reseed, thresholds – for
        user ID 0 only],
      [0xeb, 0xec], [Bulk read and insert of up to 64 KiB],
    ),
  )
]

#slide(title: [Backup: Results of the Output Calls per State])[
  #ref-table(columns: (1.95fr, 0.9fr, 1.15fr, 1.5fr), size: 12pt,
    table.header([Call], [Loaded], [Available, not operational],
      [Operational]),
    [`esdm_get_random_bytes`], [`-EOPNOTSUPP`], [`-EOPNOTSUPP`], [Data;
      `-EAGAIN` if the DRNG instances await their reseed],
    [`esdm_get_random_bytes_full`], [Waits], [Seeds, then waits until
      operational], [Data],
    [`esdm_get_random_bytes_full_noblock`], [`-EAGAIN`], [`-EAGAIN`], [Data
      or `-EAGAIN`],
    [`esdm_get_random_bytes_pr`], [Waits], [Waits until operational], [As
      many bytes as fresh entropy allows, possibly none],
    [`esdm_get_random_bytes_pr_noblock`], [`-EAGAIN`], [`-EAGAIN`], [Data or
      `-EAGAIN`],
    [`esdm_get_seed`], [`-EAGAIN` or waits], [Waits until all DRNG
      instances are seeded], [Seed data once all DRNG instances are seeded],
  )
  #v(8pt)
  #set text(size: t-small)
  Finalized, in a forked child and after a failed self test, every call
  returns `-EOPNOTSUPP`.
]

#slide(title: [Backup: SP 800-90B Measurements of the Interrupt Entropy Source])[
  #cols(widths: (1fr, 1.75fr), gutter: 20pt,
    [
      #set text(size: t-small)
      - Entropy of the 8 low bits of 1,000,000 raw timestamps per system,
        from the appendix “SP 800-90B Entropy Measurements”
      - The interrupt and the scheduler entropy source share one assessment
      - The tools to repeat it on the target are part of the ESDM:
        `esdm-getrawentropy`, `esdm-extractlsb`; for the eBPF sources
        `esdm-ebpf-collect`
      - The raw data is read from debugfs of a module built with
        `BUILD_TESTING=1`
    ],
    ref-table(columns: (1fr, 70pt, 58pt), size: 9pt,
      inset: (x: 5pt, y: 2.9pt),
      align: (left + horizon, center + horizon, center + horizon),
      table.header([Test system], [Entropy of \ 1,000,000 traces],
        [Sufficient entropy]),
      [AMD Ryzen 5950X – 64-bit KVM environment], [4.531023], [Y],
      [AMD EPYC Milan 7713 2 sockets 128 cores 8-way NUMA], [7.007947], [Y],
      [ARMv7 rev 5], [1.9344], [Y],
      [ARMv7 rev 5 (Freescale i.MX53)], [7.07088], [Y],
      [ARMv7 rev 5 (Freescale i.MX6 Ultralite)], [6.638399], [Y],
      [ARM 64 bit AppliedMicro X-Gene Mustang Board], [5.599128], [Y],
      [Intel Atom Z530 – using GUI], [3.38584], [Y],
      [Intel i7 7500U Skylake – 64-bit KVM environment], [3.452064], [Y],
      [Intel i7 8565U Whiskey Lake – 64-bit KVM environment], [7.400136], [Y],
      [Intel i7 8565U Whiskey Lake – 32-bit KVM environment], [7.405704], [Y],
      [Intel i7 8565U Whiskey Lake], [6.871], [Y],
      [Intel Xeon E7 4870 8 sockets 160 CPUs 8-way NUMA], [7.287790], [Y],
      [Intel Xeon Gold 6234], [4.434168], [Y],
      [IBM POWER 8 LE 8286-42A], [6.830712], [Y],
      [IBM POWER 7 BE 8202-E4C], [4.233912], [Y],
      [IBM System Z z13 (machine 2964)], [4.366368], [Y],
      [IBM System Z z15 (machine 8561)], [5.691832], [Y],
      [MIPS Atheros AR7241 rev 1], [7.157064], [Y],
      [MIPS Lantiq 34Kc V5.6], [7.032740], [Y],
      [Qualcomm IPQ4019 ARMv7], [6.638405], [Y],
      [SiFive HiFive Unmatched RISC-V U74], [2.387470], [Y],
    ),
  )
]

#slide(title: [Backup: Crypto Backends and Their DRNGs])[
  #ref-table(columns: (0.8fr, 2fr, 1fr),
    table.header([Backend], [DRNG], [Hash]),
    [builtin (default)], [SP 800-90A Hash DRBG with SHA-512 (default) or
      ChaCha20 DRNG], [SHA-512 or SHA3-512],
    [OpenSSL 3.0 or later], [SP 800-90A Hash DRBG with SHA-512 (default),
      CTR DRBG with AES-256 or HMAC DRBG with SHA-512], [SHA3-512],
    [Botan 3.2 or later], [SP 800-90A HMAC DRBG with SHA-512 (default) or
      ChaCha20 RNG, with fast key erasure with Botan 3.14 or later],
      [SHA3-512],
    [GnuTLS 3.6.7 or later], [SP 800-90A CTR DRBG with AES-256 and the
      derivation function added by the ESDM], [SHA-512],
    [leancrypto 1.6 or later], [XDRBG-256 with SHAKE256], [SHA3-512],
  )
  #v(10pt)
  #set text(size: t-small)
  The backend also provides the SHAKE256 of the XDRBG-256 pools; the build
  option `crypto_backend` selects it, one per build.
]

#option-slide([Backup: build option sp80090c – oversampling of the entropy
  sources], meson-sp80090c)[
  - Initial seed of a DRNG: every entropy source is asked for 384 bits
  - A conditioning component takes 64 bits of entropy more than it delivers
  - Applies as well with `fips140`, `ais2031_drg3` and `ais2031_drg4`
]

#option-slide([Backup: build option ais2031_ntg1 – two entropy sources at
  start-up], meson-ntg1)[
  - Two entropy sources deliver 240 bits each before a DRNG counts as fully
    seeded
  - Not needed for a Jitter RNG in its own NTG.1 mode: `es_jent_ntg1` with
    jitterentropy 3.7.0 or later
]

#option-slide([Backup: build option ais2031_drg4 – reseeding limits],
  meson-drg4, size: 8.6pt)[
  - No request after 2#super[17] output bits without a successful reseed
  - A reseed is attempted after three quarters of that
  - Excludes `ais2031_drg3`; combines with `ais2031_ntg1`
]

#option-slide([Backup: build option es_jent_instances – Jitter RNG
  collectors], meson-jent-instances)[
  - 1 to 64 collectors, each behind a lock of its own: the seedings of
    several DRNG instances collect side by side
  - By default 4 in a build that reseeds often, 1 otherwise
  - At runtime: the option `--es_jent_instances` of the server
]

#option-slide([Backup: build option threading_max_worker_threads – the
  number of DRNG instances], meson-threads)[
  - One DRNG instance per CPU, up to this number: 64 by default
  - Every RPC worker starts with a DRNG instance of its own
]

#option-slide([Backup: build option es_tpm2_entropy_rate – the credit of
  the TPM 2.0], meson-tpm2)[
  - `TPM2_GetRandom` on the resource manager device `/dev/tpmrm0`, without
    a TSS library
  - No credit by default: the data is additional input of the DRNG
  - A read has a deadline of 2 seconds
]

#slide(title: [Backup: Status of a Default Build])[
  #grid(columns: (1fr, 1fr, 1fr), column-gutter: 10pt,
    window(status-left.slice(0, 31), size: 6.5pt,
      title: "esdm-tool --status"),
    window(status-left.slice(31, 62), size: 6.5pt, title: "continued"),
    window(status-left.slice(62), size: 6.5pt, height: 31 * 1.36 * 6.5pt
      + 14pt, title: "continued"),
  )
]
