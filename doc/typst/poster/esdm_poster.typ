// A0 poster of the ESDM for developers (portrait, 841 x 1189 mm). It reads
// top down: what the ESDM is, the path from the noise to the random numbers
// with the central figure, then three columns - the processes, the DRNG
// instances and the interfaces - and three more - assurance, extending,
// building. The body is set at 30 pt, headings at 60 pt, the title at
// 132 pt. Its claims are those of the design document, its colors those of
// palette.typ; the QR code is rendered by doc/typst/Makefile with qrencode.

#import "../palette.typ": *
#import "../inputs.typ": esdm-version, doc-date
#import "../icons.typ": icon

#let sans = "Source Sans 3"
#let mono = "Source Code Pro"
#let figdir = "../figures/"
#let margin = 40mm
#let gutter = 24mm

#set document(title: [ESDM Poster],
  author: ("Stephan Müller", "Markus Theil"))
#set page(width: 841mm, height: 1189mm, margin: 0pt, fill: background)
#set text(font: sans, size: 30pt, fill: ink, lang: "en")
#set par(justify: false, leading: 0.55em, spacing: 0.8em)
#show raw: set text(font: mono, size: 25pt)
#set raw(theme: raw-theme)
#show raw.where(block: true): it => block(width: 100%, fill: surface-code,
  stroke: 1pt + line-color, radius: 6pt, inset: (x: 18pt, y: 14pt), it)
#set list(marker: text(fill: accent)[•], body-indent: 0.5em,
  spacing: 0.55em)

// A panel: a heading over a short blue rule, then the body.
#let panel(title, body) = block(width: 100%, {
  text(size: 60pt, weight: "semibold", fill: ink, title)
  v(8pt, weak: true)
  line(length: 90pt, stroke: 6pt + accent)
  v(9mm, weak: true)
  body
})

// A figure of the design document with its caption.
#let fig(file, width, caption) = align(center, {
  image(figdir + file, width: width)
  v(2mm)
  text(size: 24pt, fill: muted, caption)
})

// A number with what it counts.
#let stat(number, label) = stack(spacing: 5mm,
  text(size: 104pt, weight: "semibold", fill: accent-text, tracking: -2pt,
    number),
  text(size: 28pt, fill: muted, label))

// A step of the path from the noise to the random numbers.
#let step(n, title, body) = grid(columns: (62pt, 1fr), column-gutter: 18pt,
  box(width: 62pt, height: 62pt, radius: 31pt, fill: accent,
    align(center + horizon, text(size: 34pt, weight: "semibold",
      fill: background, str(n)))),
  {
    text(size: 36pt, weight: "semibold", title)
    v(5mm, weak: true)
    body
  })

// An interface with what it serves.
#let iface(name, body) = block(width: 100%, below: 6mm, {
  text(weight: "semibold", name)
  linebreak()
  text(fill: muted, body)
})

#let qr(file, label) = stack(spacing: 10pt,
  image(figdir + file, width: 92mm),
  align(center, text(size: 24pt, fill: muted, label)))

// ---------------------------------------------------------------- header

#block(width: 100%, height: 178mm, fill: navy, inset: (x: margin,
  top: 34mm), {
  stack(spacing: 11mm,
    line(length: 120pt, stroke: 8pt + accent),
    text(size: 132pt, weight: "semibold", fill: background,
      tracking: -1.5pt)[Entropy Source and DRNG Manager],
    text(size: 50pt, fill: on-navy-soft)[Random numbers for Linux from
      user space – a toolkit to tailor for FIPS 140-3, SP 800-90 and
      AIS 20/31, every entropy source chosen, credited and reported],
  )
  place(bottom, dy: -18mm, grid(columns: (1fr, auto),
    text(size: 30pt, weight: "semibold", fill: on-navy, tracking: 3pt,
      upper[ESDM #esdm-version · #doc-date]),
    text(size: 30pt, fill: rule)[Stephan Müller · Markus Theil]))
})

// ---------------------------------------------------------------- numbers

#block(width: 100%, fill: surface, inset: (x: margin, y: 13mm),
  grid(columns: (1fr,) * 5, column-gutter: gutter,
    stat[12][entropy sources, each with an entropy rate of its own],
    stat[4][output paths: full, plain, prediction resistance, seed],
    stat[5][crypto backends: builtin, OpenSSL, Botan, GnuTLS, leancrypto],
    stat[6][kinds of interfaces, from the device files to OpenSSL providers],
    stat[12][TLA+ models of the concurrent parts, checked in CI],
  ))

// ---------------------------------------------------------------- footer

#place(bottom, block(width: 100%, height: 132mm, fill: surface,
  inset: (x: margin, y: 16mm), grid(columns: (1fr, auto),
  column-gutter: gutter, align: horizon,
  {
    text(size: 60pt, weight: "semibold")[Learn More]
    v(8pt, weak: true)
    line(length: 90pt, stroke: 6pt + accent)
    v(8mm, weak: true)
    par(justify: false)[The design document in the repository –
      #box(raw("nix build .#esdm-doc")) – gives the design and the attacker
      model in chapter 2, the entropy assessments in chapters 3 and 4, the
      compliant configurations in chapter 5, the model checking in
      chapter 7 and the manual in chapters 8 to 14.]
  },
  qr("qr-repo.svg")[Source code and documentation],
)))

// ---------------------------------------------------------------- body

#block(inset: (x: margin, top: 14mm), {

  // From the noise to the random numbers
  grid(columns: (1.5fr, 1fr), column-gutter: gutter,
    fig("big-picture.svg", 100%)[Entropy sources fill the seed buffer that
      seeds the DRNG instances.],
    panel[From Noise to Random Numbers][
      #set par(justify: false)
      #stack(spacing: 8mm,
        step(1)[Collect][Internal sources time interrupts and task
          wakeups, in a kernel module or in eBPF programs. External
          sources deliver on request: Jitter RNG, CPU, kernel RNG, TPM,
          `/dev/hwrng`, provider processes.],
        step(2)[Credit][Each source fills a slot of the seed buffer with
          data and the entropy the configuration credits it. Data without
          credit becomes additional input.],
        step(3)[Seed][A DRNG instance is fully seeded with 256 bits of
          entropy, 384 with the SP 800-90C oversampling. Before that, the
          blocking interfaces wait.],
        step(4)[Serve][One DRNG instance per CPU serves the requests and
          is reseeded ahead of them; the prediction resistance instance
          reseeds for every block.],
      )
    ],
  )

  v(11mm)

  grid(columns: (1.15fr, 0.9fr, 1fr), column-gutter: gutter,
    panel[Processes][
      #fig("processes.svg", 100%)[Processes and their IPC]
      #v(3mm)
      - `esdm-server` holds the ESDM. It starts as root, sets up its
        namespaces and the privileged sources, then drops its privileges
        for good.
      - Clients reach it over two RPC sockets, the privileged one for
        root only, or over the minimal EGD protocol. The server is built
        with both interfaces or with one of them.
      - With `--pid_namespace` a root supervisor forwards the signals; the
        daemon ends with it.
    ],
    panel[DRNG Instance][
      #fig("drng-states.svg", 100%)[States of a DRNG instance]
      #v(3mm)
      - A reseed with the current time alone does not count as a full
        reseed.
      - A fork ends the output in the child. With the kernel module, a
        VM clone discards the state and a resume reseeds it.
    ],
    panel[Interfaces][
      #iface[`/dev/random`, `/dev/urandom`][CUSE daemons mounted over the
        kernel devices]
      #iface[`getrandom()`, `getentropy()`][a library preloaded into the
        consumer]
      #iface[RPC client library][the full API: all four paths, status,
        configuration]
      #iface[EGD sockets][one byte of command, one of length: for
        sandboxes, OpenSSL, libgcrypt]
      #iface[OpenSSL providers][RAND and seed source, over RPC or EGD]
      #iface[`esdm_cdev`][kernel devices `/dev/esdm_random`,
        `/dev/esdm_urandom` and `/dev/esdm_pr`]
      #v(2mm)
      #block(width: 100%, fill: accent-faint, radius: 6pt,
        inset: (x: 16pt, y: 12pt))[#icon("warning", fill: source-strong)
        #h(0.3em) The first two fall back to the kernel RNG when the
        server cannot be reached. The others report the error.]
    ],
  )

  v(11mm)

  grid(columns: (1fr, 1fr, 0.85fr), column-gutter: gutter,
    panel[Assurance][
      - SP 800-90B assessment of the interrupt and scheduler sources, with
        the tools to repeat it on the target.
      - Health tests on the raw timestamps; self tests of every primitive
        and source at start-up and every 10 minutes.
      - Configurations for SP 800-90C, FIPS 140-3 and AIS 20/31 (NTG.1,
        DRG.3, DRG.4), each with a worked example.
      - Model checking of the locks, wakeups and state machines; fuzzing
        of the RPC and EGD interfaces; sanitizers in CI.
      - The limits are written down: what the default build does not
        claim, and what no test covers.
    ],
    panel[Extending][
      An entropy source of your own is a process served by
      `libesdm_es_ext`:
      ```c
      static const
      struct esdm_es_ext_plugin src = {
        .version = ESDM_ES_EXT_PLUGIN_VERSION,
        .name = "my-noise-source",
        .get_entropy = my_get_entropy,
        .selftest = my_selftest,
      };

      int main(int argc, char *argv[])
      {
        return esdm_es_ext_provider_main(
          &src, argc, argv);
      }
      ```
      A crypto backend fills `struct esdm_drng_cb`.
    ],
    panel[Build and Test][
      ```sh
      meson setup build \
        -Dtestmode=enabled
      meson test -C build
      nix flake check
      ```
      #v(2mm)
      - A toolkit for regulated environments: components, entropy
        sources, rates and seeding strategy are configured per system.
      - Upstream integrations: OpenSSL, hypervisors, unmodified software.
      - Key generation moves out of the kernel; IVs and nonces stay there
        (AES-CBC in IPsec). The kernel seeder seeds the kernel RNG.
      - Optional kernel modules `esdm_es` and `esdm_cdev`; Linux 6.1 or
        later.
    ],
  )
})
