// A0 poster of the ESDM for developers (portrait, 841 x 1189 mm). It reads
// top down: what the ESDM is, the path from the noise to the random numbers
// with the central figure, the processes and the interfaces, the DRNG
// instance and the toolkit, and a closing band: compliance and assurance.
// No row has more than two columns. The body is set at 30 pt, headings at 60 pt, the title at
// 116 pt. Its claims are those of the design document, its colors those of
// palette.typ.

#import "../palette.typ": *
#import "../inputs.typ": esdm-version, doc-date
#import "../icons.typ": icon, brand

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

// The heading of a panel, in the accent color.
#let panel-title(title) = text(size: 60pt, weight: "semibold",
  fill: accent-text, tracking: -0.5pt, title)

// A panel: a heading, then the body.
#let panel(title, body) = block(width: 100%, {
  panel-title(title)
  v(10mm, weak: true)
  body
})

// A figure of the design document with its caption.
#let fig(file, width, caption) = align(center, {
  image(figdir + file, width: width)
  v(2mm)
  text(size: 24pt, fill: muted, caption)
})

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

// ---------------------------------------------------------------- header

#block(width: 100%, height: 190mm, fill: navy, inset: (x: margin,
  top: 42mm), {
  stack(spacing: 27mm,
    text(size: 116pt, weight: "semibold", fill: background,
      tracking: -1.5pt)[ESDM: Entropy Source and DRNG Manager],
    text(size: 50pt, fill: on-navy-soft)[Random numbers for Linux from
      user space – a toolkit for FIPS 140-3, SP 800-90 and AIS 20/31],
  )
  place(bottom, dy: -18mm, grid(columns: (1fr, auto),
    text(size: 30pt, weight: "semibold", fill: on-navy, tracking: 3pt,
      upper[ESDM #esdm-version · #doc-date]),
    text(size: 30pt, fill: rule)[Stephan Müller · Markus Theil]))
})

// ---------------------------------------------------------------- footer

#place(bottom, block(width: 100%, height: 34mm, fill: navy,
  inset: (x: margin), {
    set text(size: 30pt, fill: on-navy)
    align(horizon, grid(columns: (1fr, auto),
      [#text(size: 47pt, baseline: 3pt, icon("globe", fill: on-navy))
        #h(0.4em) https://chronox.de/esdm/],
      [#text(size: 40pt, baseline: 3pt, brand("github")) #h(0.4em)
        https://github.com/smuellerDD/esdm]))
  }))

// The closing band above the footer: what the ESDM is for and what backs it.
#place(bottom, dy: -34mm, block(width: 100%, fill: surface,
  inset: (x: margin, top: 20mm, bottom: 22mm),
  grid(columns: (1fr, 1fr), column-gutter: gutter,
    panel[Compliance][
      - Configurations for SP 800-90C, FIPS 140-3 and AIS 20/31 (NTG.1,
        DRG.3, DRG.4), each with a worked example.
      - Entropy rates and seeding strategy are configured per system.
      - The limits are written down: what the default build does not
        claim, and what no test covers.
    ],
    panel[Assurance][
      - SP 800-90B assessment of the interrupt and scheduler sources, with
        the tools to repeat it on the target.
      - Health tests on the raw timestamps; self tests at start-up and
        every 10 minutes.
      - Model checking of the locks, wakeups and state machines; fuzzing
        and sanitizers in CI.
    ],
  )))

// ---------------------------------------------------------------- body

#block(inset: (x: margin, top: 34mm), {

  // From the noise to the random numbers
  grid(columns: (1fr, 1fr), column-gutter: gutter, align: horizon,
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

  v(44mm)

  grid(columns: (1fr, 1fr), column-gutter: gutter,
    panel[Processes][
      #fig("processes.svg", 100%)[Processes and their IPC]
      #v(3mm)
      - `esdm-server` holds the ESDM. It starts as root, sets up its
        namespaces and the privileged sources, then drops its privileges
        for good.
      - Clients reach it over two RPC sockets, the privileged one for
        root only, or over the minimal EGD protocol.
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

  v(44mm)

  grid(columns: (1fr, 1fr), column-gutter: gutter,
    panel[DRNG Instance][
      #fig("drng-states.svg", 62%)[States of a DRNG instance]
    ],
    {
      panel[Reseeding][
        - A DRNG instance is reseeded after 2#super[20] requests or 600
          seconds, and on demand.
        - A reseed with the current time alone does not count as a full
          reseed.
        - A fork ends the output in the child. With the kernel module, a
          VM clone discards the state and a resume reseeds it.
      ]
      v(14mm)
      panel[Toolkit][
        - Only the generator is mandatory. Frontends, entropy sources,
          kernel modules and tools are chosen per system.
        - Upstream integrations: OpenSSL, hypervisors, unmodified
          software.
        - Key generation moves out of the kernel; IVs and nonces stay
          there (AES-CBC in IPsec). The kernel seeder seeds the kernel
          RNG.
      ]
    },
  )
})
