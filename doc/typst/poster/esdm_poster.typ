// A0 poster of the ESDM for developers (portrait, 841 x 1189 mm). It reads
// top down: what the ESDM is, the path from the noise to the random numbers
// with the central figure in the left column, the state machines, the seed
// buffer and the output paths in the right one, and a closing band. The
// two columns are independent of each other. The body is set at 34 pt, headings at 70 pt, the title at
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
#set text(font: sans, size: 34pt, fill: ink, lang: "en")
#set par(justify: false, leading: 0.55em, spacing: 0.8em)
#show raw: set text(font: mono, size: 28pt)
#set raw(theme: raw-theme)
#show raw.where(block: true): it => block(width: 100%, fill: surface-code,
  stroke: 1pt + line-color, radius: 6pt, inset: (x: 18pt, y: 14pt), it)
#set list(marker: text(fill: accent)[•], body-indent: 0.5em,
  spacing: 0.55em)

// The heading of a panel, in the accent color.
#let panel-title(title) = text(size: 70pt, weight: "semibold",
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
  text(size: 27pt, fill: muted, caption)
})

// A step of the path from the noise to the random numbers.
#let step(n, title, body) = grid(columns: (62pt, 1fr), column-gutter: 18pt,
  box(width: 62pt, height: 62pt, radius: 31pt, fill: accent,
    align(center + horizon, text(size: 34pt, weight: "semibold",
      fill: background, str(n)))),
  {
    text(size: 40pt, weight: "semibold", title)
    v(5mm, weak: true)
    body
  })

// ---------------------------------------------------------------- header

#let header-h = 122mm
#let footer-h = 34mm
#let band-h = 112mm

#block(width: 100%, height: header-h, fill: navy, inset: (x: margin),
  align(horizon, stack(spacing: 24mm,
    text(size: 116pt, weight: "semibold", fill: background,
      tracking: -1.5pt)[ESDM: Entropy Source and DRNG Manager],
    text(size: 50pt, fill: on-navy-soft)[Random numbers for Linux from
      user space – a toolkit for FIPS 140-3, SP 800-90 and AIS 20/31],
  )))

// ---------------------------------------------------------------- footer

#place(bottom, block(width: 100%, height: footer-h, fill: navy,
  inset: (x: margin), {
    set text(size: 30pt, fill: on-navy)
    align(horizon, grid(columns: (1fr, auto, auto), column-gutter: 28mm,
      text(weight: "semibold", tracking: 3pt,
        upper[ESDM #esdm-version · #doc-date]),
      [#text(size: 47pt, baseline: 3pt, icon("globe", fill: on-navy))
        #h(0.4em) https://chronox.de/esdm/],
      [#text(size: 40pt, baseline: 3pt, brand("github")) #h(0.4em)
        https://github.com/smuellerDD/esdm]))
  }))

// The closing band above the footer: what the ESDM is for and what backs it.
#place(bottom, dy: -footer-h, block(width: 100%, height: band-h,
  fill: surface, inset: (x: margin), align(horizon,
  grid(columns: (1fr, 1fr), column-gutter: gutter,
    panel[Toolkit][
      - Only the generator is mandatory; every other part is chosen.
      - Upstream integrations: OpenSSL, hypervisors.
      - Key generation moves out of the kernel.
    ],
    panel[Compliance and Assurance][
      - SP 800-90C, FIPS 140-3, AIS 20/31 (NTG.1, DRG.3, DRG.4).
      - SP 800-90B assessment, health tests, self tests.
      - Model checking, fuzzing and sanitizers in CI.
    ],
  ))))

// ---------------------------------------------------------------- body

// Two columns that do not share their rows: each is filled top to bottom.
#let column-h = 1189mm - header-h - band-h - footer-h - 28mm - 24mm
#let column(..panels) = block(width: 100%, height: column-h,
  panels.pos().join(v(1fr)))

#block(inset: (x: margin, top: 28mm),
  grid(columns: (1fr, 1fr), column-gutter: gutter,
    column(
      panel[From Noise to Random Numbers][
        #fig("big-picture.svg", 100%)[Entropy sources fill the seed
          buffer that seeds the DRNG instances.]
        #v(6mm)
        #stack(spacing: 8mm,
          step(1)[Collect][Sources time interrupts and task wakeups, or
            deliver on request: Jitter RNG, CPU, TPM, `/dev/hwrng`.],
          step(2)[Credit][Each source fills its slot of the seed buffer
            with data and the entropy it is credited.],
          step(3)[Seed][256 bits of entropy seed a DRNG instance fully,
            384 with the SP 800-90C oversampling.],
          step(4)[Serve][One DRNG instance per CPU serves the requests
            and is reseeded ahead of them.],
        )
      ],
      panel[Seeding the DRNG Instances][
        #fig("numa-drng.svg", 100%)[Every DRNG instance is seeded from a
          seed buffer of its own collection.]
      ],
      panel[Processes][
        #fig("processes.svg", 100%)[`esdm-server` drops its privileges
          after start; the clients reach it over RPC and EGD sockets.]
      ],
    ),
    column(
      panel[State Machines][
        #fig("fsm-drng.svg", 100%)[A DRNG instance]
        #v(6mm)
        #grid(columns: (1.1fr, 1fr), column-gutter: 12mm, align: horizon,
          fig("fsm-esdm.svg", 100%)[The ESDM as a whole],
          [
            - No output before the first full seed.
            - A reseed with the time alone does not count as a full
              reseed.
            - A fork ends the output in the child.
          ])
      ],
      panel[Seed Buffer][
        #grid(columns: (1.1fr, 1fr), column-gutter: 12mm, align: horizon,
          fig("es-manager.svg", 100%)[From the entropy sources to the
            seed],
          [
            - One slot per entropy source: its data and the credited
              bits.
            - The credits are added up, at most 256 bits count.
            - Data without credit is additional input.
          ])
      ],
      panel[Output Paths][
        #fig("paths.svg", 82%)[Interfaces and the four output paths]
        #v(3mm)
        #block(width: 100%, fill: accent-faint, radius: 6pt,
          inset: (x: 16pt, y: 12pt))[#icon("warning",
          fill: source-strong) #h(0.3em) The device files and
          `getrandom()` fall back to the kernel RNG when the server
          cannot be reached. The other interfaces report the error.]
      ],
    ),
  ))
