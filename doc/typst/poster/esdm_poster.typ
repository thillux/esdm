// A0 poster of the ESDM (portrait, 841 x 1189 mm) for open source
// conferences, workshops and office walls.
//
// What it has to achieve:
//   from 3 m    the ESDM is a random number generator for Linux in user
//               space: the title and the pipeline figure;
//   from 1.5 m  how entropy becomes random numbers, and that the ESDM is
//               tailored for FIPS 140-3 and AIS 20/31: the four stages and
//               the claims;
//   up close    enough detail to start a conversation, and the two links.
//
// It does not document the ESDM. All figures are drawn here for the poster,
// none is one of the design document: no label is smaller than 34 pt. The
// left column is the pipeline from the noise to the consumers; the right
// column, independent of it, says why to use the ESDM: eight claims, each a
// benefit in one line, then the deployments with their parts and the
// states of a DRNG instance. Its statements are those of the design document,
// its colors those of palette.typ.

#import "../palette.typ": *
#import "../inputs.typ": esdm-version, doc-date
#import "../icons.typ": icon, brand

#let sans = "Source Sans 3"
#let mono = "Source Code Pro"
#let margin = 40mm
#let gutter = 26mm

#let t-body = 40pt
#let t-small = 34pt
#let t-stage = 54pt
#let t-heading = 76pt

#set document(title: [ESDM Poster],
  author: ("Stephan Müller", "Markus Theil"))
#set page(width: 841mm, height: 1189mm, margin: 0pt, fill: background)
#set text(font: sans, size: t-body, fill: ink, lang: "en",
  top-edge: "cap-height", bottom-edge: "baseline")
#set par(justify: false, leading: 0.62em, spacing: 0.9em)
#show raw: set text(font: mono, size: 1.12em)

// ---------------------------------------------------------------- elements

#let heading-text(body) = text(size: t-heading, weight: "semibold",
  fill: accent-text, tracking: -0.5pt, body)

// A rounded box with a label: an entropy source, a DRNG instance, an
// interface.
#let chip(body, fill: background, stroke: rule, color: ink, height: 42mm,
  weight: "regular") = box(width: 100%, height: height, radius: 5mm,
  fill: fill, stroke: 2.5pt + stroke, inset: (x: 3mm),
  align(center + horizon, text(fill: color, weight: weight, body)))

// The number of a stage.
#let badge(n) = box(width: 24mm, height: 24mm, radius: 12mm, fill: accent,
  align(center + horizon, text(size: 48pt, weight: "semibold",
    fill: background, str(n))))

// A stage of the pipeline: its number and name, what happens, the parts.
#let stage(n, title, note, body) = block(width: 100%, fill: surface,
  radius: 8mm, inset: 13mm, {
  grid(columns: (auto, 1fr), column-gutter: 8mm, align: horizon,
    badge(n),
    stack(spacing: 8mm,
      text(size: t-stage, weight: "semibold", title),
      text(size: t-small, fill: muted, note)))
  v(11mm, weak: true)
  body
})

// The arrow between two stages, with what happens on the way. It takes the
// height the grid of the pipeline leaves to its row.
#let flow-arrow(body) = block(width: 100%, height: 100%, inset: (y: 5mm),
  grid(columns: (1fr, 60pt, 1fr), rows: 100%, align: (left, center, left),
    [],
    grid(columns: 60pt, rows: (1fr, 44pt), align: center,
      rect(width: 12pt, height: 100%, fill: accent, stroke: none),
      polygon(fill: accent, stroke: none, (0pt, 0pt), (60pt, 0pt),
        (30pt, 44pt))),
    align(horizon, pad(left: 6mm, text(size: t-small, fill: muted, body)))))

#let chips(columns, ..items) = grid(columns: (1fr,) * columns,
  column-gutter: 7mm, row-gutter: 7mm, ..items)

// ---------------------------------------------------------------- header

#let header-h = 122mm
#let footer-h = 34mm

#block(width: 100%, height: header-h, fill: navy, inset: (x: margin),
  align(horizon, stack(spacing: 20mm,
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
      [#box(baseline: 6pt, text(size: 44pt, icon("globe", fill: on-navy)))
        #h(0.4em) https://chronox.de/esdm/],
      [#box(baseline: 6pt, text(size: 40pt, brand("github"))) #h(0.4em)
        https://github.com/smuellerDD/esdm]))
  }))

// ---------------------------------------------------------------- pipeline

#let pipeline = grid(columns: 100%,
  rows: (auto, 14mm, auto, 1fr, auto, 1fr, auto, 1fr, auto),
  heading-text[From Noise to Random Numbers],
  [],
  stage(1)[Collect][Twelve entropy sources, each switched on, credited and
    reported on its own][
    #chips(4,
      chip(fill: source, stroke: source-strong)[Interrupts],
      chip(fill: source, stroke: source-strong)[Scheduler],
      chip[Jitter RNG],
      chip[CPU],
      chip[Kernel RNG],
      chip[TPM 2.0],
      chip[`/dev/hwrng`],
      chip[External],
    )
    #v(7mm, weak: true)
    #chip(fill: accent-faint, stroke: accent)[Auxiliary pool: data written
      by applications and by root]
  ],
  flow-arrow[Health tests on the raw \ data of the timing sources],
  stage(2)[Credit][Each source fills its slot of the seed buffer: data and
    the entropy it is credited][
    #let slot(fill, n) = stack(spacing: 4mm,
      rect(width: 100%, height: 36mm, fill: fill,
        stroke: 2.5pt + ink-soft),
      align(center, text(size: t-small, fill: muted, n)))
    #grid(columns: (1fr,) * 9, column-gutter: 0pt,
      slot(source)[256], slot(source-soft)[0], slot(accent-soft)[256],
      slot(accent-soft)[8], slot(accent-soft)[128], slot(background)[0],
      slot(background)[0], slot(background)[0], slot(accent-faint)[…])
  ],
  flow-arrow[Conditioned with a hash; \ the credits are added up],
  stage(3)[Seed][256 bits of entropy seed a DRNG instance fully, 384 bits
    with the SP 800-90C oversampling][
    #let drng(name, sub) = chip(fill: accent-soft, stroke: accent,
      height: 56mm, stack(spacing: 7mm,
        text(weight: "semibold", name),
        text(size: t-small, fill: muted, sub)))
    #grid(columns: (1fr, 1fr, auto, 1fr), column-gutter: 7mm,
      align: horizon,
      drng[DRNG][CPU 0], drng[DRNG][CPU 1],
      text(size: 60pt, fill: muted)[…],
      drng[DRNG][reseeded per block])
  ],
  flow-arrow[`esdm-server`, unprivileged \ after its start],
  stage(4)[Serve][Unmodified software, OpenSSL and hypervisors read from
    the interface they already use][
    #let face(body) = chip(fill: accent, stroke: accent, color: background,
      weight: "semibold", body)
    #chips(3,
      face[`/dev/random`], face[`getrandom()`], face[RPC library],
      face[EGD socket], face[OpenSSL provider], face[`/dev/esdm_pr`])
  ],
)

// ---------------------------------------------------------------- claims

#let claim(sign, title, body) = grid(columns: (30mm, 1fr),
  column-gutter: 9mm, align: horizon,
  box(width: 30mm, height: 30mm, radius: 7mm, fill: accent-soft,
    align(center + horizon, text(size: 60pt, icon(sign,
      fill: accent-text)))),
  stack(spacing: 6mm,
    text(size: 46pt, weight: "semibold", title),
    text(size: t-small, fill: muted, body)))

#let claims = {
  heading-text[Why the ESDM]
  v(14mm, weak: true)
  stack(spacing: 17mm,
    claim("plug")[Drop-in][No change to the applications],
    claim("microchip")[Stock kernel][No kernel patch; updated like any
      package],
    claim("puzzle")[A toolkit][Only the generator is mandatory],
    claim("scale")[Built for regulated use][FIPS 140-3, SP 800-90C,
      AIS 20/31],
    claim("key")[Keys from an assessed RNG][Key generation leaves the
      kernel RNG],
    claim("eye")[Every source accountable][Chosen, credited, tested and
      reported alone],
    claim("shield")[High assurance][Assessed, model checked, fuzzed],
    claim("lock")[Least privilege][Root for the set-up only, then dropped],
  )
}

// ---------------------------------------------------------------- toolkit

// The deployments against the components each of them needs: the claim
// "a toolkit" as a picture.
#let toolkit = {
  heading-text[Pick What You Need]
  v(14mm, weak: true)
  let parts = ([Generator], [Server], [RPC socket], [EGD socket],
    [CUSE daemons], [OpenSSL provider], [Kernel module])
  let uses = (
    ([One program], (0,)),
    ([OpenSSL applications], (0, 1, 2, 5)),
    ([Unmodified software], (0, 1, 2, 4)),
    ([Hypervisor], (0, 1, 3, 6)),
  )
  let dot(on) = align(center + horizon, if on {
    circle(radius: 10mm, fill: accent, stroke: none)
  } else {
    circle(radius: 3mm, fill: rule, stroke: none)
  })
  grid(columns: (auto,) + (1fr,) * parts.len(), column-gutter: 2mm,
    row-gutter: 13mm, align: (x, y) => if y == 0 { center + bottom } else
      if x == 0 { left + horizon } else { center + horizon },
    [], ..parts.map(p => rotate(-90deg, reflow: true, text(size: t-small,
      fill: muted, p))),
    ..uses.map(((name, on)) => (text(weight: "semibold", name),
      ..range(parts.len()).map(i => dot(i in on)))).flatten(),
  )
}

// ---------------------------------------------------------------- states

// The states of a DRNG instance in one line: the claim "assured".
#let states = {
  heading-text[Life of a DRNG Instance]
  v(14mm, weak: true)
  let state(title, sub, fill: accent-soft, stroke: accent) = box(
    width: 100%, height: 66mm, radius: 7mm, fill: fill,
    stroke: 2.5pt + stroke, align(center + horizon, stack(spacing: 7mm,
      text(weight: "semibold", title),
      text(size: t-small, fill: muted, sub))))
  let arrow(back: false) = align(center + horizon, stack(spacing: 4mm,
    polygon(fill: accent, stroke: none, (0mm, 3mm), (11mm, 3mm),
      (11mm, 0mm), (19mm, 5mm), (11mm, 10mm), (11mm, 7mm), (0mm, 7mm)),
    if back {
      polygon(fill: accent, stroke: none, (19mm, 3mm), (8mm, 3mm),
        (8mm, 0mm), (0mm, 5mm), (8mm, 10mm), (8mm, 7mm), (19mm, 7mm))
    }))
  grid(columns: (1fr, 21mm, 1fr, 21mm, 1fr), column-gutter: 3mm,
    state(fill: surface, stroke: ink-soft)[Unseeded][no output],
    arrow(),
    state[Seeded][serves],
    arrow(back: true),
    state[Reseed due][reseeds first])
  v(10mm, weak: true)
  text(size: t-small, fill: muted)[A reseed is due after 2#super[20]
    requests or 600 s. A reset or a fork ends the output until the next
    full seed.]
}

// ---------------------------------------------------------------- body

#let body-h = 1189mm - header-h - footer-h - 30mm - 36mm

#block(inset: (x: margin, y: 30mm), grid(columns: (1.22fr, 1fr),
  column-gutter: gutter,
  block(width: 100%, height: body-h, pipeline),
  block(width: 100%, height: body-h, {
    claims
    v(1fr)
    toolkit
    v(1fr)
    states
  }),
))
